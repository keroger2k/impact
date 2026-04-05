"""
PAN-OS SSH (CLI) collector using Netmiko.

Supports: PA-VM, PA-3220, PA-3260, PA-3060, PA-5280, PA-5420, M-600 (Panorama).
Tested against: PAN-OS 9.1.x and 11.1.x

Auth:
    Standard SSH with AD username/password — same credentials you type at the CLI.

IPv6 collection strategy (two independent attempts, first one wins):

    Primary — "show config running" XML parse:
        PAN-OS returns the full running config as XML over SSH. We search the
        entire tree for any <entry name="addr/prefix"> whose name contains a
        colon (i.e. looks like an IPv6 address), anchored to an interface entry
        by walking up the tree. Works on both 9.1.x and 11.1.x.

    Fallback — "show interface <n>" per interface:
        If the XML parse finds nothing (truncated output, unexpected structure,
        Panorama, etc.), we issue one show-interface command per interface and
        regex-scan the text output for IPv6 addresses. Slower but guaranteed to
        reflect operational state.

Debugging:
    Run with --log-level DEBUG to see parse details at every step.
    Pass --save-raw <dir> to dump raw command output to timestamped text files —
    one file per device per command. Inspect these if IPv6 still shows N/A.
"""

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from collectors.base import BaseCollector
from models.interface import InterfaceResult

logger = logging.getLogger(__name__)

PLATFORM_NAME       = "paloalto"
NETMIKO_DEVICE_TYPE = "paloalto_panos"
CONFIG_CMD_TIMEOUT  = 60  # seconds

# MAC address: exactly 6 groups of exactly 2 hex chars  e.g. c4:24:56:db:18:4c
_MAC_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
    r"(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# IPv6: comprehensive pattern covering all RFC-valid forms.
# MACs are scrubbed before this is applied, providing a second layer of protection.
_IPV6_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"              # full 8-group
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                            # trailing ::
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"                            # leading ::x
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"           # n groups :: m
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"          # ::x...
    r"|::"                                                      # bare ::
    r")"
    r"(?:/\d{1,3})?"
    r"(?![0-9a-fA-F])",
    re.IGNORECASE,
)


class PaloAltoCollector(BaseCollector):

    def __init__(self, *args, save_raw_dir: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.save_raw_dir = save_raw_dir

    # ------------------------------------------------------------------ #
    #  Public entry point                                                  #
    # ------------------------------------------------------------------ #

    def collect(self) -> List[InterfaceResult]:
        logger.debug("[%s] Connecting via SSH to %s", self.hostname, self.ip_address)

        try:
            conn = ConnectHandler(
                device_type=NETMIKO_DEVICE_TYPE,
                host=self.ip_address,
                username=self.username,
                password=self.password,
                secret="",
                conn_timeout=30,
                auth_timeout=30,
                banner_timeout=30,
            )
        except NetmikoAuthenticationException as exc:
            logger.error("[%s] Authentication failed: %s", self.hostname, exc)
            return self._error_result(f"Authentication failed: {exc}")
        except NetmikoTimeoutException as exc:
            logger.error("[%s] Connection timed out: %s", self.hostname, exc)
            return self._error_result(f"Connection timed out: {exc}")
        except Exception as exc:
            logger.error("[%s] SSH connection failed: %s", self.hostname, exc)
            return self._error_result(f"SSH connection failed: {exc}")

        try:
            results = self._collect_with_connection(conn)
        finally:
            conn.disconnect()

        return results

    # ------------------------------------------------------------------ #
    #  Collection                                                          #
    # ------------------------------------------------------------------ #

    def _collect_with_connection(self, conn) -> List[InterfaceResult]:

        # Step 1: interface names + IPv4
        mac_map: Dict[str, str] = {}
        try:
            iface_raw = conn.send_command("show interface all")
            self._save_raw(iface_raw, "show_interface_all")
            ipv4_map, mac_map, zone_map = self._parse_show_interface_all(iface_raw)

        except Exception as exc:
            logger.error("[%s] 'show interface all' failed: %s", self.hostname, exc)
            return self._error_result(f"'show interface all' failed: {exc}")

        if not ipv4_map:
            return self._error_result(
                "No logical interfaces found in 'show interface all' output. "
                "Re-run with --save-raw to inspect the raw output."
            )

        logger.debug("[%s] Found %d logical interface(s)", self.hostname, len(ipv4_map))

        # Step 2a: IPv6 via config XML (primary)
        ipv6_map: Dict[str, List[str]] = {}
        try:
            config_raw = conn.send_command(
                "show config running", read_timeout=CONFIG_CMD_TIMEOUT
            )
            self._save_raw(config_raw, "show_config_running")
            ipv6_map = self._parse_ipv6_from_config_xml(config_raw, set(ipv4_map.keys()))
            logger.debug(
                "[%s] Config XML: IPv6 found on %d interface(s): %s",
                self.hostname, len(ipv6_map), list(ipv6_map.keys()) or "none",
            )
        except Exception as exc:
            logger.warning("[%s] 'show config running' failed: %s", self.hostname, exc)

        # Step 2b: per-interface fallback if XML yielded nothing
        if not ipv6_map:
            logger.debug(
                "[%s] Config XML found no IPv6 — running per-interface fallback",
                self.hostname,
            )
            ipv6_map = self._get_ipv6_per_interface(conn, list(ipv4_map.keys()))

        # Step 3: merge
        results: List[InterfaceResult] = []
        for iface_name, ipv4_addr in sorted(ipv4_map.items()):
            results.append(InterfaceResult(
                hostname=self.hostname,
                device_ip=self.ip_address,
                platform=PLATFORM_NAME,
                interface_name=iface_name,
                ipv4_address=ipv4_addr,
                ipv6_addresses=ipv6_map.get(iface_name, []),
                zone=zone_map.get(iface_name, "N/A"),
                mac_address=mac_map.get(iface_name, "N/A"),
            ))

        return results

    # ------------------------------------------------------------------ #
    #  "show interface all" parser                                         #
    # ------------------------------------------------------------------ #

    def _parse_show_interface_all(self, output: str):
        """
        Parse both tables from 'show interface all'.
        Returns (ipv4_map, mac_map):
            ipv4_map: {iface_name: ipv4_or_N/A}
            mac_map:  {iface_name: mac_or_N/A}  — from the hardware table

        Hardware table (MACs):
            name                    id    speed/duplex/state    mac-address
            ---------------------------------------------------------------
            ethernet1/1             16    1000/full/up          c4:24:56:db:18:4c

        Logical table (IPv4):
            name           id    vsys  zone       forwarding    tag  address
            -----------------------------------------------------------------
            ethernet1/1    16    vsys1 trust      vr:default    0    10.0.0.1/24
        """
        ipv4_map: Dict[str, str] = {}
        mac_map:  Dict[str, str] = {}
        zone_map: Dict[str, str] = {}


        # ── Hardware table → MACs ─────────────────────────────────────
        hw_match = re.search(
            r"total configured hardware interfaces\s*:\s*\d+", output, re.IGNORECASE
        )
        if hw_match:
            hw_section = output[hw_match.start():]
            past_sep   = False
            for line in hw_section.splitlines():
                stripped = line.strip()
                if not past_sep:
                    if re.match(r"^-{10,}", stripped):
                        past_sep = True
                    continue
                if not stripped:
                    break
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                iface_name = parts[0]
                last_field = parts[-1]
                if _MAC_RE.match(last_field):
                    mac_map[iface_name] = last_field.lower()

        # ── Logical table → IPv4 ──────────────────────────────────────
        log_match = re.search(
            r"total configured logical interfaces\s*:\s*\d+", output, re.IGNORECASE
        )
        if not log_match:
            logger.debug("[%s] Logical interface section not found", self.hostname)
            return ipv4_map, mac_map

        section  = output[log_match.start():]
        past_sep = False

        for line in section.splitlines():
            stripped = line.strip()

            if not past_sep:
                if re.match(r"^-{10,}", stripped):
                    past_sep = True
                continue

            if not stripped:
                break

            parts = stripped.split()
            if len(parts) < 2:
                continue

            iface_name = parts[0]
            last_field = parts[-1]

            if len(parts) >= 5:
                zone_map[iface_name] = parts[3]

            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", last_field):
                ipv4_map[iface_name] = last_field
            else:
                ipv4_map[iface_name] = "N/A"

        return ipv4_map, mac_map, zone_map

    # ------------------------------------------------------------------ #
    #  IPv6 primary: "show config running" XML                            #
    # ------------------------------------------------------------------ #

    def _parse_ipv6_from_config_xml(
        self, output: str, known_interfaces: set
    ) -> Dict[str, List[str]]:
        """
        Two-pass XML strategy:

        Pass 1 — anchor search:
            Find every <entry name="<iface_name>"> for each known interface.
            Deep-search that entry for child <entry> names containing colons
            (IPv6 addresses) or <prefix>/<ip> text nodes with IPv6 content.

        Pass 2 — broad fallback:
            If pass 1 finds nothing, iterate every element in the tree looking
            for <entry name="..."> where the name looks like an IPv6 address,
            then walk up the parent chain to find the owning interface entry.
        """
        ipv6_map: Dict[str, List[str]] = {}

        xml_start = output.find("<")
        if xml_start == -1:
            logger.debug("[%s] No XML content found in config output", self.hostname)
            return ipv6_map

        xml_text = output[xml_start:]
        logger.debug("[%s] Config XML: %d chars", self.hostname, len(xml_text))

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning(
                "[%s] Config XML parse error: %s  (use --save-raw to inspect)", self.hostname, exc
            )
            return ipv6_map

        logger.debug("[%s] XML root: <%s>", self.hostname, root.tag)

        # Pass 1: anchor on known interface names
        for iface_name in known_interfaces:
            for iface_entry in root.findall(f".//entry[@name='{iface_name}']"):
                addrs = self._extract_ipv6_from_entry(iface_entry)
                if addrs:
                    ipv6_map.setdefault(iface_name, []).extend(addrs)
                    logger.debug("[%s] Pass1 %s → %s", self.hostname, iface_name, addrs)

        if ipv6_map:
            return ipv6_map

        # Pass 2: broad scan
        logger.debug("[%s] Pass 1 found nothing — broad XML scan", self.hostname)
        parent_map: Dict[ET.Element, ET.Element] = {
            child: parent for parent in root.iter() for child in parent
        }

        for elem in root.iter("entry"):
            name = elem.get("name", "")
            if name.count(":") < 2:
                continue
            if not _IPV6_RE.match(name):
                continue

            # Walk up to find owning interface
            ancestor = parent_map.get(elem)
            while ancestor is not None:
                anc_name = ancestor.get("name", "")
                if anc_name in known_interfaces:
                    ipv6_map.setdefault(anc_name, []).append(name)
                    logger.debug("[%s] Pass2 %s → %s", self.hostname, anc_name, name)
                    break
                ancestor = parent_map.get(ancestor)

        return ipv6_map

    @staticmethod
    def _extract_ipv6_from_entry(entry: ET.Element) -> List[str]:
        """
        Find IPv6 addresses anywhere under an interface entry element.

        PAN-OS 9.1.x / 11.1.x both use:
            <layer3><ipv6><address><entry name="2001:db8::1/64"/></address></ipv6></layer3>

        Some builds also use <prefix> or <ip> text nodes — we check those too.
        """
        addrs: List[str] = []

        # Entry name pattern (most common)
        for child in entry.iter("entry"):
            if child is entry:
                continue
            name = child.get("name", "")
            if name.count(":") >= 2 and _IPV6_RE.match(name):
                addrs.append(name)

        # Text node patterns
        for tag in ("prefix", "ip", "address"):
            for el in entry.iter(tag):
                text = (el.text or "").strip()
                if text.count(":") >= 2 and _IPV6_RE.match(text):
                    addrs.append(text)

        # Deduplicate, preserve order
        seen = set()
        result = []
        for a in addrs:
            if a not in seen:
                seen.add(a)
                result.append(a)
        return result

    # ------------------------------------------------------------------ #
    #  IPv6 fallback: per-interface "show interface <n>"                  #
    # ------------------------------------------------------------------ #

    def _get_ipv6_per_interface(
        self, conn, interface_names: List[str]
    ) -> Dict[str, List[str]]:
        """
        Query each interface with 'show interface <name>' and regex-scan
        the plain-text output for IPv6 addresses.

        Used only when the config XML approach finds nothing. The format of
        'show interface <name>' varies across PAN-OS versions and interface
        types, so we scan broadly rather than matching fixed field names.
        """
        ipv6_map: Dict[str, List[str]] = {}

        for iface_name in interface_names:
            try:
                raw = conn.send_command(f"show interface {iface_name}")
                self._save_raw(raw, f"show_interface_{iface_name.replace('/', '_')}")

                addrs = self._extract_ipv6_from_text(raw)
                if addrs:
                    ipv6_map[iface_name] = addrs
                    logger.debug("[%s] Fallback %s → %s", self.hostname, iface_name, addrs)

            except Exception as exc:
                logger.debug("[%s] show interface %s failed: %s", self.hostname, iface_name, exc)

        return ipv6_map

    @staticmethod
    def _extract_ipv6_from_text(text: str) -> List[str]:
        """
        Scan free-form text for IPv6 addresses (with optional /prefix).
        MAC addresses (XX:XX:XX:XX:XX:XX) are explicitly excluded before scanning.
        """
        # Blank out MAC addresses so the IPv6 regex cannot match them
        scrubbed = _MAC_RE.sub("", text)

        seen  = set()
        addrs = []
        for match in _IPV6_RE.finditer(scrubbed):
            addr = match.group(0).strip()
            if addr.count(":") < 2:
                continue
            if addr not in seen:
                seen.add(addr)
                addrs.append(addr)
        return addrs

    # ------------------------------------------------------------------ #
    #  Raw output dump                                                     #
    # ------------------------------------------------------------------ #

    def _save_raw(self, output: str, label: str) -> None:
        """Write raw command output to a file when --save-raw is active."""
        if not self.save_raw_dir:
            return
        out_dir = Path(self.save_raw_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = out_dir / f"{self.hostname}__{label}__{ts}.txt"
        try:
            path.write_text(output, encoding="utf-8")
            logger.debug("[%s] Saved raw output: %s", self.hostname, path)
        except OSError as exc:
            logger.warning("[%s] Could not save raw output: %s", self.hostname, exc)