"""
Cisco NX-OS SSH collector using Netmiko.

Supported platforms: Nexus 3000, 5000, 7000, 9000 series.
Tested against: NX-OS 9.x and 10.x

Auth:
    Standard SSH with AD username/password. NX-OS does not require an enable
    secret — the session starts in exec mode with full show access.

Data collection (two commands per device):

    1. "show interface"
       Parses every interface block for:
         - Interface name  (Ethernet1/1, Vlan10, mgmt0, port-channel1, etc.)
         - MAC address     (NX-OS dotted format aaaa.bbbb.cccc → normalized to aa:bb:cc:dd:ee:ff)
         - IPv4 address    (x.x.x.x/prefix)

    2. "show ipv6 interface"
       Parses per-interface IPv6 address blocks, including:
         - Link-local addresses (fe80::/10)
         - Global unicast addresses
       If the device has no IPv6 configured this command may return an empty
       or error response — that is handled gracefully (IPv6 stays N/A).
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from collectors.base import BaseCollector
from models.interface import InterfaceResult

logger = logging.getLogger(__name__)

PLATFORM_NAME       = "nxos"
NETMIKO_DEVICE_TYPE = "cisco_nxos"

# NX-OS dotted MAC: 0050.5685.a1b2
_MAC_DOTTED_RE = re.compile(
    r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
)

# Standard colon MAC (occasionally appears in NX-OS output)
_MAC_COLON_RE = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}(?![0-9a-fA-F}])",
    re.IGNORECASE,
)

_IPV4_PREFIX_RE = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b"
)

# Broad but safe IPv6 — MACs are scrubbed before this is applied
_IPV6_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r"|::"
    r")"
    r"(?:/\d{1,3})?"
    r"(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# Interface name patterns NX-OS uses at the start of a block
_IFACE_HEADER_RE = re.compile(
    r"^(Ethernet\S+|port-channel\S+|Vlan\S+|mgmt\S+|loopback\S+|tunnel\S+"
    r"|nve\S+|Null\S+)\s+is\s+",
    re.IGNORECASE,
)


class NXOSCollector(BaseCollector):

    def __init__(self, *args, save_raw_dir: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.save_raw_dir = save_raw_dir

    # ------------------------------------------------------------------ #
    #  Public entry point                                                  #
    # ------------------------------------------------------------------ #

    def collect(self, collect_config: bool = False) -> List[InterfaceResult] | Tuple[List[InterfaceResult], Optional[str]]:
        """
        Public entry point to collect interface and optionally configuration data.

        If collect_config is False (default), returns List[InterfaceResult] for backward compatibility.
        If collect_config is True, returns Tuple[List[InterfaceResult], Optional[str]].
        """
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
            res = self._error_result(f"Authentication failed: {exc}")
            return (res, None) if collect_config else res
        except NetmikoTimeoutException as exc:
            logger.error("[%s] Connection timed out: %s", self.hostname, exc)
            res = self._error_result(f"Connection timed out: {exc}")
            return (res, None) if collect_config else res
        except Exception as exc:
            logger.error("[%s] SSH connection failed: %s", self.hostname, exc)
            res = self._error_result(f"SSH connection failed: {exc}")
            return (res, None) if collect_config else res

        try:
            results, config = self._collect_with_connection(conn, collect_config)
        finally:
            conn.disconnect()

        return (results, config) if collect_config else results

    # ------------------------------------------------------------------ #
    #  Collection                                                          #
    # ------------------------------------------------------------------ #

    def _collect_with_connection(self, conn, collect_config: bool = False) -> Tuple[List[InterfaceResult], Optional[str]]:

        # Step 1: interface names, MACs, IPv4
        try:
            iface_raw = conn.send_command("show interface", read_timeout=60)
            self._save_raw(iface_raw, "show_interface")
            iface_map = self._parse_show_interface(iface_raw)
        except Exception as exc:
            logger.error("[%s] 'show interface' failed: %s", self.hostname, exc)
            return self._error_result(f"'show interface' failed: {exc}"), None

        if not iface_map:
            return self._error_result(
                "No interfaces found in 'show interface' output. "
                "Use --save-raw to inspect raw output."
            ), None

        logger.debug("[%s] Found %d interface(s)", self.hostname, len(iface_map))

        # Step 2: IPv6 addresses
        ipv6_map: Dict[str, List[str]] = {}
        try:
            ipv6_raw = conn.send_command("show ipv6 interface", read_timeout=30)
            self._save_raw(ipv6_raw, "show_ipv6_interface")

            # NX-OS returns "% IPv6 not enabled" or similar if nothing configured
            if not any(err in ipv6_raw.lower() for err in
                       ("not enabled", "not supported", "invalid command", "% error")):
                ipv6_map = self._parse_show_ipv6_interface(ipv6_raw)

            logger.debug(
                "[%s] IPv6 found on %d interface(s): %s",
                self.hostname, len(ipv6_map), list(ipv6_map.keys()) or "none",
            )
        except Exception as exc:
            logger.warning("[%s] 'show ipv6 interface' failed: %s", self.hostname, exc)

        # Step 3: configuration (optional)
        config = None
        if collect_config:
            try:
                config = conn.send_command("show running-config", read_timeout=120)
                self._save_raw(config, "show_running_config")
            except Exception as exc:
                logger.error("[%s] 'show running-config' failed: %s", self.hostname, exc)

        # Step 4: merge
        results: List[InterfaceResult] = []
        for iface_name, (ipv4_addr, mac_addr) in sorted(iface_map.items()):
            results.append(InterfaceResult(
                hostname=self.hostname,
                device_ip=self.ip_address,
                platform=PLATFORM_NAME,
                interface_name=iface_name,
                ipv4_address=ipv4_addr,
                ipv6_addresses=ipv6_map.get(iface_name, []),
                mac_address=mac_addr,
            ))

        return results, config

    # ------------------------------------------------------------------ #
    #  "show interface" parser                                             #
    # ------------------------------------------------------------------ #

    def _parse_show_interface(self, output: str) -> Dict[str, Tuple[str, str]]:
        """
        Parse 'show interface' output into {iface_name: (ipv4, mac)}.

        NX-OS interface blocks look like:

            Ethernet1/1 is up
              Hardware: 100/1000/10000 Ethernet, address: 0050.5685.a1b2 (bia 0050.5685.a1b2)
              Internet Address is 10.0.0.1/24
              ...

            Vlan10 is up, line protocol is up
              Hardware is EtherSVI, address is 0050.5685.a1b3
              Internet Address is 192.168.10.1/24

            mgmt0 is up
              Hardware: GigabitEthernet, address: 0050.5685.a1b4 (bia ...)
              Internet Address is 10.1.1.1/24
        """
        iface_map: Dict[str, Tuple[str, str]] = {}

        current_iface: Optional[str] = None
        current_ipv4  = "N/A"
        current_mac   = "N/A"

        def _flush():
            if current_iface:
                iface_map[current_iface] = (current_ipv4, current_mac)

        for line in output.splitlines():
            stripped = line.strip()

            # New interface block?
            header = _IFACE_HEADER_RE.match(line)
            if header:
                _flush()
                current_iface = header.group(1)
                current_ipv4  = "N/A"
                current_mac   = "N/A"
                continue

            if current_iface is None:
                continue

            # MAC address line — appears after "Hardware:" or "Hardware is"
            if "address:" in stripped.lower() or "address is" in stripped.lower():
                mac = self._extract_mac(stripped)
                if mac:
                    current_mac = mac

            # IPv4 address line
            if "internet address is" in stripped.lower():
                m = _IPV4_PREFIX_RE.search(stripped)
                if m:
                    current_ipv4 = m.group(1)

        _flush()
        return iface_map

    # ------------------------------------------------------------------ #
    #  "show ipv6 interface" parser                                        #
    # ------------------------------------------------------------------ #

    def _parse_show_ipv6_interface(self, output: str) -> Dict[str, List[str]]:
        """
        Parse 'show ipv6 interface' output into {iface_name: [addr/prefix, ...]}.

        NX-OS format:

            IPv6 Interface Status for VRF "default"
            Ethernet1/1, IPv6 is enabled, link-local address: fe80::250:56ff:fe85:a1b2
              Global unicast address(es):
                2001:db8::1, subnet is 2001:db8::/64 [VALID]
                2001:db8::2, subnet is 2001:db8:1::/64 [VALID]

            Vlan10, IPv6 is enabled, link-local address: fe80::250:56ff:fe85:a1b3
              Global unicast address(es):
                2001:db8:10::1, subnet is 2001:db8:10::/64 [VALID]
        """
        ipv6_map: Dict[str, List[str]] = {}

        current_iface: Optional[str] = None
        current_addrs: List[str] = []

        def _flush():
            if current_iface and current_addrs:
                ipv6_map[current_iface] = list(current_addrs)

        for line in output.splitlines():
            stripped = line.strip()

            # New interface block — starts with interface name followed by comma
            # e.g. "Ethernet1/1, IPv6 is enabled..."
            iface_match = re.match(
                r"^(Ethernet\S+|port-channel\S+|Vlan\S+|mgmt\S+|loopback\S+|tunnel\S+)"
                r"\s*,",
                line, re.IGNORECASE,
            )
            if iface_match:
                _flush()
                current_iface = iface_match.group(1)
                current_addrs = []
                # Link-local may be on this same line
                addrs = self._extract_ipv6_addresses(line)
                current_addrs.extend(addrs)
                continue

            if current_iface is None:
                continue

            # Global unicast address lines
            if stripped and not stripped.startswith("#"):
                addrs = self._extract_ipv6_addresses(stripped)
                for addr in addrs:
                    if addr not in current_addrs:
                        current_addrs.append(addr)

        _flush()
        return ipv6_map

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_mac(text: str) -> Optional[str]:
        """
        Extract MAC from a line. Handles both NX-OS dotted (0050.5685.a1b2)
        and colon (00:50:56:85:a1:b2) formats. Returns colon-separated lowercase.
        """
        # Try dotted format first (NX-OS native)
        m = _MAC_DOTTED_RE.search(text)
        if m:
            raw = m.group(0).replace(".", "")
            return ":".join(raw[i:i+2] for i in range(0, 12, 2)).lower()

        # Fall back to colon format
        m = _MAC_COLON_RE.search(text)
        if m:
            return m.group(0).lower()

        return None

    @staticmethod
    def _extract_ipv6_addresses(text: str) -> List[str]:
        """
        Extract IPv6 addresses from a line of text.
        Strips any NX-OS status suffixes like [VALID], [TENTATIVE], subnet info.
        """
        # Scrub dotted MACs so they don't confuse the IPv6 regex
        scrubbed = _MAC_DOTTED_RE.sub("", text)
        scrubbed = _MAC_COLON_RE.sub("", scrubbed)

        addrs = []
        seen  = set()

        for m in _IPV6_RE.finditer(scrubbed):
            addr = m.group(0).strip()
            if addr.count(":") < 2:
                continue

            # Normalize: strip trailing colon artifacts
            addr = addr.rstrip(":")

            # Try to attach prefix length from "subnet is x::/n" on same line
            # "2001:db8::1, subnet is 2001:db8::/64" → keep as-is if already has prefix
            if "/" not in addr:
                prefix_match = re.search(
                    r"subnet\s+is\s+[0-9a-fA-F:]+/(\d{1,3})", text, re.IGNORECASE
                )
                if prefix_match:
                    addr = f"{addr}/{prefix_match.group(1)}"

            if addr not in seen:
                seen.add(addr)
                addrs.append(addr)

        return addrs

    # ------------------------------------------------------------------ #
    #  Raw output dump                                                     #
    # ------------------------------------------------------------------ #

    def _save_raw(self, output: str, label: str) -> None:
        if not self.save_raw_dir:
            return
        from pathlib import Path
        from datetime import datetime
        out_dir = Path(self.save_raw_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = out_dir / f"{self.hostname}__{label}__{ts}.txt"
        try:
            path.write_text(output, encoding="utf-8")
            logger.debug("[%s] Saved raw output: %s", self.hostname, path)
        except OSError as exc:
            logger.warning("[%s] Could not save raw output: %s", self.hostname, exc)
