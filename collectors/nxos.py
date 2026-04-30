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
import time
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from collectors.base import BaseCollector
from models.interface import InterfaceResult

logger = logging.getLogger(__name__)

PLATFORM_NAME       = "nxos"
NETMIKO_DEVICE_TYPE = "cisco_nxos"


def _empty_extras() -> Dict:
    """Empty extras payload returned on connection or parse failure."""
    return {"port_channels": [], "vpcs": [], "vlans": []}

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

    def collect(self, collect_config: bool = False) -> List[InterfaceResult] | Tuple[List[InterfaceResult], Optional[str], Dict]:
        """
        Public entry point to collect interface and optionally configuration data.

        If collect_config is False (default), returns List[InterfaceResult] for backward compatibility.
        If collect_config is True, returns Tuple[List[InterfaceResult], Optional[str], Dict].
        The Dict ("extras") carries Nexus-specific structured data:
            { "port_channels": [...], "vpcs": [...], "vlans": [...] }
        Each entry list may be empty if the device does not support the feature
        or the command failed; the SSH session is not aborted on extras failure.
        """
        logger.debug("[%s] Connecting via SSH to %s", self.hostname, self.ip_address)

        start_time = time.time()
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
            duration = int((time.time() - start_time) * 1000)
            logger.info(f"SSH Connected: {self.hostname} ({self.ip_address})", extra={
                "target": "Nexus",
                "action": "SSH_CONNECT",
                "status": 200,
                "duration_ms": duration
            })
        except NetmikoAuthenticationException as exc:
            duration = int((time.time() - start_time) * 1000)
            logger.error(f"[{self.hostname}] Authentication failed: {exc}", extra={
                "target": "Nexus",
                "action": "SSH_CONNECT",
                "status": 401,
                "duration_ms": duration
            })
            logger.error("[%s] Authentication failed: %s", self.hostname, exc)
            res = self._error_result(f"Authentication failed: {exc}")
            return (res, None, _empty_extras()) if collect_config else res
        except NetmikoTimeoutException as exc:
            duration = int((time.time() - start_time) * 1000)
            logger.error("[%s] Connection timed out: %s", self.hostname, exc, extra={
                "target": "Nexus",
                "action": "SSH_CONNECT",
                "status": 408,
                "duration_ms": duration
            })
            res = self._error_result(f"Connection timed out: {exc}")
            return (res, None, _empty_extras()) if collect_config else res
        except Exception as exc:
            duration = int((time.time() - start_time) * 1000)
            logger.error("[%s] SSH connection failed: %s", self.hostname, exc, extra={
                "target": "Nexus",
                "action": "SSH_CONNECT",
                "status": 500,
                "duration_ms": duration
            })
            res = self._error_result(f"SSH connection failed: {exc}")
            return (res, None, _empty_extras()) if collect_config else res

        try:
            results, config, extras = self._collect_with_connection(conn, collect_config)
        finally:
            conn.disconnect()

        return (results, config, extras) if collect_config else results

    # ------------------------------------------------------------------ #
    #  Collection                                                          #
    # ------------------------------------------------------------------ #

    def _collect_with_connection(self, conn, collect_config: bool = False) -> Tuple[List[InterfaceResult], Optional[str], Dict]:
        # Step 1: interface names, MACs, IPv4
        try:
            cmd = "show interface"
            start_time = time.time()
            iface_raw = conn.send_command(cmd, read_timeout=60)
            duration = int((time.time() - start_time) * 1000)
            logger.info(f"SSH CMD: {self.hostname} - {cmd}", extra={
                "target": "Nexus",
                "action": "FETCH_NEXUS_INTERFACES",
                "status": 200,
                "duration_ms": duration
            })
            self._save_raw(iface_raw, "show_interface")
            iface_map = self._parse_show_interface(iface_raw)
        except Exception as exc:
            duration = int((time.time() - start_time) * 1000)
            logger.error("[%s] 'show interface' failed: %s", self.hostname, exc, extra={
                "target": "Nexus",
                "action": "FETCH_NEXUS_INTERFACES",
                "status": 500,
                "duration_ms": duration
            })
            return self._error_result(f"'show interface' failed: {exc}"), None

        if not iface_map:
            return self._error_result(
                "No interfaces found in 'show interface' output. "
                "Use --save-raw to inspect raw output."
            ), None, _empty_extras()

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
            cmd = "show running-config"
            start_time = time.time()
            try:
                config = conn.send_command(cmd, read_timeout=120)
                duration = int((time.time() - start_time) * 1000)
                logger.info(f"SSH CMD: {self.hostname} - {cmd}", extra={
                    "target": "Nexus",
                    "action": "FETCH_NEXUS_CONFIG",
                    "status": 200,
                    "duration_ms": duration
                })
                self._save_raw(config, "show_running_config")
            except Exception as exc:
                duration = int((time.time() - start_time) * 1000)
                logger.error("[%s] 'show running-config' failed: %s", self.hostname, exc, extra={
                    "target": "Nexus",
                    "action": "FETCH_NEXUS_CONFIG",
                    "status": 500,
                    "duration_ms": duration
                })

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

        # Step 5: Nexus-specific extras (port-channels, vPCs, VLANs).
        # All best-effort; failures are logged but do not abort the collection.
        extras = self._collect_extras(conn)

        return results, config, extras

    # ------------------------------------------------------------------ #
    #  Nexus extras (port-channels, vPCs, VLANs)                          #
    # ------------------------------------------------------------------ #

    def _collect_extras(self, conn) -> Dict:
        port_channels: List[Dict] = []
        vpcs:          List[Dict] = []
        vlans:         List[Dict] = []

        try:
            raw = conn.send_command("show port-channel summary", read_timeout=30)
            self._save_raw(raw, "show_port_channel_summary")
            port_channels = self._parse_port_channel_summary(raw)
        except Exception as exc:
            logger.warning("[%s] 'show port-channel summary' failed: %s", self.hostname, exc)

        try:
            raw = conn.send_command("show vpc", read_timeout=30)
            self._save_raw(raw, "show_vpc")
            vpcs = self._parse_show_vpc(raw)
        except Exception as exc:
            logger.warning("[%s] 'show vpc' failed: %s", self.hostname, exc)

        try:
            raw = conn.send_command("show vlan brief", read_timeout=30)
            self._save_raw(raw, "show_vlan_brief")
            vlans = self._parse_show_vlan_brief(raw)
        except Exception as exc:
            logger.warning("[%s] 'show vlan brief' failed: %s", self.hostname, exc)

        return {"port_channels": port_channels, "vpcs": vpcs, "vlans": vlans}

    def _parse_port_channel_summary(self, output: str) -> List[Dict]:
        """
        Parse `show port-channel summary` into a list of port-channel dicts.

        Format (truncated):
            Group Port-       Type     Protocol  Member Ports
                  Channel
            ----- ----------- -------- --------- ----------------------------
            1     Po1(SU)     Eth      LACP      Eth1/1(P)    Eth1/2(P)
            10    Po10(SU)    Eth      NONE      Eth1/10(P)
        """
        rows: List[Dict] = []
        in_table = False
        # Match: <group> <Po##(STATE)> <type> <protocol> <members...>
        row_re = re.compile(
            r"^\s*(\d+)\s+"
            r"(Po\d+)(?:\(([A-Za-z]+)\))?\s+"
            r"(\S+)\s+"
            r"(\S+)\s+"
            r"(.+)$"
        )
        for line in output.splitlines():
            stripped = line.strip()
            if not in_table:
                if stripped.startswith("---") and "---" in stripped:
                    in_table = True
                continue
            if not stripped:
                continue
            if stripped.startswith("---"):
                continue
            m = row_re.match(line)
            if not m:
                continue
            group, iface, state, type_, protocol, members_raw = m.groups()
            members = []
            for tok in members_raw.split():
                # Strip trailing "(P)", "(D)", etc.
                base = re.sub(r"\([A-Za-z]+\)$", "", tok)
                if base:
                    members.append(base)
            rows.append({
                "hostname": self.hostname,
                "group":     int(group),
                "interface": iface,
                "state":     state or "",
                "layer":     "L2" if type_.startswith("Eth") else ("L3" if type_.startswith("IP") else type_),
                "protocol":  protocol,
                "members":   members,
            })
        return rows

    def _parse_show_vpc(self, output: str) -> List[Dict]:
        """
        Parse `show vpc` into a list of vPC entries (one row per vPC ID).

        Each entry inherits the global domain/role/peer fields so the row is
        self-describing in the UI without a separate header view.
        """
        if not output or "vpc not configured" in output.lower():
            return []

        domain_id   = ""
        role        = ""
        peer_status = ""
        config_consistency = ""

        # Header fields
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("vPC domain id"):
                domain_id = stripped.split(":", 1)[-1].strip()
            elif stripped.startswith("vPC role"):
                role = stripped.split(":", 1)[-1].strip()
            elif stripped.startswith("Peer status"):
                # "peer adjacency formed ok" → "ok" / "peer-ok"
                val = stripped.split(":", 1)[-1].strip().lower()
                peer_status = "peer-ok" if "ok" in val else val
            elif stripped.startswith("Configuration consistency status"):
                config_consistency = stripped.split(":", 1)[-1].strip()

        # Row format under "vPC status":
        #   Id    Port          Status  Consistency  Reason  Active vlans
        #   --    ----          ------  -----------  ------  ------------
        #   10    Po10          up      success      success 10
        rows: List[Dict] = []
        in_status = False
        row_re = re.compile(
            r"^\s*(\d+)\s+"
            r"(\S+)\s+"
            r"(up|down)\s+"
            r"(\S+)\s+"
            r"(.+?)\s{2,}"
            r"(\S.*)?$"
        )
        for line in output.splitlines():
            stripped = line.strip()
            if not in_status:
                # The vPC status section is preceded by a header row containing "Id" and "Port"
                if stripped.startswith("Id") and "Port" in stripped and "Status" in stripped:
                    in_status = True
                continue
            if stripped.startswith("---") or not stripped:
                continue
            m = row_re.match(line)
            if not m:
                continue
            vpc_id, port, status, consistency, reason, active_vlans = m.groups()
            rows.append({
                "hostname":     self.hostname,
                "domain_id":    domain_id,
                "role":         role,
                "peer_status":  peer_status,
                "config_consistency": config_consistency,
                "vpc_id":       int(vpc_id),
                "port":         port,
                "status":       status.lower(),
                "consistency":  consistency.lower(),
                "reason":       (reason or "").strip(),
                "active_vlans": (active_vlans or "").strip() or "-",
            })
        return rows

    def _parse_show_vlan_brief(self, output: str) -> List[Dict]:
        """
        Parse `show vlan brief` into a list of VLAN dicts.

        Format:
            VLAN Name                             Status    Ports
            ---- -------------------------------- --------- ----------------------
            1    default                          active    Po1, Eth1/15
            10   USERS                            active    Po1, Po10, Eth1/20

        Continuation lines (extra ports without a leading VLAN id) are appended
        to the previous VLAN entry's ports list.
        """
        rows: List[Dict] = []
        current: Optional[Dict] = None
        header_seen = False
        row_re = re.compile(
            r"^\s*(\d+)\s+"
            r"(\S.*?)\s{2,}"
            r"(\S+)\s*"
            r"(.*)$"
        )
        for line in output.splitlines():
            if not header_seen:
                if line.lstrip().startswith("VLAN") and "Name" in line and "Status" in line:
                    header_seen = True
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("---"):
                continue
            m = row_re.match(line)
            if m:
                if current:
                    rows.append(current)
                vlan_id, name, state, ports_raw = m.groups()
                ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
                current = {
                    "hostname": self.hostname,
                    "vlan_id":  int(vlan_id),
                    "name":     name.strip(),
                    "state":    state.strip().lower(),
                    "ports":    ports,
                }
            elif current:
                # Continuation port list
                ports = [p.strip() for p in stripped.split(",") if p.strip()]
                current["ports"].extend(ports)
        if current:
            rows.append(current)
        return rows

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
