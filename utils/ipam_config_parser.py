"""
ipam_config_parser.py — Extract EIGRP summary-address declarations from
Cisco IOS / IOS-XE running configurations.

Two forms are supported:

  Named-mode EIGRP (preferred on modern IOS-XE):
      router eigrp TSA-EIGRP
       address-family ipv4 unicast autonomous-system 22
        af-interface Tunnel5000
         summary-address 10.1.0.0 255.255.252.0

  Classic-mode (interface-level):
      interface Tunnel5000
       ip summary-address eigrp 22 10.1.0.0 255.255.252.0
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import netaddr


_RE_ROUTER_EIGRP   = re.compile(r"^router\s+eigrp\s+(\S+)\s*$")
_RE_INTERFACE      = re.compile(r"^interface\s+(\S+)\s*$")
_RE_ADDR_FAMILY    = re.compile(r"^address-family\s+ipv4\s+unicast\s+autonomous-system\s+(\d+)\b")
_RE_AF_INTERFACE   = re.compile(r"^af-interface\s+(\S+)\s*$")
_RE_NAMED_SUMMARY  = re.compile(r"^summary-address\s+(\S+)\s+(\S+)")
_RE_CLASSIC_SUM    = re.compile(r"^ip\s+summary-address\s+eigrp\s+(\d+)\s+(\S+)\s+(\S+)")

# IPv6 address forms that yield a usable subnet:
#   ipv6 address 2001:db8::1/64
#   ipv6 address 2001:db8::/64 eui-64
# Forms we deliberately skip (no usable network info):
#   ipv6 address autoconfig
#   ipv6 address dhcp
#   ipv6 address fe80::1 link-local        -> excluded later by is_excluded
_RE_IPV6_ADDRESS   = re.compile(r"^ipv6\s+address\s+([0-9a-fA-F:]+)/(\d{1,3})\b")


def _mask_to_prefix(mask: str) -> Optional[int]:
    """Dotted-decimal mask -> prefix length, or None if unparseable."""
    try:
        return netaddr.IPAddress(mask).netmask_bits()
    except Exception:
        return None


def parse_eigrp_summaries(config: str) -> List[Dict]:
    """
    Walk a Cisco running-config and return every EIGRP summary-address found.

    Each result dict has:
        network        - dotted-decimal network address (str)
        prefix_length  - int (e.g. 22)
        af_interface   - the interface this summary is advertised on (str)
        eigrp_process  - named-mode process tag (str) or None for classic mode
        eigrp_as       - autonomous system number (int)
        mode           - 'named' or 'classic'
    """
    if not config:
        return []

    summaries: List[Dict] = []

    # Nesting context — only one of (eigrp_process, iface_name) is active at a time.
    eigrp_process: Optional[str] = None
    eigrp_as: Optional[int] = None
    af_interface: Optional[str] = None
    iface_name: Optional[str] = None

    for raw_line in config.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()

        # Skip blank lines and bang-only separators (which appear at every indent level).
        if not stripped or stripped == "!":
            continue

        indent = len(line) - len(stripped)

        # Indent 0 closes any nested context; only `router eigrp` or `interface`
        # opens a new one we care about.
        if indent == 0:
            eigrp_process = eigrp_as = af_interface = iface_name = None

            m = _RE_ROUTER_EIGRP.match(stripped)
            if m:
                eigrp_process = m.group(1)
                continue

            m = _RE_INTERFACE.match(stripped)
            if m:
                iface_name = m.group(1)
                continue

            continue

        # Inside a `router eigrp` block — track address-family / af-interface
        # nesting and capture summary-address rows.
        if eigrp_process is not None:
            m = _RE_ADDR_FAMILY.match(stripped)
            if m:
                eigrp_as = int(m.group(1))
                af_interface = None
                continue

            if stripped.startswith("exit-address-family"):
                eigrp_as = None
                af_interface = None
                continue

            m = _RE_AF_INTERFACE.match(stripped)
            if m:
                af_interface = m.group(1)
                continue

            if stripped.startswith("exit-af-interface"):
                af_interface = None
                continue

            if af_interface and eigrp_as is not None:
                m = _RE_NAMED_SUMMARY.match(stripped)
                if m:
                    network, mask = m.group(1), m.group(2)
                    prefix = _mask_to_prefix(mask)
                    if prefix is not None and prefix > 0:
                        summaries.append({
                            "network":       network,
                            "prefix_length": prefix,
                            "af_interface":  af_interface,
                            "eigrp_process": eigrp_process,
                            "eigrp_as":      eigrp_as,
                            "mode":          "named",
                        })
            continue

        # Inside a classic `interface` block — look for `ip summary-address eigrp`.
        if iface_name is not None:
            m = _RE_CLASSIC_SUM.match(stripped)
            if m:
                as_num, network, mask = int(m.group(1)), m.group(2), m.group(3)
                prefix = _mask_to_prefix(mask)
                if prefix is not None and prefix > 0:
                    summaries.append({
                        "network":       network,
                        "prefix_length": prefix,
                        "af_interface":  iface_name,
                        "eigrp_process": None,
                        "eigrp_as":      as_num,
                        "mode":          "classic",
                    })

    return summaries


def parse_ipv6_addresses(config: str) -> List[Dict]:
    """
    Walk a Cisco running-config and return every IPv6 address declared on an
    interface. Handles IOS / IOS-XE and NX-OS (same `ipv6 address X/Y` syntax).

    Only static addresses with explicit prefix are returned — `autoconfig`,
    `dhcp`, and prefix-less link-local forms are skipped.

    Each result dict has:
        interface     - the interface name (str)
        address       - the IPv6 address (str, e.g. "2001:db8::1")
        prefix_length - int (e.g. 64)
        cidr          - "<address>/<prefix>" convenience field
    """
    if not config:
        return []

    results: List[Dict] = []
    iface_name: Optional[str] = None

    for raw_line in config.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()

        if not stripped or stripped == "!":
            continue

        indent = len(line) - len(stripped)

        if indent == 0:
            iface_name = None
            m = _RE_INTERFACE.match(stripped)
            if m:
                iface_name = m.group(1)
            continue

        if iface_name is None:
            continue

        m = _RE_IPV6_ADDRESS.match(stripped)
        if not m:
            continue
        addr, prefix_str = m.group(1), m.group(2)
        try:
            prefix = int(prefix_str)
        except ValueError:
            continue
        if prefix < 1 or prefix > 128:
            continue
        results.append({
            "interface":     iface_name,
            "address":       addr,
            "prefix_length": prefix,
            "cidr":          f"{addr}/{prefix}",
        })

    return results
