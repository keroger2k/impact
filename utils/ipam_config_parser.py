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
_RE_ROUTER_OSPF    = re.compile(r"^router\s+ospf\s+(\S+)\s*$")
_RE_ROUTER_BGP     = re.compile(r"^router\s+bgp\s+(\S+)\s*$")
_RE_INTERFACE      = re.compile(r"^interface\s+(\S+)\s*$")
_RE_ADDR_FAMILY    = re.compile(r"^address-family\s+ipv4\s+unicast(?:\s+vrf\s+\S+)?\s+autonomous-system\s+(\d+)\b")
_RE_AF_INTERFACE   = re.compile(r"^af-interface\s+(\S+)\s*$")
_RE_NAMED_SUMMARY  = re.compile(r"^summary-address\s+(\S+)\s+(\S+)")
_RE_CLASSIC_SUM    = re.compile(r"^ip\s+summary-address\s+eigrp\s+(\d+)\s+(\S+)\s+(\S+)")

# Non-EIGRP summary forms. These don't need EIGRP context tracking; they live
# in different parent blocks (or no block at all for static routes).
_RE_STATIC_NULL    = re.compile(r"^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+[Nn]ull0\b")
_RE_OSPF_AREA_RNG  = re.compile(r"^area\s+(\S+)\s+range\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\b")
_RE_BGP_AGGR_IOS   = re.compile(r"^aggregate-address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\b")
_RE_BGP_AGGR_NX    = re.compile(r"^aggregate-address\s+(\d+\.\d+\.\d+\.\d+)/(\d{1,2})\b")

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


def parse_static_null_summaries(config: str) -> List[Dict]:
    """Parse `ip route NET MASK Null0` declarations.

    A static route pointing at Null0 is the canonical way to anchor a summary
    CIDR that's then advertised via `redistribute static` into a routing
    protocol. Each result has:
        network        - dotted-decimal network address (str)
        prefix_length  - int
    """
    if not config:
        return []
    results: List[Dict] = []
    for raw_line in config.splitlines():
        stripped = raw_line.strip()
        m = _RE_STATIC_NULL.match(stripped)
        if not m:
            continue
        network, mask = m.group(1), m.group(2)
        prefix = _mask_to_prefix(mask)
        if prefix is None or prefix <= 0:
            continue
        results.append({"network": network, "prefix_length": prefix})
    return results


def parse_ospf_area_ranges(config: str) -> List[Dict]:
    """Parse `area X range NET MASK` declarations under `router ospf <pid>`.

    Each result has:
        network        - dotted-decimal network address (str)
        prefix_length  - int
        area           - OSPF area id (str, may be dotted-quad form)
        ospf_process   - process id (str)
    """
    if not config:
        return []
    results: List[Dict] = []
    ospf_process: Optional[str] = None

    for raw_line in config.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()
        if not stripped or stripped == "!":
            continue
        indent = len(line) - len(stripped)

        if indent == 0:
            ospf_process = None
            m = _RE_ROUTER_OSPF.match(stripped)
            if m:
                ospf_process = m.group(1)
            continue

        if ospf_process is None:
            continue

        m = _RE_OSPF_AREA_RNG.match(stripped)
        if not m:
            continue
        area, network, mask = m.group(1), m.group(2), m.group(3)
        prefix = _mask_to_prefix(mask)
        if prefix is None or prefix <= 0:
            continue
        results.append({
            "network":      network,
            "prefix_length": prefix,
            "area":         area,
            "ospf_process": ospf_process,
        })
    return results


def parse_bgp_aggregates(config: str) -> List[Dict]:
    """Parse `aggregate-address ...` declarations under `router bgp <as>`.

    Handles two forms:
      - IOS / IOS-XE:  aggregate-address A.B.C.D E.F.G.H [summary-only ...]
      - NX-OS:         aggregate-address A.B.C.D/N      [summary-only ...]

    Only IPv4-unicast aggregates are returned. An `address-family ipv6 ...`
    block suppresses capture while open.

    Each result has:
        network        - dotted-decimal network address (str)
        prefix_length  - int
        bgp_as         - BGP AS the aggregate is configured under (str)
    """
    if not config:
        return []
    results: List[Dict] = []
    bgp_as: Optional[str] = None
    in_v6_af = False

    for raw_line in config.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()
        if not stripped or stripped == "!":
            continue
        indent = len(line) - len(stripped)

        if indent == 0:
            bgp_as = None
            in_v6_af = False
            m = _RE_ROUTER_BGP.match(stripped)
            if m:
                bgp_as = m.group(1)
            continue

        if bgp_as is None:
            continue

        if stripped.startswith("address-family ipv6"):
            in_v6_af = True
            continue
        if stripped.startswith("address-family ipv4"):
            in_v6_af = False
            continue
        if stripped.startswith("exit-address-family"):
            in_v6_af = False
            continue
        if in_v6_af:
            continue

        m = _RE_BGP_AGGR_IOS.match(stripped)
        if m:
            network, mask = m.group(1), m.group(2)
            prefix = _mask_to_prefix(mask)
        else:
            m = _RE_BGP_AGGR_NX.match(stripped)
            if not m:
                continue
            network, prefix = m.group(1), int(m.group(2))

        if prefix is None or prefix <= 0:
            continue
        results.append({
            "network":      network,
            "prefix_length": prefix,
            "bgp_as":       bgp_as,
        })
    return results


def parse_aggregate_summaries(config: str) -> List[Dict]:
    """Return every IPv4 summary/aggregate found in a Cisco config, regardless
    of which routing protocol declared it. The engine treats them all
    identically (DNAC-Config-source aggregate nodes) — the `kind` field is
    just there so we can label them helpfully in the dashboard / CSV.

    Each result has:
        kind           - 'eigrp' | 'static-null' | 'ospf-range' | 'bgp-aggregate'
        network        - dotted-decimal network address (str)
        prefix_length  - int
        context        - short, kind-specific label (interface/area/AS/…)
    """
    out: List[Dict] = []
    for s in parse_eigrp_summaries(config):
        out.append({
            "kind":          "eigrp",
            "network":       s["network"],
            "prefix_length": s["prefix_length"],
            "context":       s.get("af_interface") or "",
        })
    for s in parse_static_null_summaries(config):
        out.append({
            "kind":          "static-null",
            "network":       s["network"],
            "prefix_length": s["prefix_length"],
            "context":       "Null0",
        })
    for s in parse_ospf_area_ranges(config):
        out.append({
            "kind":          "ospf-range",
            "network":       s["network"],
            "prefix_length": s["prefix_length"],
            "context":       f"area {s['area']}",
        })
    for s in parse_bgp_aggregates(config):
        out.append({
            "kind":          "bgp-aggregate",
            "network":       s["network"],
            "prefix_length": s["prefix_length"],
            "context":       f"AS {s['bgp_as']}",
        })
    return out


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
