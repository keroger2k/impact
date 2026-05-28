"""utils/site_aggregator.py — Per-site rollup across DNAC, Nexus, Panorama,
IPAM (DNAC reserve subpools), IPv6 registry, and the normalized tunnel
inventory.

A "site" here is identified by a short code (K023, SDCZ, …) — the same
codes ``utils.site_code`` extracts from DNAC hierarchies and hostnames.
Each helper is a pure read against the existing caches; nothing here
hits the network. The router calls these synchronously inside a thread
executor when a request lands on /site/{code}.

The aggregator never raises on missing cache data — it returns empty
lists/None and lets the template render an empty state. The site page
should still load when DNAC is cold or the tunnel inventory hasn't been
built yet.
"""
from __future__ import annotations

import re
from typing import Optional

from cache import cache, TUNNEL_INVENTORY_CACHE_KEY
from clients import ipv6_registry
from utils.site_code import site_code as _sc, site_code_from_hostname as _sch


# ── Site identity ────────────────────────────────────────────────────────────

def resolve_site(code: str) -> dict:
    """Resolve a typed site code against the DNAC site hierarchy cache.

    Returns ``{"code": <upper>, "hierarchies": [<full path>, ...]}``. A
    single code can match multiple DNAC entries (building + floor + area);
    the most-specific path appears first.
    """
    code_u = (code or "").strip().upper()
    sites = cache.get("sites") or []
    matches: list[str] = []
    for s in sites:
        name = s.get("name") or s.get("siteNameHierarchy") or ""
        if not name:
            continue
        if _sc(name).upper() == code_u:
            matches.append(name)
    # Longer paths are more specific — list them first.
    matches.sort(key=lambda n: (-n.count("/"), n))
    return {"code": code_u, "hierarchies": matches}


# ── Devices ──────────────────────────────────────────────────────────────────

# DNAC roles whose devices are likely running a routing protocol. Distribution
# is included because at smaller sites the dist switches carry the L3 edge.
ROUTING_ROLES = {"CORE", "BORDER ROUTER", "DISTRIBUTION"}


def list_devices_for_site(code: str) -> list[dict]:
    """Return every device associated with this site code.

    Sources:
      * DNAC devices whose ``device_site_map`` entry's site_code matches
      * Nexus inventory rows whose hostname's site_code matches
      * Panorama firewalls (from ``pan_interfaces``) whose hostname matches

    Each returned dict carries ``source`` ('DNAC'|'Nexus'|'Panorama'),
    ``siteName`` (best-known hierarchy or empty), and the standard
    inventory fields the devices table renders.
    """
    code_u = (code or "").strip().upper()
    if not code_u:
        return []

    out: list[dict] = []

    devices = cache.get("devices") or []
    dev_site_map = cache.get("device_site_map") or {}

    for d in devices:
        dev_id = d.get("id")
        site_name = dev_site_map.get(dev_id) or ""
        derived = _sc(site_name) or _sch(d.get("hostname") or "")
        if derived.upper() != code_u:
            continue
        out.append({
            "source": "DNAC",
            "id": dev_id,
            "hostname": d.get("hostname"),
            "managementIpAddress": d.get("managementIpAddress"),
            "platformId": d.get("platformId"),
            "role": (d.get("role") or "").upper(),
            "softwareVersion": d.get("softwareVersion"),
            "reachabilityStatus": d.get("reachabilityStatus"),
            "upTime": d.get("upTime"),
            "siteName": site_name,
        })

    # Nexus — site code comes from hostname only.
    try:
        from routers.nexus import get_cached_nexus_inventory
        for d in get_cached_nexus_inventory() or []:
            if _sch(d.get("hostname") or "").upper() != code_u:
                continue
            out.append({
                "source": "Nexus",
                "id": d.get("id") or d.get("hostname"),
                "hostname": d.get("hostname"),
                "managementIpAddress": d.get("managementIpAddress"),
                "platformId": d.get("platformId"),
                "role": (d.get("role") or "").upper(),
                "softwareVersion": d.get("softwareVersion"),
                "reachabilityStatus": d.get("reachabilityStatus"),
                "upTime": d.get("upTime"),
                "siteName": "",
            })
    except Exception:
        pass

    # Panorama firewalls — same hostname-prefix rule.
    pan_devs = cache.get("pan_interfaces") or []
    for d in pan_devs:
        hostname = d.get("hostname") or ""
        if _sch(hostname).upper() != code_u:
            continue
        out.append({
            "source": "Panorama",
            "id": d.get("serial") or hostname,
            "hostname": hostname,
            "managementIpAddress": d.get("ip_address") or d.get("ipAddress"),
            "platformId": d.get("model") or "PA",
            "role": "FIREWALL",
            "softwareVersion": d.get("sw_version") or d.get("swVersion"),
            "reachabilityStatus": "Reachable" if d.get("connected") else "Unknown",
            "upTime": d.get("uptime"),
            "siteName": "",
        })

    out.sort(key=lambda d: (d.get("hostname") or "").lower())
    return out


# ── Routing protocols (config-grep) ──────────────────────────────────────────

_RE_BGP   = re.compile(r"^\s*router\s+bgp\s+(\S+)", re.MULTILINE | re.IGNORECASE)
_RE_OSPF  = re.compile(r"^\s*router\s+ospf\s+(\d+)", re.MULTILINE | re.IGNORECASE)
_RE_EIGRP_CLASSIC = re.compile(r"^\s*router\s+eigrp\s+(\d+)\s*$", re.MULTILINE | re.IGNORECASE)
_RE_EIGRP_NAMED   = re.compile(r"^\s*router\s+eigrp\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE)


def detect_protocols(config_text: Optional[str]) -> dict:
    """Return ``{"bgp": {...}|None, "ospf": {...}|None, "eigrp": {...}|None}``.

    Each protocol entry, when present, carries the AS / process id /
    instance name parsed out of the ``router <proto> X`` line. ``None``
    means the protocol is not configured on this device.
    """
    if not config_text:
        return {"bgp": None, "ospf": None, "eigrp": None}

    result = {"bgp": None, "ospf": None, "eigrp": None}

    m = _RE_BGP.search(config_text)
    if m:
        result["bgp"] = {"asn": m.group(1)}

    m = _RE_OSPF.search(config_text)
    if m:
        result["ospf"] = {"process_id": m.group(1)}

    m = _RE_EIGRP_CLASSIC.search(config_text)
    if m:
        result["eigrp"] = {"asn": m.group(1), "named": False}
    else:
        m = _RE_EIGRP_NAMED.search(config_text)
        if m:
            result["eigrp"] = {"instance": m.group(1), "named": True}

    return result


def routing_devices(devices: list[dict]) -> list[dict]:
    """Filter site devices to those likely running a routing protocol,
    and attach a ``protocols`` dict from the cached config-grep.

    Reads ``dnac_device_configs`` (already populated by the IPAM/tunnel
    refresh paths). Devices without a cached config get the all-None
    protocols dict — the UI hides them.
    """
    configs = cache.get("dnac_device_configs") or {}
    out: list[dict] = []
    for d in devices:
        if d.get("source") != "DNAC":
            continue
        if d.get("role") not in ROUTING_ROLES:
            continue
        protos = detect_protocols(configs.get(d.get("id")))
        if not any(protos.values()):
            continue
        d2 = dict(d)
        d2["protocols"] = protos
        out.append(d2)
    return out


# ── IPAM (DNAC reserve subpools) ─────────────────────────────────────────────

def ipam_pools_for_site(code: str) -> list[dict]:
    """Return every DNAC reserve subpool whose siteName resolves to this code.

    Output: flat list of ``{cidr, name, group_name, is_ipv6, gateway,
    dhcp_servers, site_name}`` rows. One reserve-pool row in the DNAC
    cache typically carries one or two inner pools (v4 + v6 dual-stack);
    each becomes its own row here.
    """
    code_u = (code or "").strip().upper()
    if not code_u:
        return []
    subpools = cache.get("dnac_reserve_subpools") or []
    out: list[dict] = []
    for sp in subpools:
        site_name = sp.get("siteName") or sp.get("groupName") or ""
        if _sc(site_name).upper() != code_u:
            continue
        group_name = sp.get("groupName") or ""
        inner_pools = sp.get("ipPools") or []
        if not isinstance(inner_pools, list):
            inner_pools = [inner_pools]
        for ip in inner_pools:
            cidr = ip.get("ipPoolCidr") or ip.get("cidr")
            if not cidr:
                continue
            gateways = ip.get("gateways") or []
            if isinstance(gateways, str):
                gateways = [gateways]
            dhcp = ip.get("dhcpServerIps") or []
            if isinstance(dhcp, str):
                dhcp = [dhcp]
            out.append({
                "cidr": cidr,
                "name": ip.get("ipPoolName") or group_name or "Reserved Pool",
                "group_name": group_name,
                "is_ipv6": bool(ip.get("ipv6")) or ":" in cidr,
                "gateway": gateways[0] if gateways else None,
                "dhcp_servers": dhcp,
                "site_name": site_name,
            })
    out.sort(key=lambda r: (r["is_ipv6"], r["cidr"]))
    return out


# ── IPv6 registry ────────────────────────────────────────────────────────────

def ipv6_for_site(code: str) -> Optional[dict]:
    """Match an IPv6 registry site row by name (case-insensitive substring)
    against the site code, and return ``{site, allocations}``.

    Returns ``None`` if no registry row matches. Registry names don't
    follow the same code convention as DNAC hierarchies, so this is a
    best-effort lookup — operators name registry sites with codes like
    "K023" or "DC1 K023" but not always.
    """
    code_u = (code or "").strip().upper()
    if not code_u:
        return None
    try:
        sites = ipv6_registry.list_sites()
    except Exception:
        return None
    # Prefer an exact word-boundary match before falling back to substring.
    word_re = re.compile(rf"\b{re.escape(code_u)}\b", re.IGNORECASE)
    site = next((s for s in sites if word_re.search(s.get("name") or "")), None)
    if not site:
        site = next((s for s in sites if code_u in (s.get("name") or "").upper()), None)
    if not site:
        return None
    try:
        allocs = ipv6_registry.list_allocations(site_id=site["id"])
    except Exception:
        allocs = []
    return {"site": site, "allocations": allocs}


# ── Tunnels ──────────────────────────────────────────────────────────────────

def tunnels_for_site(code: str) -> list[dict]:
    """Return every tunnel whose any endpoint has ``local_site_code`` equal
    to this site code. The normalized inventory already populates
    local_site_code from either the site path or the hostname."""
    code_u = (code or "").strip().upper()
    if not code_u:
        return []
    inv = cache.get(TUNNEL_INVENTORY_CACHE_KEY) or {}
    out: list[dict] = []
    for t in inv.get("tunnels") or []:
        for ep in t.get("endpoints") or []:
            if (ep.get("local_site_code") or "").upper() == code_u:
                out.append(t)
                break
    return out
