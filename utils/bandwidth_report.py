"""utils/bandwidth_report.py — Site Bandwidth Utilization report (SolarWinds).

Looks up a Cisco router interface by node name + interface name (defaulting
to Tunnel5000, the standard DMVPN hub-facing interface across TSA sites), then
pulls percent-utilization traffic history for the last 24 hours and last 7
days. Data only — `routers/reports.py` returns this as JSON and the chart is
rendered client-side as inline SVG; nothing is written to disk here.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import clients.solarwinds as solarwinds

# Conservative charset for names interpolated into SWQL — mirrors
# routers/firewall.py's _CLI_NAME_RE for the same reason (untrusted web input
# reaching a query string).
_SWQL_NAME_RE = re.compile(r"^[\w .:/-]{1,63}$")

DEFAULT_INTERFACE = "Tunnel5000"


class InvalidNameError(ValueError):
    """A router/interface name failed the SWQL-safe charset check."""


def _validate_name(value: str, label: str) -> str:
    value = value.strip()
    if not value or not _SWQL_NAME_RE.match(value):
        raise InvalidNameError(f"{label} contains unsupported characters")
    return value


def _escape_literal(value: str) -> str:
    # Belt-and-suspenders on top of the charset allowlist above: SWQL string
    # literals end on an unescaped single quote.
    return value.replace("'", "''")


# Selected + joined once here and reused by both find_interfaces() and
# get_interface_by_id() so the Site Information panel costs no extra round
# trip — the interface lookup already touches every table it needs. Field
# names confirmed against a real SolarWinds instance (see
# scripts/solarwinds_discover_site_properties.py's docstring for the
# discovery trail): Orion.NodesCustomProperties needs an explicit join on
# NodeID (it doesn't expose Caption directly), exactly the pattern
# utils/cdrl49_report.py's build_swql() already uses for Site/Building/State.
_SITE_INFO_SELECT = """
    n.NodeID,
    n.Caption AS NodeName,
    n.IPAddress AS NodeIpAddress,
    n.Contact AS NodeContact,
    i.InterfaceID,
    i.Caption AS InterfaceCaption,
    i.Name AS InterfaceName,
    i.InterfaceAlias,
    i.Status,
    i.StatusDescription,
    i.Speed AS InterfaceSpeed,
    cp.Site,
    cp.Building,
    cp.City,
    cp.State,
    cp.Airport_Code,
    cp.AirportCategory
"""
_SITE_INFO_JOIN = """
FROM Orion.NPM.Interfaces i
JOIN Orion.Nodes n ON i.NodeID = n.NodeID
JOIN Orion.NodesCustomProperties cp ON cp.NodeID = n.NodeID
"""


def find_interfaces(router_name: str | None, interface_name: str, username: str, password: str) -> list[dict]:
    """Find interfaces matching `interface_name`, optionally scoped to a router."""
    interface_name = _validate_name(interface_name, "Interface name")
    iface_lit = _escape_literal(interface_name)

    where_router = ""
    if router_name:
        router_name = _validate_name(router_name, "Router name")
        where_router = f"n.Caption = '{_escape_literal(router_name)}'\n    AND "

    swql = f"""
SELECT{_SITE_INFO_SELECT}{_SITE_INFO_JOIN}
WHERE
    {where_router}(
        i.Caption = '{iface_lit}'
        OR i.Name = '{iface_lit}'
        OR i.InterfaceAlias = '{iface_lit}'
        OR i.Caption LIKE '%{iface_lit}%'
        OR i.Name LIKE '%{iface_lit}%'
        OR i.InterfaceAlias LIKE '%{iface_lit}%'
    )
ORDER BY n.Caption, i.Caption
"""
    return solarwinds.query(swql, username, password)


def find_node_ip(router_name: str, username: str, password: str) -> str | None:
    """Resolve a router's SolarWinds-polled IP address by node Caption.

    Used by the Application Traffic report (utils/sna_report.py) to match SNA's
    Report Builder Exporters, which are keyed by IP rather than hostname
    (confirmed against real production data — the hostname substring match
    that works for everything else on this page came up empty against SNA).
    """
    name = _validate_name(router_name, "Router name")
    lit = _escape_literal(name)
    swql = f"""
SELECT n.Caption AS NodeName, n.IPAddress AS NodeIpAddress
FROM Orion.Nodes n
WHERE n.Caption = '{lit}' OR n.Caption LIKE '%{lit}%'
ORDER BY n.Caption
"""
    rows = solarwinds.query(swql, username, password)
    if not rows:
        return None
    exact = [r for r in rows if (r.get("NodeName") or "").strip().lower() == name.lower()]
    match = exact[0] if exact else rows[0]
    return match.get("NodeIpAddress")


def get_interface_by_id(interface_id: int, username: str, password: str) -> dict | None:
    swql = f"""
SELECT{_SITE_INFO_SELECT}{_SITE_INFO_JOIN}
WHERE i.InterfaceID = {int(interface_id)}
"""
    rows = solarwinds.query(swql, username, password)
    return rows[0] if rows else None


def get_traffic_series(interface_id: int, hours: int, username: str, password: str) -> list[dict]:
    swql = f"""
SELECT
    it.DateTime,
    it.InPercentUtil,
    it.OutPercentUtil
FROM Orion.NPM.InterfaceTraffic it
WHERE it.InterfaceID = {int(interface_id)}
AND it.DateTime >= ADDHOUR(-{int(hours)}, GETUTCDATE())
ORDER BY it.DateTime
"""
    raw = solarwinds.query(swql, username, password)

    def _num(value):
        if value in (None, ""):
            return None
        try:
            return round(float(value), 2)
        except (TypeError, ValueError):
            return None

    points = []
    for row in raw:
        dt = row.get("DateTime")
        if not dt:
            continue
        points.append({
            "t": dt,
            "in": _num(row.get("InPercentUtil")),
            "out": _num(row.get("OutPercentUtil")),
        })
    return points


def generate_bandwidth_report(
    router_name: str | None,
    interface_name: str,
    interface_id: int | None,
    username: str,
    password: str,
) -> dict:
    """Resolve the target interface, then pull 24h + 7d traffic series.

    Returns one of:
      {"status": "ambiguous", "candidates": [...]}   — let the caller disambiguate
      {"status": "ok", "node_name", "interface_caption", "interface_id",
       "series_24h", "series_7d"}

    Raises InvalidNameError on bad input, LookupError if nothing matches.
    """
    if interface_id is not None:
        meta = get_interface_by_id(interface_id, username, password)
        if not meta:
            raise LookupError("Interface not found")
    else:
        if not router_name:
            raise InvalidNameError("Router name is required")
        matches = find_interfaces(router_name, interface_name or DEFAULT_INTERFACE, username, password)
        if not matches:
            raise LookupError("No matching interface found")
        if len(matches) > 1:
            return {
                "status": "ambiguous",
                "candidates": [
                    {
                        "interface_id": m.get("InterfaceID"),
                        "node_name": m.get("NodeName"),
                        "node_ip": m.get("NodeIpAddress"),
                        "caption": m.get("InterfaceCaption"),
                        "name": m.get("InterfaceName"),
                        "alias": m.get("InterfaceAlias"),
                        "status": m.get("StatusDescription"),
                    }
                    for m in matches
                ],
            }
        meta = matches[0]

    iface_id = meta.get("InterfaceID")

    # The 24h and 7d windows are independent SolarWinds queries — run them
    # concurrently rather than back-to-back. This function already executes
    # inside its own worker thread (routers/reports.py's run_in_executor), so
    # a small in-function pool just overlaps the two blocking HTTP calls
    # instead of serializing them, which matters since the user is watching
    # a spinner on this synchronous, uncached endpoint.
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_24h = pool.submit(get_traffic_series, iface_id, 24, username, password)
        fut_7d = pool.submit(get_traffic_series, iface_id, 24 * 7, username, password)
        series_24h = fut_24h.result()
        series_7d = fut_7d.result()

    return {
        "status": "ok",
        "node_name": meta.get("NodeName"),
        "node_ip": meta.get("NodeIpAddress"),
        "interface_caption": meta.get("InterfaceCaption") or meta.get("InterfaceName"),
        "interface_id": iface_id,
        "site_info": _build_site_info(meta),
        "series_24h": series_24h,
        "series_7d": series_7d,
    }


def _build_site_info(meta: dict) -> dict:
    """Site Information panel fields confirmed against a real SolarWinds
    instance (see scripts/solarwinds_discover_site_properties.py). Circuit
    Provider, FRM, and Transition Date aren't tracked anywhere in SolarWinds
    (checked all 43 configured custom properties plus every interface's
    caption/carrier fields) — they're left out here and stay manual inputs
    on the report itself.
    """
    speed = meta.get("InterfaceSpeed")
    circuit_mbps = None
    if speed not in (None, ""):
        try:
            circuit_mbps = round(float(speed) / 1_000_000, 1)
        except (TypeError, ValueError):
            circuit_mbps = None

    def _clean(value):
        return value.strip() if isinstance(value, str) and value.strip() else None

    return {
        "site_code": _clean(meta.get("Site")),
        "airport_code": _clean(meta.get("Airport_Code")),
        "category": _clean(meta.get("AirportCategory")),
        "building": _clean(meta.get("Building")),
        "city": _clean(meta.get("City")),
        "state": _clean(meta.get("State")),
        "local_poc": _clean(meta.get("NodeContact")),
        "circuit_size_mbps": circuit_mbps,
    }
