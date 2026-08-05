"""utils/bandwidth_report.py — Site Bandwidth Utilization report (SolarWinds).

Looks up a Cisco router interface by node name + interface name (defaulting
to Tunnel5000, the standard DMVPN hub-facing interface across TSA sites), then
pulls percent-utilization traffic history for the last 24 hours and last 7
days. Data only — `routers/reports.py` returns this as JSON and the chart is
rendered client-side as inline SVG; nothing is written to disk here.
"""
from __future__ import annotations

import re

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


def find_interfaces(router_name: str | None, interface_name: str, username: str, password: str) -> list[dict]:
    """Find interfaces matching `interface_name`, optionally scoped to a router."""
    interface_name = _validate_name(interface_name, "Interface name")
    iface_lit = _escape_literal(interface_name)

    where_router = ""
    if router_name:
        router_name = _validate_name(router_name, "Router name")
        where_router = f"n.Caption = '{_escape_literal(router_name)}'\n    AND "

    swql = f"""
SELECT
    n.NodeID,
    n.Caption AS NodeName,
    n.IPAddress AS NodeIpAddress,
    i.InterfaceID,
    i.Caption AS InterfaceCaption,
    i.Name AS InterfaceName,
    i.InterfaceAlias,
    i.Status,
    i.StatusDescription
FROM Orion.NPM.Interfaces i
JOIN Orion.Nodes n ON i.NodeID = n.NodeID
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
"""
    rows = solarwinds.query(swql, username, password)
    if not rows:
        return None
    exact = [r for r in rows if (r.get("NodeName") or "").strip().lower() == name.lower()]
    match = exact[0] if exact else rows[0]
    return match.get("NodeIpAddress")


def get_interface_by_id(interface_id: int, username: str, password: str) -> dict | None:
    swql = f"""
SELECT
    n.NodeID,
    n.Caption AS NodeName,
    n.IPAddress AS NodeIpAddress,
    i.InterfaceID,
    i.Caption AS InterfaceCaption,
    i.Name AS InterfaceName,
    i.InterfaceAlias,
    i.Status,
    i.StatusDescription
FROM Orion.NPM.Interfaces i
JOIN Orion.Nodes n ON i.NodeID = n.NodeID
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
    return {
        "status": "ok",
        "node_name": meta.get("NodeName"),
        "node_ip": meta.get("NodeIpAddress"),
        "interface_caption": meta.get("InterfaceCaption") or meta.get("InterfaceName"),
        "interface_id": iface_id,
        "series_24h": get_traffic_series(iface_id, 24, username, password),
        "series_7d": get_traffic_series(iface_id, 24 * 7, username, password),
    }
