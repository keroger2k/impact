"""utils/sna_report.py — resolve a router+interface name to SNA's IDs and pull application traffic.

SNA's Report Builder filter hierarchy is Flow Collector → Exporter →
Interface, keyed by opaque internal IDs — nothing here matches SolarWinds'
IDs, so this does its own resolution against SNA's own device list. See
clients/sna.py's module docstring for how that hierarchy maps to real
infrastructure (Exporter = router, not "Device").

Exporters are keyed by IP, not hostname (confirmed against real production
data — a router that resolved fine everywhere else on this page came up
empty here on a hostname substring match alone). So this first resolves the
router name to its SolarWinds-polled IP (utils.bandwidth_report.find_node_ip)
and matches Exporters against that; a hostname substring match is kept as a
fallback for environments where an Exporter's name does carry the hostname.
"""
from __future__ import annotations

import clients.sna as sna_client
from utils.bandwidth_report import bare_interface_name, find_node_ip, short_hostname
from utils.report_pool import FANOUT_POOL


def find_exporters(
    session, base_url: str, domain_id: str, router_name: str, router_ip: str | None = None,
) -> list[dict]:
    """Match every Flow Collector's exporters against `router_ip` (exact) first;
    if nothing matches on IP, fall back to a case-insensitive substring match
    on `router_name` against the exporter's name. Returns candidates:
    [{"device_id", "device_name", "exporter_ip", "exporter_name"}]."""
    needle = router_name.strip().lower()
    ip_matches = []
    name_matches = []
    for device in sna_client.list_flow_collectors(session, base_url, domain_id):
        device_id = device.get("id")
        device_name = device.get("name") or ""
        for exp in sna_client.list_exporters(session, base_url, domain_id, device_id):
            exp_id = str(exp.get("id") or "").strip()
            exp_name = str(exp.get("name") or "").strip()
            candidate = {
                "device_id": device_id,
                "device_name": device_name,
                "exporter_ip": exp.get("id"),
                "exporter_name": exp_name or exp_id,
            }
            if router_ip and exp_id == router_ip:
                ip_matches.append(candidate)
            elif needle and needle in exp_name.lower():
                name_matches.append(candidate)
    return ip_matches or name_matches


def _interface_name_candidates(interface_name: str) -> list[str]:
    """Progressively less specific forms of an interface name to match on.

    The dropdown now posts a bare interface name, so the first candidate
    normally hits. This kept as a safety net for values that still arrive
    decorated — a SolarWinds Caption pasted by hand, or an older client:
    SNA's interface names are bare identifiers ("Tunnel5000", or an
    "ifIndex-N" fallback), and a decorated string is longer than the stored
    name, which a longer string can never substring-match (same failure class
    as the FQDN router-name bug — see utils.bandwidth_report.short_hostname).
    Full string first, so an environment whose SNA names *do* carry
    decoration still wins on the exact match.
    """
    full = interface_name.strip()
    candidates = [full]
    bare = bare_interface_name(full)
    if bare and bare != full:
        candidates.append(bare)
    return [c for c in candidates if c]


def find_interfaces(
    session, base_url: str, domain_id: str, device_id, exporter_ip: str, interface_name: str,
) -> list[dict]:
    """Exact (case-insensitive) match first, falling back to substring, over
    each candidate form of the name (see _interface_name_candidates).
    Returns candidates: [{"interface_id", "interface_name"}]."""
    interfaces = sna_client.list_interfaces(session, base_url, domain_id, device_id, exporter_ip)

    for candidate in _interface_name_candidates(interface_name):
        needle = candidate.lower()
        exact = [i for i in interfaces if (i.get("name") or "").strip().lower() == needle]
        pool = exact or [i for i in interfaces if needle in (i.get("name") or "").lower()]
        if pool:
            return [{"interface_id": i.get("id"), "interface_name": i.get("name")} for i in pool]

    return []


def generate_application_traffic_report(
    base_url: str,
    domain: str,
    username: str,
    password: str,
    router_name: str,
    interface_name: str,
) -> dict:
    """Resolve router+interface against SNA, then pull the application-traffic
    report for both the last 24 hours and the last 7 days in one call — mirrors
    utils.bandwidth_report.generate_bandwidth_report's single-request,
    both-windows shape, so one "Generate" click on the Bandwidth Utilization
    report can produce every chart without a second click.

    Returns one of:
      {"status": "ambiguous", "level": "exporter"|"interface", "candidates": [...]}
      {"status": "ok", "node_name", "interface_name", "traffic_24h": {...}, "traffic_7d": {...}}
      (each traffic_* is {"buckets", "applications", "series"}, see utils.sna_traffic)

    Raises sna_client.SNAError on auth/API failure, LookupError if nothing
    matches, InvalidNameError if router_name fails the SolarWinds charset
    check, or whatever clients.solarwinds.query raises on a SolarWinds
    failure (that lookup is load-bearing here, not best-effort — swallowing
    it would surface a misleading "no exporter found" instead of the real
    cause).
    """
    # Both the SolarWinds IP lookup (find_node_ip, an exact-then-LIKE match
    # on Node Caption) and SNA's own exporter name-fallback match
    # (find_exporters, a substring check) need the short form — an FQDN
    # (DNAC's `devices` cache occasionally carries one) is longer than
    # either stored name and can't satisfy either comparison. Normalize
    # once here so every downstream use — including the routers/reports.py
    # datalist this usually arrives from — sees the same short name.
    router_name = short_hostname(router_name)
    router_ip = find_node_ip(router_name)

    session = sna_client.login(base_url, username, password, domain)
    try:
        return _report_with_session(session, base_url, router_name, router_ip, interface_name)
    finally:
        # Every Generate click mints a new SMC session; without this they'd
        # accumulate server-side until they age out. Best-effort — a failed
        # logout must not mask a successful report (or a real error).
        sna_client.logout(session, base_url)


def _report_with_session(
    session, base_url: str, router_name: str, router_ip: str | None, interface_name: str,
) -> dict:
    domain_id = sna_client.get_tenant_id(session, base_url)

    exporters = find_exporters(session, base_url, domain_id, router_name, router_ip)
    if not exporters:
        detail = f" (resolved SolarWinds IP {router_ip})" if router_ip else ""
        raise LookupError(f"No SNA exporter found matching '{router_name}'{detail}")
    if len(exporters) > 1:
        return {
            "status": "ambiguous",
            "level": "exporter",
            "candidates": [
                {"device_id": e["device_id"], "exporter_ip": e["exporter_ip"], "exporter_name": e["exporter_name"]}
                for e in exporters
            ],
        }
    exporter = exporters[0]

    interfaces = find_interfaces(
        session, base_url, domain_id, exporter["device_id"], exporter["exporter_ip"], interface_name,
    )
    if not interfaces:
        # Name-matching between SolarWinds and SNA has been the recurring
        # failure here (decorated Captions, FQDNs, ifIndex fallbacks), so say
        # what SNA actually has rather than only what didn't match — the
        # difference is usually obvious on sight. One extra cheap GET, error
        # path only.
        available = [
            (i.get("name") or "").strip()
            for i in sna_client.list_interfaces(
                session, base_url, domain_id, exporter["device_id"], exporter["exporter_ip"],
            )
        ]
        available = [n for n in available if n]
        hint = ""
        if available:
            shown = ", ".join(available[:12])
            more = f" (+{len(available) - 12} more)" if len(available) > 12 else ""
            hint = f". SNA reports these interfaces on it: {shown}{more}"
        raise LookupError(
            f"No interface matching '{interface_name}' found on {exporter['exporter_name']}{hint}"
        )
    # SNA hands out a new internal interface ID whenever the exporter's SNMP
    # ifIndex for this name changes (a router reload/reconfig is enough) but
    # keeps the old ID's record around with its historical data — so the same
    # physical interface can show up as two "Tunnel5000" entries, one that
    # stopped getting flow data whenever the rotation happened and one that's
    # picked it up since. Confirmed against real production data: a fleet
    # router with a Tunnel5000 rotation showed exactly this split, one ID
    # covering the trailing month and the other covering the month before.
    # Text refinement can never resolve this — the two candidates' names are
    # byte-identical — so a true ambiguity (different names both loosely
    # matching the search term) still gets the candidate picker, but an
    # all-same-name split is treated as one logical interface and every ID's
    # traffic is pulled and merged, which also naturally covers a rotation
    # that lands inside the 7-day window instead of arbitrarily picking one
    # ID's data over the other's.
    distinct_names = {(i["interface_name"] or "").strip().lower() for i in interfaces}
    if len(interfaces) > 1 and len(distinct_names) > 1:
        return {
            "status": "ambiguous",
            "level": "interface",
            "candidates": interfaces,
            "exporter": exporter,
        }
    resolved_interface_name = interfaces[0]["interface_name"]

    from utils.sna_traffic import bucket_application_traffic

    def _pull(hours: int) -> dict:
        # Sequential, not fanned out to FANOUT_POOL: this already runs inside
        # a FANOUT_POOL worker (below), and that pool is bounded — submitting
        # more work to the same pool from inside it is the deadlock this
        # pool's own docstring warns about (utils/report_pool.py). At most
        # two interface IDs in practice, so a plain loop is cheap enough.
        records = []
        for iface in interfaces:
            records.extend(sna_client.get_interface_application_traffic(
                session, base_url, domain_id,
                exporter["device_id"], exporter["device_name"],
                exporter["exporter_ip"], exporter["exporter_name"],
                iface["interface_id"], iface["interface_name"],
                hours,
            ))
        return bucket_application_traffic(records, hours)

    # Same reasoning as utils.bandwidth_report.generate_bandwidth_report: the
    # 24h and 7d pulls are independent report POSTs against the same session,
    # so overlap them instead of running back-to-back. Shared FANOUT_POOL
    # (utils/report_pool.py) rather than a per-request pool.
    fut_24h = FANOUT_POOL.submit(_pull, 24)
    fut_7d = FANOUT_POOL.submit(_pull, 24 * 7)
    traffic_24h = fut_24h.result()
    traffic_7d = fut_7d.result()

    return {
        "status": "ok",
        "node_name": exporter["exporter_name"],
        "interface_name": resolved_interface_name,
        "traffic_24h": traffic_24h,
        "traffic_7d": traffic_7d,
    }
