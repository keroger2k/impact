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
from utils.bandwidth_report import find_node_ip

VALID_HOURS = (24, 24 * 7)


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


def find_interfaces(
    session, base_url: str, domain_id: str, device_id, exporter_ip: str, interface_name: str,
) -> list[dict]:
    """Exact (case-insensitive) match first, falling back to substring.
    Returns candidates: [{"interface_id", "interface_name"}]."""
    needle = interface_name.strip().lower()
    interfaces = sna_client.list_interfaces(session, base_url, domain_id, device_id, exporter_ip)

    exact = [i for i in interfaces if (i.get("name") or "").strip().lower() == needle]
    if exact:
        pool = exact
    else:
        pool = [i for i in interfaces if needle in (i.get("name") or "").lower()]

    return [{"interface_id": i.get("id"), "interface_name": i.get("name")} for i in pool]


def generate_application_traffic_report(
    base_url: str,
    domain: str,
    username: str,
    password: str,
    router_name: str,
    interface_name: str,
    hours: int,
) -> dict:
    """Resolve router+interface against SNA, then pull the application-traffic report.

    Returns one of:
      {"status": "ambiguous", "level": "exporter"|"interface", "candidates": [...]}
      {"status": "ok", "node_name", "interface_name", "buckets", "applications", "series"}

    Raises sna_client.SNAError on auth/API failure, LookupError if nothing
    matches, InvalidNameError if router_name fails the SolarWinds charset
    check, or whatever clients.solarwinds.query raises on a SolarWinds
    failure (that lookup is load-bearing here, not best-effort — swallowing
    it would surface a misleading "no exporter found" instead of the real
    cause).
    """
    if hours not in VALID_HOURS:
        raise ValueError(f"hours must be one of {VALID_HOURS}")

    router_ip = find_node_ip(router_name, username, password)

    session = sna_client.login(base_url, username, password, domain)
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
        raise LookupError(f"No interface matching '{interface_name}' found on {exporter['exporter_name']}")
    if len(interfaces) > 1:
        return {
            "status": "ambiguous",
            "level": "interface",
            "candidates": interfaces,
            "exporter": exporter,
        }
    interface = interfaces[0]

    from utils.sna_traffic import bucket_application_traffic

    records = sna_client.get_interface_application_traffic(
        session, base_url, domain_id,
        exporter["device_id"], exporter["device_name"],
        exporter["exporter_ip"], exporter["exporter_name"],
        interface["interface_id"], interface["interface_name"],
        hours,
    )
    bucketed = bucket_application_traffic(records, hours)

    return {
        "status": "ok",
        "node_name": exporter["exporter_name"],
        "interface_name": interface["interface_name"],
        **bucketed,
    }
