"""utils/sna_report.py — resolve a router+interface name to SNA's IDs and pull application traffic.

SNA's Report Builder filter hierarchy is Flow Collector → Exporter →
Interface, keyed by opaque internal IDs — nothing here matches SolarWinds'
IDs, so this does its own name-based resolution against SNA's own device
list. See clients/sna.py's module docstring for how that hierarchy maps to
real infrastructure (Exporter = router, not "Device").
"""
from __future__ import annotations

import clients.sna as sna_client

VALID_HOURS = (24, 24 * 7)


def find_exporters(session, base_url: str, domain_id: str, router_name: str) -> list[dict]:
    """Search every Flow Collector's exporter list for a case-insensitive
    substring match on `router_name`. Returns candidates:
    [{"device_id", "device_name", "exporter_ip", "exporter_name"}]."""
    needle = router_name.strip().lower()
    matches = []
    for device in sna_client.list_flow_collectors(session, base_url, domain_id):
        device_id = device.get("id")
        device_name = device.get("name") or ""
        for exp in sna_client.list_exporters(session, base_url, domain_id, device_id):
            exp_name = exp.get("name") or ""
            if needle in exp_name.lower():
                matches.append({
                    "device_id": device_id,
                    "device_name": device_name,
                    "exporter_ip": exp.get("id"),
                    "exporter_name": exp_name,
                })
    return matches


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

    Raises sna_client.SNAError on auth/API failure, LookupError if nothing matches.
    """
    if hours not in VALID_HOURS:
        raise ValueError(f"hours must be one of {VALID_HOURS}")

    session = sna_client.login(base_url, username, password, domain)
    domain_id = sna_client.get_tenant_id(session, base_url)

    exporters = find_exporters(session, base_url, domain_id, router_name)
    if not exporters:
        raise LookupError(f"No SNA exporter found matching '{router_name}'")
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
    bucketed = bucket_application_traffic(records)

    return {
        "status": "ok",
        "node_name": exporter["exporter_name"],
        "interface_name": interface["interface_name"],
        **bucketed,
    }
