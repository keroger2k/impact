"""clients/sna.py — Cisco Secure Network Analytics (SNA / Stealthwatch) read client.

Auth + tenant discovery confirmed against a live SMC via
`scripts/sna_discover.py` (see that file's docstring): stateful cookie auth
(``POST /token/v2/authenticate``), a tenant discovered via
``GET /sw-reporting/v1/tenants`` — the ``application/json`` Accept variant
406s on this SMC, ``text/plain`` works and still returns a JSON body.

The application-traffic data itself comes from the **Report Builder** API
(``/report-builder/api/v1/...``), reverse-engineered from the SMC UI's own
"Interface Application Traffic" report — captured via browser dev tools, not
guessed. This is a different, better-fitting API than SNA's raw flow-search:
it's synchronous (no job/poll cycle), returns clean per-hour bps values
directly, and — critically — it's scoped by **interface** rather than by a
host IP. A host-centric query (an earlier approach here) only ever surfaces
a device's own management-plane sessions (SNMP/syslog/SSH/NetFlow-export)
because a router doesn't originate the traffic that transits it; querying by
*interface* is what actually captures WAN/tunnel traffic.

Report Builder's own filter hierarchy is Flow Collector → Exporter →
Interface, not Router → Interface as you might expect:
  - "Device" in this API means the **Flow Collector appliance** (there may
    be only one, as in this environment — `list_flow_collectors` returns
    whatever exists).
  - Individual routers appear as **Exporters** underneath a Flow Collector,
    identified by hostname + IP (`list_exporters`).
  - **Interfaces** hang off an Exporter, with friendly names when SNA has
    learned them (e.g. "Tunnel5000") or "ifIndex-N" as a fallback
    (`list_interfaces`).

Read-only: everything here is a GET except the final report POST, which (like
the old flow-search job) only runs a report query — it doesn't touch SMC
config or policy.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests

from clients import verify_ssl

TENANTS_PATH = "/sw-reporting/v1/tenants"
REPORT_BUILDER = "/report-builder/api/v1"


class SNAError(Exception):
    """Any SNA API failure — auth, lookup, or report fetch."""


def login(base_url: str, username: str, password: str, domain: str, timeout: int = 30) -> requests.Session:
    """Authenticate and return a session carrying the stealthwatch.jwt cookie.

    Tries a bare username first, then `domain\\username` if that's rejected
    (the same fallback SolarWinds needed — see clients/solarwinds.py).
    """
    session = requests.Session()
    session.verify = verify_ssl()

    def _attempt(user: str) -> requests.Response:
        return session.post(
            f"{base_url}/token/v2/authenticate",
            data={"username": user, "password": password},
            timeout=timeout,
        )

    resp = _attempt(username)
    if (resp.status_code not in (200, 201, 204) or not session.cookies.get("stealthwatch.jwt")) and domain:
        resp = _attempt(f"{domain}\\{username}")

    if resp.status_code not in (200, 201, 204) or not session.cookies.get("stealthwatch.jwt"):
        raise SNAError("SNA authentication failed")
    return session


def _headers(session: requests.Session, method: str = "GET") -> dict:
    headers = {"Accept": "application/json"}
    if method.upper() not in ("GET", "HEAD", "OPTIONS"):
        headers["Content-Type"] = "application/json"
        xsrf = session.cookies.get("XSRF-TOKEN")
        if xsrf:
            headers["X-XSRF-TOKEN"] = xsrf
    return headers


def get_tenant_id(session: requests.Session, base_url: str, timeout: int = 30) -> str:
    for accept in ("text/plain", "application/json"):
        resp = session.get(f"{base_url}{TENANTS_PATH}", headers={"Accept": accept}, timeout=timeout)
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        tenants = data.get("data") if isinstance(data, dict) else data
        if isinstance(tenants, list) and tenants:
            first = tenants[0]
            return str(first.get("id") if isinstance(first, dict) else first)
    raise SNAError("Could not resolve an SNA tenant ID")


def _get_json(session: requests.Session, url: str, timeout: int) -> list[dict]:
    resp = session.get(url, headers=_headers(session), timeout=timeout)
    if resp.status_code != 200:
        raise SNAError(f"GET {url} failed: HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        raise SNAError(f"GET {url} returned non-JSON")
    return data if isinstance(data, list) else []


def list_flow_collectors(session: requests.Session, base_url: str, domain_id: str, timeout: int = 30) -> list[dict]:
    """Report Builder's "Device" filter — the Flow Collector appliance(s), not routers."""
    return _get_json(session, f"{base_url}{REPORT_BUILDER}/devices/{domain_id}/list", timeout)


def list_exporters(session: requests.Session, base_url: str, domain_id: str, device_id, timeout: int = 30) -> list[dict]:
    """Exporters (routers) reporting to a given Flow Collector device."""
    return _get_json(session, f"{base_url}{REPORT_BUILDER}/exporters/{domain_id}/swas/{device_id}", timeout)


def list_interfaces(
    session: requests.Session, base_url: str, domain_id: str, device_id, exporter_ip: str, timeout: int = 30,
) -> list[dict]:
    """Interfaces on a given Exporter."""
    return _get_json(
        session,
        f"{base_url}{REPORT_BUILDER}/interfaces/{domain_id}/swas/{device_id}/exporters/{exporter_ip}",
        timeout,
    )


def get_interface_application_traffic(
    session: requests.Session,
    base_url: str,
    domain_id: str,
    device_id,
    device_name: str,
    exporter_ip: str,
    exporter_name: str,
    interface_id,
    interface_name: str,
    hours: int,
    timeout: int = 60,
) -> list[dict]:
    """Per-application traffic (bps) for one interface, at native hourly granularity.

    Returns a flat list of {applicationName, time (ISO8601 UTC),
    trafficInboundBps, trafficOutboundBps} — one row per (application, hour).
    """
    duration_ms = int(hours * 3600 * 1000)
    body = {
        "filter": {
            "domainId": int(domain_id) if str(domain_id).isdigit() else domain_id,
            "startTime": 0,
            "endTime": 0,
            "duration": duration_ms,
            "dayCount": 0,
            "params": [
                {"category": "Device", "id": device_id, "name": device_name},
                {"category": "Exporter", "id": exporter_ip, "parentId": device_id, "name": exporter_name},
                {"category": "Interface", "id": interface_id, "parentId": exporter_ip, "name": interface_name},
            ],
        },
        "filterConfig": {"logic": "and", "filters": []},
    }
    url = f"{base_url}{REPORT_BUILDER}/reports/interface-application-traffic"
    resp = session.post(url, headers=_headers(session, "POST"), json=body, timeout=timeout)
    if resp.status_code != 200:
        raise SNAError(f"Interface application traffic report failed: HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        data = resp.json()
    except ValueError:
        raise SNAError("Interface application traffic report returned non-JSON")
    return data if isinstance(data, list) else []
