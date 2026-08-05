"""clients/sna.py — Cisco Secure Network Analytics (SNA / Stealthwatch) read client.

Confirmed against a live SMC via `scripts/sna_discover.py` (see that file's
docstring for the full trail): stateful cookie auth
(``POST /token/v2/authenticate``), a tenant discovered via
``GET /sw-reporting/v1/tenants`` — the ``application/json`` Accept variant
406s on this SMC, ``text/plain`` works and still returns a JSON body — then
the v2 tenant-scoped Flow Queries API: POST a query, poll it, GET the
results once done.

Flow search is a **slow, job-based scan over raw NetFlow** — confirmed empty
in under a minute for even a 24h window on the real box — never a single
blocking call. Callers must create → poll → fetch, same as SNA's own UI
does. No pagination field was observed in the results payload; ``record_limit``
is a hard cap and truncation must be surfaced to the caller, not hidden.

Read-only in effect: the only POST here creates a transient flow-search job
(exactly what running a search in the SMC UI does) — nothing here can modify
SMC configuration or security policy.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests

from clients import verify_ssl

TENANTS_PATH = "/sw-reporting/v1/tenants"


class SNAError(Exception):
    """Any SNA API failure — auth, query creation, status, or results."""


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


def create_flow_query(
    session: requests.Session, base_url: str, tenant_id: str,
    ip_address: str, hours: int, record_limit: int, timeout: int = 30,
) -> str:
    """Start a flow-search job scoped to one IP over the last `hours`. Returns the query id to poll."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    body = {
        "startDateTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endDateTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "recordLimit": record_limit,
        "subject": {"ipAddresses": {"includes": [ip_address]}},
    }
    url = f"{base_url}/sw-reporting/v2/tenants/{tenant_id}/flows/queries"
    resp = session.post(url, headers=_headers(session, "POST"), json=body, timeout=timeout)
    if resp.status_code not in (200, 201, 202):
        raise SNAError(f"Flow query creation failed: HTTP {resp.status_code}: {resp.text[:300]}")

    data = resp.json()
    query = data.get("data", {}).get("query", {}) if isinstance(data.get("data"), dict) else {}
    query_id = query.get("id")
    if not query_id:
        raise SNAError("Flow query response did not include a query id")
    return query_id


def get_query_status(session: requests.Session, base_url: str, tenant_id: str, query_id: str, timeout: int = 30) -> dict:
    url = f"{base_url}/sw-reporting/v2/tenants/{tenant_id}/flows/queries/{query_id}"
    resp = session.get(url, headers=_headers(session), timeout=timeout)
    if resp.status_code != 200:
        raise SNAError(f"Query status check failed: HTTP {resp.status_code}")
    data = resp.json()
    query = data.get("data", {}).get("query", {}) if isinstance(data.get("data"), dict) else {}
    return {
        "status": query.get("status", "UNKNOWN"),
        "percent_complete": query.get("percentComplete", 0),
    }


def get_query_results(session: requests.Session, base_url: str, tenant_id: str, query_id: str, timeout: int = 60) -> list[dict]:
    """Raw flow records. Caller compares len(result) to the record_limit it
    requested to detect truncation — no pagination mechanism is known."""
    url = f"{base_url}/sw-reporting/v2/tenants/{tenant_id}/flows/queries/{query_id}/results"
    resp = session.get(url, headers=_headers(session), timeout=timeout)
    if resp.status_code != 200:
        raise SNAError(f"Fetching query results failed: HTTP {resp.status_code}")
    data = resp.json()
    return data.get("data", {}).get("flows", []) if isinstance(data.get("data"), dict) else []
