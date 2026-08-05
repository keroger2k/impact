#!/usr/bin/env python3
"""scripts/sna_discover.py — Cisco Secure Network Analytics API discovery probe.

Read-only reconnaissance for wiring SNA (formerly Stealthwatch) into the
Bandwidth Utilization report's application-traffic stacked chart. We don't
yet know which API generation the target SMC runs, so this script:

  1. Logs in (POST /token/v2/authenticate) — tries a bare username first,
     then `SNA_DOMAIN\\username` if that 401s, same domain-prefix quirk
     SolarWinds has (see clients/solarwinds.py).
  2. GET /sw-reporting/v1/tenants — confirms the modern v2 API surface
     exists at all and gives us the tenant ID every v2 call needs.
  3. Probes the v2 tenant-scoped Flow Queries API (POST a query, poll it,
     GET the results) — this is what should replace the legacy
     `/smc/rest/flows` guesswork for per-application, per-time-bucket
     traffic. Prints the FULL raw response at every step, including 400
     validation bodies — those usually spell out the exact expected field
     names faster than any doc search would.
  4. Falls back to probing a handful of legacy `/smc/rest/...` paths only
     if the v2 surface isn't there.

Nothing here writes anything — every call is a GET or a flow *search* (SNA's
own read-only query mechanism). Run it against your real SNA server and
paste the output back; that's what nails down the real request/response
shape before any of this gets wired into the app.

Env vars (.env):
    SNA_BASE_URL        e.g. https://your-sna-host
    SNA_USERNAME        defaults to DOMAIN_USERNAME (SNA uses domain creds)
    SNA_PASSWORD        defaults to DOMAIN_PASSWORD
    SNA_DOMAIN          optional NTLM-style prefix, tried only if bare
                         username 401s (e.g. "network")
    SNA_DEVICE          a device/host IP or name to scope the flow query to
    SNA_HOURS           lookback window for the probe query (default 24)
    SNA_VERIFY_SSL      default false (self-signed certs)
    SNA_TIMEOUT         default 30

Usage:
    .venv/bin/python -m scripts.sna_discover
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv()


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "y")


def _print_header(title: str):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _print_response(resp: requests.Response, max_body: int = 2000):
    print(f"  → {resp.request.method} {resp.url}")
    print(f"  ← HTTP {resp.status_code}")
    try:
        body = json.dumps(resp.json(), indent=2)
    except ValueError:
        body = resp.text
    if len(body) > max_body:
        body = body[:max_body] + f"\n  … [truncated, {len(body)} chars total]"
    print(body)


def login(base_url: str, username: str, password: str, domain: str, verify_ssl: bool, timeout: int) -> requests.Session:
    _print_header("STEP 1 — Authenticate")

    def _attempt(user: str) -> tuple[requests.Session, requests.Response]:
        s = requests.Session()
        s.verify = verify_ssl
        r = s.post(
            f"{base_url}/token/v2/authenticate",
            data={"username": user, "password": password},
            timeout=timeout,
        )
        return s, r

    session, resp = _attempt(username)
    print(f"Trying bare username '{username}'...")
    _print_response(resp)

    if resp.status_code not in (200, 201, 204) or not session.cookies.get("stealthwatch.jwt"):
        if domain:
            domain_user = f"{domain}\\{username}"
            print(f"\nBare username failed — retrying as '{domain_user}'...")
            session, resp = _attempt(domain_user)
            _print_response(resp)

    if resp.status_code not in (200, 201, 204) or not session.cookies.get("stealthwatch.jwt"):
        print("\nAuthentication FAILED — nothing further will work. Check "
              "SNA_USERNAME/SNA_PASSWORD/SNA_DOMAIN and SNA_BASE_URL.")
        sys.exit(1)

    print("\nAuthentication OK — stealthwatch.jwt cookie present.")
    return session


def _headers(session: requests.Session, method: str = "GET") -> dict:
    headers = {"Accept": "application/json"}
    if method.upper() not in ("GET", "HEAD", "OPTIONS"):
        headers["Content-Type"] = "application/json"
        xsrf = session.cookies.get("XSRF-TOKEN")
        if xsrf:
            headers["X-XSRF-TOKEN"] = xsrf
    return headers


def list_tenants(session: requests.Session, base_url: str, timeout: int) -> list[dict]:
    _print_header("STEP 2 — List tenants (GET /sw-reporting/v1/tenants)")
    url = f"{base_url}/sw-reporting/v1/tenants"
    try:
        resp = session.get(url, headers=_headers(session), timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []
    _print_response(resp)
    if resp.status_code != 200:
        print("\nNo v1 tenants endpoint response — this SMC may not expose "
              "the modern v2 API surface, or the path differs on this version.")
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    tenants = data.get("data") if isinstance(data, dict) else data
    return tenants if isinstance(tenants, list) else []


def probe_v2_flow_query(session: requests.Session, base_url: str, tenant_id, device: str, hours: int, timeout: int):
    _print_header(f"STEP 3 — v2 Flow Queries API (tenant {tenant_id})")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    query_url = f"{base_url}/sw-reporting/v2/tenants/{tenant_id}/flows/queries"
    body = {
        "startDateTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endDateTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "recordLimit": 1000,
        "subject": {
            "ipAddresses": {"includes": [device]},
        },
    }
    print("POSTing a best-guess flow-query body — if this 400s, the error")
    print("body usually names the exact field it wanted instead:")
    print(json.dumps(body, indent=2))

    try:
        resp = session.post(query_url, headers=_headers(session, "POST"), json=body, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return
    _print_response(resp)

    if resp.status_code not in (200, 201, 202):
        print("\nv2 flow-query creation did not succeed. Adjust `body` above "
              "based on the error detail and re-run, or share this output back.")
        return

    try:
        data = resp.json()
    except ValueError:
        print("Response wasn't JSON — can't extract a query ID to poll.")
        return

    query_id = (
        data.get("data", {}).get("query", {}).get("id")
        if isinstance(data.get("data"), dict) else None
    ) or data.get("id")
    if not query_id:
        print("\nCouldn't find a query ID in the response body — check the "
              "shape above and adjust the extraction logic.")
        return

    print(f"\nQuery created: id={query_id}. Polling for completion...")
    status_url = f"{query_url}/{query_id}"
    for attempt in range(10):
        time.sleep(2)
        resp = session.get(status_url, headers=_headers(session), timeout=timeout)
        print(f"  poll {attempt + 1}: HTTP {resp.status_code}")
        try:
            status_data = resp.json()
        except ValueError:
            status_data = {}
        state = str(status_data).lower()
        if "complet" in state or "done" in state:
            print("  → looks complete, fetching results")
            break
    else:
        print("  gave up polling after 10 attempts — printing last status body:")

    _print_response(resp)

    results_url = f"{status_url}/results"
    print(f"\nFetching results: GET {results_url}")
    resp = session.get(results_url, headers=_headers(session), timeout=timeout)
    _print_response(resp, max_body=4000)


def probe_legacy_smc(session: requests.Session, base_url: str, device: str, hours: int, timeout: int):
    _print_header("STEP 4 (fallback) — legacy /smc/rest/flows probe")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    url = f"{base_url}/smc/rest/flows"

    for param in ("device", "host", "hostname", "router", "sensor", "exporter", "sourceDevice"):
        params = {"startTime": start_time.isoformat(), "endTime": end_time.isoformat(), param: device}
        print(f"\nTrying param '{param}'...")
        try:
            resp = session.get(url, headers=_headers(session), params=params, timeout=timeout)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            continue
        print(f"  HTTP {resp.status_code} — {resp.url}")
        if resp.status_code == 200:
            _print_response(resp, max_body=1000)
            return
    print("\nNo legacy param combination returned 200. This SMC likely "
          "doesn't expose /smc/rest/flows at all (modern SNA removed it).")


def main():
    base_url = os.getenv("SNA_BASE_URL", "").rstrip("/")
    username = os.getenv("SNA_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SNA_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    domain = os.getenv("SNA_DOMAIN", "")
    device = os.getenv("SNA_DEVICE", "")
    hours = int(os.getenv("SNA_HOURS", "24"))
    verify_ssl = _bool_env("SNA_VERIFY_SSL", False)
    timeout = int(os.getenv("SNA_TIMEOUT", "30"))

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not base_url or not username or not password:
        print("ERROR: SNA_BASE_URL and SNA_USERNAME/SNA_PASSWORD (or DOMAIN_USERNAME/"
              "DOMAIN_PASSWORD) must be set.")
        sys.exit(1)
    if not device:
        print("ERROR: SNA_DEVICE is required (a device IP or name to scope the probe query to).")
        sys.exit(1)

    session = login(base_url, username, password, domain, verify_ssl, timeout)
    tenants = list_tenants(session, base_url, timeout)

    if tenants:
        print(f"\nFound {len(tenants)} tenant(s):")
        for t in tenants:
            print(f"  {t}")
        tenant_id = tenants[0].get("id") if isinstance(tenants[0], dict) else tenants[0]
        probe_v2_flow_query(session, base_url, tenant_id, device, hours, timeout)
    else:
        probe_legacy_smc(session, base_url, device, hours, timeout)

    print()
    print("=" * 78)
    print("Done. Paste this whole output back so the real client can be built")
    print("against your SMC's actual API shape instead of guesses.")
    print("=" * 78)


if __name__ == "__main__":
    main()
