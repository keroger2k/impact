#!/usr/bin/env python3
"""scripts/sna_discover_dscp.py — probe SNA for a DSCP-marked traffic breakdown.

Read-only reconnaissance for a question raised while designing
scripts/wan_qos_report.py: that script gets per-QoS-class queue stats
(queue depth, drops, offered rate) by SSHing to the border router and
parsing `show policy-map interface ... output`. SolarWinds/DNAC/SNA were
considered as alternatives — DNAC's QoS API is confirmed configuration-only
(no live counters), and SNA is fundamentally NetFlow/IPFIX-based, so it
structurally cannot see drops or queue depth at all: flow export only
describes packets that were actually forwarded, and queue occupancy is
router-local QoS state that's never exported as flow data. No discovery
changes that; it's how NetFlow works, not a config gap.

The one adjacent thing SNA *could* still offer is DSCP-marked traffic
*volume* — how many bytes/packets on an interface are marked EF/AF31/etc,
since ToS/DSCP is a standard flow field. That doesn't answer "is this
circuit dropping voice traffic" the way the SSH report does, but it's a
real, checkable signal rather than something to rule out from reasoning
alone. This script checks it against a real SMC.

What it does, in order:
  1. Reuses the *already-proven* resolution chain — clients.sna.login() /
     get_tenant_id() and utils.sna_report.find_exporters() /
     find_interfaces() — to resolve --router/--interface to a real
     Device/Exporter/Interface ID triple, the same one
     utils/sna_report.py's production Application Traffic chart resolves.
     Nothing here is under test; it's just how we get a real, known-good
     interface ID to probe with instead of guessing one.
  2. Probes for a Report Builder report *catalog* (GET .../reports,
     GET .../reports/interface-application-traffic) to see whether report
     names are enumerable at all, rather than guessed.
  3. POSTs a short list of plausible DSCP/QoS report-name candidates to
     .../reports/<candidate>, using the exact body shape
     clients.sna.get_interface_application_traffic() already sends
     (Device/Exporter/Interface filter params) — a 404 vs. a 400 with a
     validation detail vs. a 200 all say something different, same
     principle the SolarWinds discovery scripts use for SWQL errors.
  4. Falls back to a raw v2 Flow Queries probe (same mechanism as
     scripts/sna_discover.py's probe_v2_flow_query) scoped to the
     Exporter's IP, purely to check whether a DSCP/ToS-like field exists
     anywhere in SNA's flow record schema. This is explicitly
     HOST-scoped, not interface-scoped — clients/sna.py's own module
     docstring notes a host-IP flow query only shows that device's own
     management-plane traffic (SNMP/syslog/SSH/NetFlow-export), not
     transit traffic. A field showing up here confirms it exists in SNA's
     schema, not that it's usable for the interface's real traffic mix —
     steps 2-3 are what would actually answer that.

For steps 2-4, this deliberately bypasses clients/sna.py's helpers and
posts/gets with raw `requests` instead — same reason
scripts/solarwinds_discover_site_properties.py bypasses
clients.solarwinds.query(): that wrapper only keeps a short error-body
excerpt, and this needs the FULL body on every call (success or failure)
to read real report/field names directly rather than guess twice.

Nothing here writes anything. Every call is a GET, or a report/flow-search
POST (SNA's own read-only query mechanisms, same as running a report in
the SMC UI) — no config or policy is ever touched.

Env vars (.env) — same convention as scripts/sna_discover.py:
    SNA_BASE_URL        e.g. https://your-sna-host
    SNA_USERNAME        defaults to DOMAIN_USERNAME (SNA uses domain creds)
    SNA_PASSWORD        defaults to DOMAIN_PASSWORD
    SNA_DOMAIN          optional NTLM-style prefix, tried only if bare
                         username 401s (e.g. "network")
    SNA_TIMEOUT         default 30
    SNA_VERIFY_SSL      default false (self-signed certs)

Usage:
    .venv/bin/python -m scripts.sna_discover_dscp --router RTR-DCA-01 --interface Tunnel5000
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.sna as sna_client  # noqa: E402
from utils.sna_report import find_exporters, find_interfaces  # noqa: E402

REPORT_BUILDER = "/report-builder/api/v1"

# Plausible names for a DSCP/QoS-marked-traffic report, tried against
# POST {base}/report-builder/api/v1/reports/<candidate> with the same
# Device/Exporter/Interface filter shape the known-good
# interface-application-traffic report uses. Not guaranteed to exist —
# that's exactly what this step is checking.
DSCP_REPORT_CANDIDATES = [
    "interface-dscp-traffic",
    "interface-traffic-by-dscp",
    "interface-qos-traffic",
    "interface-cos-traffic",
    "interface-tos-traffic",
    "interface-application-traffic-by-dscp",
]


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "y")


def _print_header(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _print_response(resp: requests.Response, max_body: int = 3000) -> None:
    print(f"  → {resp.request.method} {resp.url}")
    if resp.request.body:
        try:
            body_preview = json.dumps(json.loads(resp.request.body), indent=2)
        except (ValueError, TypeError):
            body_preview = str(resp.request.body)
        print(f"  → body: {body_preview}")
    print(f"  ← HTTP {resp.status_code}")
    try:
        body = json.dumps(resp.json(), indent=2)
    except ValueError:
        body = resp.text
    if len(body) > max_body:
        body = body[:max_body] + f"\n  … [truncated, {len(body)} chars total]"
    print(body)


def _headers(session: requests.Session, method: str = "GET") -> dict:
    headers = {"Accept": "application/json"}
    if method.upper() not in ("GET", "HEAD", "OPTIONS"):
        headers["Content-Type"] = "application/json"
        xsrf = session.cookies.get("XSRF-TOKEN")
        if xsrf:
            headers["X-XSRF-TOKEN"] = xsrf
    return headers


def resolve_target(
    session: requests.Session, base_url: str, router: str, interface: str, timeout: int,
) -> dict:
    """STEP 1 — resolve --router/--interface to real SNA IDs using the same,
    already-proven chain utils/sna_report.py uses for the production
    Application Traffic chart. Not under test; just gets us a real
    interface ID to probe with instead of guessing one."""
    _print_header("STEP 1 — Resolve router/interface to SNA IDs")

    domain_id = sna_client.get_tenant_id(session, base_url, timeout)
    print(f"Tenant/domain ID: {domain_id}")

    exporters = find_exporters(session, base_url, domain_id, router)
    if not exporters:
        print(f"\nNo SNA exporter found matching '{router}'. Nothing further to probe.")
        sys.exit(1)
    if len(exporters) > 1:
        print(f"\nMultiple exporters matched '{router}' — pick one and re-run with a more specific --router:")
        for e in exporters:
            print(f"  {e}")
        sys.exit(1)
    exporter = exporters[0]
    print(f"Exporter: {exporter}")

    interfaces = find_interfaces(
        session, base_url, domain_id, exporter["device_id"], exporter["exporter_ip"], interface,
    )
    if not interfaces:
        print(f"\nNo interface matching '{interface}' found on {exporter['exporter_name']}. Nothing further to probe.")
        sys.exit(1)
    if len(interfaces) > 1:
        distinct = {(i["interface_name"] or "").strip().lower() for i in interfaces}
        if len(distinct) > 1:
            print(f"\nMultiple distinct interfaces matched '{interface}' — pick one and re-run with a more specific name:")
            for i in interfaces:
                print(f"  {i}")
            sys.exit(1)
        # Same-name split (SNA ID rotation) — utils/sna_report.py merges these
        # for a real report; for a probe, the first ID is enough to confirm
        # whether a report shape exists at all.
        print(f"\n{len(interfaces)} interface IDs share the name '{interface}' (SNA ID rotation) — using the first: {interfaces[0]}")
    interface_obj = interfaces[0]
    print(f"Interface: {interface_obj}")

    return {
        "domain_id": domain_id,
        "device_id": exporter["device_id"],
        "device_name": exporter["device_name"],
        "exporter_ip": exporter["exporter_ip"],
        "exporter_name": exporter["exporter_name"],
        "interface_id": interface_obj["interface_id"],
        "interface_name": interface_obj["interface_name"],
    }


def probe_report_catalog(session: requests.Session, base_url: str, timeout: int) -> None:
    """STEP 2 — is there an enumerable list of Report Builder report names?
    Best case: this hands back real names instead of needing step 3's
    guesses."""
    _print_header("STEP 2 — Probe for a Report Builder report catalog")

    for path in (f"{REPORT_BUILDER}/reports", REPORT_BUILDER):
        url = f"{base_url}{path}"
        print(f"\nGET {url}")
        try:
            resp = session.get(url, headers=_headers(session), timeout=timeout)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            continue
        _print_response(resp)


def probe_dscp_report_candidates(
    session: requests.Session, base_url: str, target: dict, timeout: int,
) -> None:
    """STEP 3 — try each candidate DSCP/QoS report name with the same body
    shape the known-good interface-application-traffic report uses.
    A 404 vs. a 400-with-detail vs. a 200 all say something different."""
    _print_header("STEP 3 — Try candidate DSCP/QoS report names")

    body = {
        "filter": {
            "domainId": int(target["domain_id"]) if str(target["domain_id"]).isdigit() else target["domain_id"],
            "startTime": 0,
            "endTime": 0,
            "duration": 24 * 3600 * 1000,
            "dayCount": 0,
            "params": [
                {"category": "Device", "id": target["device_id"], "name": target["device_name"]},
                {"category": "Exporter", "id": target["exporter_ip"], "parentId": target["device_id"], "name": target["exporter_name"]},
                {"category": "Interface", "id": target["interface_id"], "parentId": target["exporter_ip"], "name": target["interface_name"]},
            ],
        },
        "filterConfig": {"logic": "and", "filters": []},
    }

    for candidate in DSCP_REPORT_CANDIDATES:
        url = f"{base_url}{REPORT_BUILDER}/reports/{candidate}"
        print(f"\nPOST {url}")
        try:
            resp = session.post(url, headers=_headers(session, "POST"), json=body, timeout=timeout)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            continue
        _print_response(resp)
        if resp.status_code == 200:
            print(f"\n  *** '{candidate}' returned HTTP 200 — inspect the body above for DSCP-shaped fields. ***")


def probe_raw_flow_dscp_field(
    session: requests.Session, base_url: str, target: dict, timeout: int, hours: int = 24,
) -> None:
    """STEP 4 (fallback/cross-check) — does a DSCP/ToS-like field exist
    anywhere in SNA's raw flow record schema at all? HOST-scoped (the
    Exporter's own IP), not interface-scoped — see module docstring. Same
    query mechanism as scripts/sna_discover.py's probe_v2_flow_query."""
    _print_header("STEP 4 (fallback) — raw flow record field inspection (HOST-scoped, not interface-scoped)")
    print("Note: this queries flows sourced/destined at the router's own IP, which")
    print("clients/sna.py's module docstring notes only surfaces that device's own")
    print("management-plane traffic (SNMP/syslog/SSH/NetFlow-export) — NOT transit")
    print("traffic through the interface. This step only checks whether a DSCP/ToS")
    print("field exists in SNA's flow schema at all; it does not confirm the field")
    print("is meaningful for the interface's real traffic mix (steps 2-3 do that).")

    domain_id = target["domain_id"]
    device_ip = target["exporter_ip"]
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    query_url = f"{base_url}/sw-reporting/v2/tenants/{domain_id}/flows/queries"
    body = {
        "startDateTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endDateTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "recordLimit": 200,
        "subject": {"ipAddresses": {"includes": [device_ip]}},
    }
    print(f"\nPOST {query_url}")
    print(json.dumps(body, indent=2))
    try:
        resp = session.post(query_url, headers=_headers(session, "POST"), json=body, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return
    _print_response(resp)

    if resp.status_code not in (200, 201, 202):
        print("\nFlow-query creation did not succeed — skipping poll/results.")
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
        print("\nCouldn't find a query ID in the response body.")
        return

    import time
    print(f"\nQuery created: id={query_id}. Polling for completion...")
    status_url = f"{query_url}/{query_id}"
    for attempt in range(15):
        time.sleep(2)
        resp = session.get(status_url, headers=_headers(session), timeout=timeout)
        try:
            status_data = resp.json()
        except ValueError:
            status_data = {}
        query_info = status_data.get("data", {}).get("query", {}) if isinstance(status_data.get("data"), dict) else {}
        status = query_info.get("status", "")
        pct = query_info.get("percentComplete", 0)
        print(f"  poll {attempt + 1}: HTTP {resp.status_code} status={status!r} percentComplete={pct}")
        if status and status.upper() not in ("IN_PROGRESS", "PENDING", "RUNNING", "QUEUED"):
            break
        if isinstance(pct, (int, float)) and pct >= 100:
            break
    else:
        print("  gave up polling after 15 attempts (30s) — fetching results anyway.")

    results_url = f"{status_url}/results"
    print(f"\nFetching results: GET {results_url}")
    resp = session.get(results_url, headers=_headers(session), timeout=timeout)
    print(f"  ← HTTP {resp.status_code}")
    try:
        results_data = resp.json()
    except ValueError:
        print("Non-JSON response:")
        print(resp.text[:2000])
        return

    outer = results_data.get("data", {}) if isinstance(results_data, dict) else {}
    flows = outer.get("flows", [])
    print(f"flows returned: {len(flows)}")

    if not flows:
        print("\nNo flows returned — can't inspect field names from an empty result.")
        return

    sample = flows[0]
    dscp_like_keys = [
        k for k in _flatten_keys(sample)
        if any(token in k.lower() for token in ("dscp", "tos", "diffserv", "cos", "qos"))
    ]
    print(f"\nKeys in the first flow record that look DSCP/QoS-related: {dscp_like_keys or '(none found)'}")
    print("\nFull first flow record (for field-name reference):")
    print(json.dumps(sample, indent=2))


def _flatten_keys(obj, prefix: str = "") -> list[str]:
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.append(full)
            keys.extend(_flatten_keys(v, full))
    return keys


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="Read-only probe: can SNA supply a DSCP-marked traffic breakdown for a WAN interface?",
    )
    ap.add_argument("--router", required=True, help="Router name (resolved the same way the Bandwidth report does)")
    ap.add_argument("--interface", required=True, help="Interface name, e.g. Tunnel5000")
    args = ap.parse_args()

    base_url = os.getenv("SNA_BASE_URL", "").rstrip("/")
    username = os.getenv("SNA_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SNA_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    domain = os.getenv("SNA_DOMAIN", "")
    verify_ssl = _bool_env("SNA_VERIFY_SSL", False)
    timeout = int(os.getenv("SNA_TIMEOUT", "30"))

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not base_url or not username or not password:
        print("ERROR: SNA_BASE_URL and SNA_USERNAME/SNA_PASSWORD (or DOMAIN_USERNAME/"
              "DOMAIN_PASSWORD) must be set.")
        return 1

    session = sna_client.login(base_url, username, password, domain, timeout)
    try:
        target = resolve_target(session, base_url, args.router, args.interface, timeout)
        probe_report_catalog(session, base_url, timeout)
        probe_dscp_report_candidates(session, base_url, target, timeout)
        probe_raw_flow_dscp_field(session, base_url, target, timeout)
    finally:
        sna_client.logout(session, base_url)

    print()
    print("=" * 78)
    print("Done. Review the output above:")
    print("  - Did any candidate in STEP 3 return HTTP 200 with DSCP-shaped data?")
    print("  - Did STEP 2's catalog probe reveal real report names to try instead?")
    print("  - Did STEP 4 find a dscp/tos-like field in the raw flow schema at all?")
    print("Paste this whole output back to decide whether pursuing this further is worthwhile.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
