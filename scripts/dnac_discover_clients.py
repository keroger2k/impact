#!/usr/bin/env python3
"""scripts/dnac_discover_clients.py — does Catalyst Center already hold the
whole answer in one record?

Read-only reconnaissance for the cross-platform endpoint search
(docs/ROADMAP.md item #1, with items #2 and #3 — health scores and clients —
as the DNAC-side prerequisites). Today `clients/dnac.py` touches exactly one
piece of the Assurance surface, `get_recent_issues()`. Everything else the
app does with DNAC is inventory, config and IP lookup.

That matters because a single Assurance client record is, on paper, the entire
feature in one call: connected switch name, the physical port, VLAN, SSID and
AP for wireless, the site hierarchy, the host name, the client's IP and MAC,
a health score — and `userId`, the identity that authenticated. If that field
is populated, DNAC alone answers "which port is this person on", with no ISE
join, no AD lookup, and no new client-layer code beyond the call itself.

Four surfaces are probed, cheapest question first:

  1. `/dna/intent/api/v1/client-health` — is Assurance returning anything at
     all? A rollup with counts is the fastest yes/no.
  2. `/dna/data/api/v1/clients` — the newer data API. Richer and filterable,
     but version-dependent; a 404 here is informative rather than a failure.
  3. `/dna/intent/api/v1/client-detail` — the per-client record, by MAC.
     This is where connectedDevice / port / userId live.
  4. `/dna/intent/api/v1/user-enrichment-details` — the one endpoint in the
     estate that takes a USER identity as its input rather than a MAC or an
     IP. It is header-driven (`entity_type: network_user_id`), which is why
     it is easy to miss reading the SDK. If it works, the email → AD →
     username chain lands directly here.

⚠️  THE FAILURE MODE TO WATCH FOR, inherited verbatim from the earlier
    scripts/dnac_discover_assurance.py probe (removed; in git history): all of
    this depends on Assurance licensing *and* telemetry actually being
    configured. An instance without it returns a well-formed EMPTY response —
    HTTP 200, correct shape, no rows — which is indistinguishable from "no
    problems" unless you are looking for the distinction. Every empty result
    below is called out explicitly as ambiguous rather than reported as a
    clean negative.

Requests go through `dnac.custom_caller.call_api` with `original_response=True`
and `raise_exception=False`, so the HTTP status and body survive to the
terminal. Several of these endpoints have no typed SDK binding at all, and
`clients/dnac.py` already reaches for custom_caller for that same reason
(`get_recent_issues`, `get_interface_by_ip`).

Every call is a GET.

⚠️  OUTPUT CONTAINS REAL USERNAMES, HOSTNAMES, MAC AND IP ADDRESSES. Pass
    --redact before pasting it anywhere.

Env vars (.env): DNA_CENTER_BASE_URL, DNA_CENTER_VERSION, DOMAIN_USERNAME,
DOMAIN_PASSWORD.

Usage:
    .venv/bin/python -m scripts.dnac_discover_clients
    .venv/bin/python -m scripts.dnac_discover_clients --mac 00:11:22:33:44:55
    .venv/bin/python -m scripts.dnac_discover_clients --user jsmith --redact
    .venv/bin/python -m scripts.dnac_discover_clients --mac 00:11:22:33:44:55 --full
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.dnac as dc  # noqa: E402

# The fields that would make this feature a one-call affair.
_PAYOFF_FIELDS = [
    "userId", "id", "hostMac", "hostName", "hostType", "hostIpV4",
    "connectedDevice", "clientConnection", "port", "vlanId", "vnid",
    "ssid", "location", "siteId", "siteHierarchy", "healthScore",
    "connectionStatus", "lastUpdated", "deviceName", "apName", "frequency",
]

_SENSITIVE = re.compile(r"(mac|ip|user|host|name|ssid|serial)", re.I)


def _mask(val) -> str:
    s = str(val)
    if not s or s in ("None", "-"):
        return s
    if s.count(".") == 3 and all(p.isdigit() for p in s.split(".")):
        p = s.split(".")
        return f"{p[0]}.{p[1]}.x.x"
    raw = s.replace(":", "").replace("-", "")
    if len(raw) == 12 and all(c in "0123456789abcdefABCDEF" for c in raw):
        return f"{raw[:6]}-XXXXXX"
    return f"{s[:3]}***{s[-2:]}" if len(s) > 6 else "***"


class Redactor:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def cell(self, key: str, val):
        if self.enabled and _SENSITIVE.search(key or "") and not isinstance(val, (dict, list)):
            return _mask(val)
        return val

    def plain(self, val) -> str:
        return _mask(val) if self.enabled else str(val)


def _hr(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _call(dnac, path: str, params: dict | None = None,
          headers: dict | None = None) -> tuple[object | None, str | None]:
    """One GET. Returns (payload, error_text) with the status and body intact."""
    kwargs: dict = {"original_response": True, "raise_exception": False}
    if params:
        kwargs["params"] = params
    if headers:
        kwargs["headers"] = headers
    try:
        resp = dnac.custom_caller.call_api("GET", path, **kwargs)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

    status = getattr(resp, "status_code", None)
    if status is None:                       # SDK returned a parsed object
        return getattr(resp, "response", resp), None
    if status >= 400:
        body = (getattr(resp, "text", "") or "")[:600]
        hint = ""
        if status == 404:
            hint = "\n       → 404: this Catalyst Center version has no such endpoint."
        elif status == 403:
            hint = "\n       → 403: usually means Assurance is not licensed."
        elif status == 400:
            hint = "\n       → 400: a parameter this version rejects; the body normally names it."
        return None, f"HTTP {status} — {body}{hint}"
    try:
        data = resp.json()
    except Exception:
        return None, f"HTTP {status} with an unparseable body: {(resp.text or '')[:300]}"
    return data.get("response", data) if isinstance(data, dict) else data, None


def _rows(payload) -> list:
    if payload is None:
        return []
    if isinstance(payload, dict):
        for key in ("response", "clients", "items"):
            if key in payload and isinstance(payload[key], list):
                return payload[key]
        return [payload]
    return payload if isinstance(payload, list) else []


def _empty_warning() -> None:
    print("     EMPTY RESPONSE — the endpoint exists and answered, but returned no")
    print("     rows. That is what an unlicensed or un-telemetried Assurance install")
    print("     looks like, and it is NOT the same as 'no clients'. Check Assurance")
    print("     licensing and whether the site's devices export telemetry before")
    print("     reading anything into it.")


def step_client_health(dnac, red: Redactor, hours: int) -> bool:
    _hr("STEP 1  —  IS ASSURANCE ALIVE?  GET /dna/intent/api/v1/client-health")
    ts = int(time.time() * 1000)
    payload, err = _call(dnac, "/dna/intent/api/v1/client-health", {"timestamp": ts})
    if err:
        print(f"  FAILED — {err}")
        return False
    rows = _rows(payload)
    if not rows:
        _empty_warning()
        return False
    print(f"  {len(rows)} health rollup row(s).")
    blob = json.dumps(rows[0], default=str)
    total = sum(int(m.group(1)) for m in re.finditer(r'"clientCount"\s*:\s*(\d+)', blob))
    if total:
        print(f"  clientCount total in the first rollup: {total}")
    print(f"\n  first row (truncated):\n{json.dumps(rows[0], indent=2, default=str)[:900]}")
    print("\n  → Assurance is answering. Whether it knows about YOUR clients is step 2.")
    return True


def step_data_clients(dnac, red: Redactor, hours: int, full: bool) -> list:
    _hr("STEP 2  —  NEWER DATA API  GET /dna/data/api/v1/clients")
    end = int(time.time() * 1000)
    params = {"limit": 5, "startTime": end - hours * 3600 * 1000, "endTime": end}
    payload, err = _call(dnac, "/dna/data/api/v1/clients", params)
    if err:
        print(f"  FAILED — {err}")
        print("  Not fatal: this surface only exists on recent versions. Step 3 uses")
        print("  the older intent API, which is present much further back.")
        return []
    rows = _rows(payload)
    if not rows:
        _empty_warning()
        return []
    print(f"  {len(rows)} client row(s).")
    keys = sorted(rows[0].keys()) if isinstance(rows[0], dict) else []
    print(f"\n  keys on a client record ({len(keys)}):")
    for i in range(0, len(keys), 3):
        print("    " + "".join(f"{k:<30}" for k in keys[i:i + 3]))
    _report_payoff(rows[0], red)
    if full:
        print(f"\n  full first record:\n{json.dumps(rows[0], indent=2, default=str)[:2500]}")
    return rows


def _report_payoff(record: dict, red: Redactor) -> None:
    if not isinstance(record, dict):
        return
    print("\n  FIELDS THAT WOULD MAKE THIS A ONE-CALL FEATURE")
    print("  " + "-" * 60)
    found_user = False
    for key in _PAYOFF_FIELDS:
        actual = next((k for k in record if k.lower() == key.lower()), None)
        if actual is None:
            continue
        val = record[actual]
        if val in (None, "", [], {}):
            print(f"     {actual:<24} (present but empty)")
            continue
        if key.lower() == "userid":
            found_user = True
        shown = red.cell(actual, val)
        if isinstance(shown, (dict, list)):
            shown = json.dumps(shown, default=str)[:70]
        print(f"     {actual:<24} {str(shown)[:70]}")
    print()
    if found_user:
        print("  ★ userId IS POPULATED. This is the significant finding: DNAC ties the")
        print("    authenticated identity to the switch and port in one record. Email →")
        print("    AD → username → this call is the whole chain, and ISE becomes")
        print("    enrichment (policy, SGT, authz profile) rather than the backbone.")
    else:
        print("  userId is absent or empty on this record. DNAC can still answer")
        print("  MAC/IP → port, but the identity hop has to come from ISE or User-ID.")


def step_client_detail(dnac, mac: str, red: Redactor, full: bool) -> None:
    _hr(f"STEP 3  —  PER-CLIENT RECORD  GET /dna/intent/api/v1/client-detail  "
        f"[{red.plain(mac)}]")
    ts = int(time.time() * 1000)
    payload, err = _call(dnac, "/dna/intent/api/v1/client-detail",
                         {"macAddress": mac, "timestamp": ts})
    if err:
        print(f"  FAILED — {err}")
        return
    if not payload:
        _empty_warning()
        return
    detail = payload.get("detail") if isinstance(payload, dict) else None
    conn = payload.get("connectionInfo") if isinstance(payload, dict) else None
    record = detail if isinstance(detail, dict) else (payload if isinstance(payload, dict) else {})
    if not record:
        _empty_warning()
        return
    print(f"  keys: {sorted(record.keys())[:24]}")
    _report_payoff(record, red)
    if isinstance(conn, dict) and conn:
        print("\n  connectionInfo (the switch/AP side):")
        for k, v in conn.items():
            if v not in (None, "", [], {}):
                print(f"     {k:<24} {str(red.cell(k, v))[:70]}")
    if full:
        print(f"\n  full payload:\n{json.dumps(payload, indent=2, default=str)[:3000]}")


def step_user_enrichment(dnac, user: str, red: Redactor, full: bool) -> None:
    _hr(f"STEP 4  —  BY USER  GET /dna/intent/api/v1/user-enrichment-details  "
        f"[{red.plain(user)}]")
    print("  The only endpoint in the estate keyed on a USER rather than a MAC or IP.")
    print("  Header-driven, which is why it is easy to miss in the SDK.\n")
    headers = {"entity_type": "network_user_id", "entity_value": user}
    payload, err = _call(dnac, "/dna/intent/api/v1/user-enrichment-details",
                         headers=headers)
    if err:
        print(f"  FAILED — {err}")
        print("\n  If this 404s, the by-user path through DNAC is closed and the")
        print("  identity hop must come from ISE (Session/UserName) or PAN User-ID.")
        return
    rows = _rows(payload)
    if not rows:
        print("  EMPTY — endpoint answered, no record for that user id.")
        print("  Try the exact form DNAC stores (bare name vs DOMAIN\\user vs UPN);")
        print("  the ISE probe's step 4 reports which format this estate uses.")
        return
    print(f"  {len(rows)} record(s).")
    first = rows[0] if isinstance(rows[0], dict) else {}
    if "userDetails" in first:
        print("\n  userDetails:")
        for k, v in (first.get("userDetails") or {}).items():
            if v not in (None, "", [], {}):
                print(f"     {k:<24} {str(red.cell(k, v))[:70]}")
    if "connectedDevice" in first:
        print("\n  connectedDevice:")
        print(f"     {json.dumps(first['connectedDevice'], default=str)[:600]}")
    if not ("userDetails" in first or "connectedDevice" in first):
        _report_payoff(first, red)
    print("\n  ★ If this returned a device and port, the whole feature is one GET per")
    print("    user and everything else is enrichment.")
    if full:
        print(f"\n  full payload:\n{json.dumps(payload, indent=2, default=str)[:3000]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mac", help="Client MAC to fetch a full record for "
                                  "(get one from the ISE probe's output)")
    ap.add_argument("--user", help="Username to try the by-user endpoint with")
    ap.add_argument("--hours", type=int, default=24,
                    help="Window for the windowed endpoints (default 24)")
    ap.add_argument("--redact", action="store_true",
                    help="Mask MACs/IPs/usernames — use before pasting output anywhere")
    ap.add_argument("--full", action="store_true", help="Dump full JSON payloads")
    args = ap.parse_args()

    if not os.getenv("DNA_CENTER_BASE_URL"):
        print("ERROR: DNA_CENTER_BASE_URL must be set (see .env.template).")
        return 1

    red = Redactor(args.redact)
    print(f"Catalyst Center client/Assurance probe — {os.getenv('DNA_CENTER_BASE_URL')}")
    print("Read-only: every call below is a GET.")
    if not args.redact:
        print("NOTE: output will contain real client data. Re-run with --redact")
        print("      before pasting it anywhere it will be stored.")

    try:
        dnac = dc.get_client()
    except Exception as e:
        print(f"\nERROR: could not build a DNAC client — {type(e).__name__}: {e}")
        return 1

    alive = step_client_health(dnac, red, args.hours)
    rows = step_data_clients(dnac, red, args.hours, args.full)

    mac = args.mac
    if not mac and rows:
        first = rows[0] if isinstance(rows[0], dict) else {}
        mac = first.get("macAddress") or first.get("hostMac") or first.get("id")
        if mac:
            print(f"\n  (no --mac given; using {red.plain(mac)} from step 2)")
    if mac:
        step_client_detail(dnac, mac, red, args.full)
    else:
        _hr("STEP 3  —  client-detail  (SKIPPED)")
        print("  No MAC available. Pass --mac, ideally one harvested from")
        print("  ise_discover_user_sessions so both systems are asked about the same")
        print("  endpoint — that comparison is more informative than either alone.")

    if args.user:
        step_user_enrichment(dnac, args.user, red, args.full)
    else:
        _hr("STEP 4  —  user-enrichment-details  (SKIPPED)")
        print("  Pass --user NAME to test the by-user path. Use the exact format the")
        print("  ISE probe reports, not the email address.")

    _hr("VERDICT")
    if not alive:
        print("  Assurance did not return usable data. Before concluding it is off,")
        print("  confirm licensing and telemetry — an un-telemetried instance answers")
        print("  200 with no rows, which reads exactly like a healthy quiet network.")
    else:
        print("  Assurance is answering. The decisive question is whether `userId` is")
        print("  populated on client records (called out in steps 2-3): that single")
        print("  field decides whether this feature is one DNAC call or a four-system")
        print("  join.")

    _hr("NEXT")
    print("  ise_discover_user_sessions   identity, policy, SGT and the port fallback")
    print("  solarwinds_discover_udt      port history and unauthenticated ports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
