#!/usr/bin/env python3
"""scripts/solarwinds_test_maintenance_plan.py — live test of Orion.MaintenancePlan.

Orion.AlertSuppression (tested in scripts/solarwinds_test_alert_suppression.py)
mutes alerts but confirmed NOT to show up in Settings > All Settings > Manage
Maintenance Schedules. That screen's real backing entity is very likely
**Orion.MaintenancePlan** ("Plan defining maintenance schedule for entities
being unmanaged") + **Orion.MaintenancePlanAssignment** (links entities to a
plan via MaintenancePlanID + EntityUri) — confirmed to exist, with this exact
property list, in SolarWinds' own public schema reference
(https://solarwinds.github.io/OrionSDK/schema/), not guessed. Neither entity
has custom verbs — they're managed via plain SWIS Create, same primitive
clients/solarwinds.py's query() already uses, still just Basic Auth. If this
works, we don't need the /api2/ cookie+XSRF session flow at all.

MaintenancePlan properties relevant here: Name, Reason, Enabled, KeepPolling
(almost certainly the "Mute alerts" vs "Stop polling (Unmanage)" toggle from
the real dialog — True keeps polling running while suppressing alerts, False
is the classic Unmanage behavior), UnmanageDate (start), RemanageDate (end).
This script always sends KeepPolling=true per "I always just want to mute
alerts."

Flow: Create one Orion.MaintenancePlan, read back its ID/Uri, then Create one
Orion.MaintenancePlanAssignment per --node pointing MaintenancePlanID at it.

Genuine write — dry-run by default (prints every request it would make),
--apply to actually create anything. No cancel/delete verb tested yet; if
this works, cancelling should just be a normal SWIS Delete on the Plan
(deletes cascade to its Assignments via the Hosting relationship) — untested,
flagged for a follow-up once creation itself is confirmed.

Env vars (.env): SOLARWINDS_URL (required), SOLARWINDS_DOMAIN/PORT/TIMEOUT
(optional), SOLARWINDS_USERNAME/PASSWORD (default to DOMAIN_USERNAME/PASSWORD),
SOLARWINDS_VERIFY_SSL (default false).

Usage:
    python -m scripts.solarwinds_test_maintenance_plan --node <caption> [--node <caption> ...]
    python -m scripts.solarwinds_test_maintenance_plan --node <caption> --minutes 5 --apply
"""
from __future__ import annotations

import argparse
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
from requests.auth import HTTPBasicAuth  # noqa: E402

load_dotenv()


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "y")


def _base_url() -> str:
    url = os.getenv("SOLARWINDS_URL", "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _format_username(username: str) -> str:
    if "\\" in username or "@" in username:
        return username
    domain = os.getenv("SOLARWINDS_DOMAIN", "network")
    return f"{domain}\\{username}"


def _caller(username: str, password: str, verify_ssl: bool, timeout: int):
    port = os.getenv("SOLARWINDS_PORT", "17774")
    base = f"{_base_url()}:{port}/SolarWinds/InformationService/v3/Json"
    auth = HTTPBasicAuth(_format_username(username), password)

    def call(method: str, frag: str, payload):
        url = f"{base}/{frag}"
        print(f"\n→ {method} {url}")
        print(f"  body: {json.dumps(payload)}")
        resp = requests.request(method, url, json=payload, auth=auth, verify=verify_ssl, timeout=timeout,
                                 headers={"Accept": "application/json", "Content-Type": "application/json"})
        print(f"← HTTP {resp.status_code}")
        print(resp.text[:2000])
        return resp

    return call


def resolve_uris(call, nodes: list[str]) -> dict[str, str]:
    resolved = {}
    for node in nodes:
        resp = call("POST", "Query", {"query": f"SELECT Uri, Caption FROM Orion.Nodes WHERE Caption = '{node}' OR Caption LIKE '%{node}%'"})
        if resp.status_code != 200:
            continue
        rows = resp.json().get("results", [])
        if not rows:
            print(f"\nNo node matched '{node}' — skipping.")
            continue
        exact = [r for r in rows if (r.get("Caption") or "").lower() == node.lower()]
        match = exact[0] if exact else rows[0]
        print(f"\nResolved '{node}' -> {match.get('Caption')} ({match.get('Uri')})")
        resolved[node] = match.get("Uri")
    return resolved


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node", action="append", required=True, help="Node Caption (repeatable for multiple nodes)")
    ap.add_argument("--minutes", type=int, default=5, help="Plan window length (default 5)")
    ap.add_argument("--name", default=None, help="Plan name (default: auto-generated)")
    ap.add_argument("--reason", default="IMPACT II test", help="Plan reason")
    ap.add_argument("--apply", action="store_true", help="Actually create the plan/assignments (default: dry-run)")
    args = ap.parse_args()

    username = os.getenv("SOLARWINDS_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SOLARWINDS_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    verify_ssl = _bool_env("SOLARWINDS_VERIFY_SSL", False)
    timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not os.getenv("SOLARWINDS_URL"):
        print("ERROR: SOLARWINDS_URL must be set (see .env.template).")
        sys.exit(1)
    if not username or not password:
        print("ERROR: SOLARWINDS_USERNAME/SOLARWINDS_PASSWORD (or DOMAIN_USERNAME/DOMAIN_PASSWORD) must be set.")
        sys.exit(1)

    call = _caller(username, password, verify_ssl, timeout)
    uris = resolve_uris(call, args.node)
    if not uris:
        print("\nNo nodes resolved — nothing to do.")
        sys.exit(1)

    start = datetime.now(timezone.utc)
    end = start + timedelta(minutes=args.minutes)
    name = args.name or f"IMPACT II Test {start.strftime('%Y%m%d_%H%M%S')}"

    plan_props = {
        "Name": name,
        "Reason": args.reason,
        "Enabled": True,
        "KeepPolling": True,  # always mute-alerts-only, per requirement
        "UnmanageDate": start.isoformat(),
        "RemanageDate": end.isoformat(),
    }

    print("\n" + "=" * 78)
    print(f"Would create Orion.MaintenancePlan: {json.dumps(plan_props, indent=2)}")
    print(f"Then Orion.MaintenancePlanAssignment for each of {len(uris)} node(s): {list(uris.values())}")
    print("=" * 78)

    if not args.apply:
        print("\nDRY RUN — pass --apply to actually create these.")
        return

    print("\n--- Creating Orion.MaintenancePlan ---")
    resp = call("POST", "Create/Orion.MaintenancePlan", plan_props)
    if resp.status_code not in (200, 201):
        print("\nPlan creation failed — stopping (no assignments created).")
        sys.exit(1)

    # SWIS Create typically returns the new entity's Uri as a bare JSON
    # string — printed above either way in case the shape differs here.
    try:
        plan_uri = resp.json()
    except ValueError:
        plan_uri = resp.text.strip().strip('"')
    print(f"\nCreated plan Uri: {plan_uri!r}")

    plan_id = None
    if isinstance(plan_uri, str) and "ID=" in plan_uri:
        plan_id = plan_uri.rsplit("ID=", 1)[-1]
        print(f"Parsed MaintenancePlanID: {plan_id}")

    if not plan_id:
        print("\nCouldn't parse a MaintenancePlanID from the response above — "
              "inspect it manually before wiring assignments to a real ID.")
        sys.exit(1)

    for node, uri in uris.items():
        print(f"\n--- Creating Orion.MaintenancePlanAssignment for {node} ---")
        call("POST", "Create/Orion.MaintenancePlanAssignment", {
            "MaintenancePlanID": int(plan_id),
            "EntityUri": uri,
            "Enabled": True,
        })

    print()
    print("=" * 78)
    print("Now check the SolarWinds UI: does this plan show up in Settings > All")
    print("Settings > Manage Maintenance Schedules, with the right entity count?")
    print("Paste back yes/no (and what you see) either way.")
    print("=" * 78)


if __name__ == "__main__":
    main()
