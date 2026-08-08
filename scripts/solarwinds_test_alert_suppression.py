#!/usr/bin/env python3
"""scripts/solarwinds_test_alert_suppression.py — live test of Orion.AlertSuppression.

Confirms two things against a real SolarWinds instance before this gets
wired into the Maintenance Mode Scheduler report
(utils/maintenance_report.py):

  1. That `Orion.AlertSuppression/SuppressAlerts` actually works over plain
     HTTP Basic Auth (the same per-call AD-creds model every other client in
     this app uses) — confirmed separately that `/api2/schedules/createOneTime`
     (the endpoint the real "Scheduled Maintenance" UI dialog calls, and the
     one confirmed to populate Settings > All Settings > Manage Maintenance
     Schedules) does NOT accept Basic Auth alone (401) — it needs a real
     cookie+XSRF session, which this app doesn't have a login flow for yet.
  2. Whether calling SuppressAlerts *directly* (bypassing /api2/) is enough
     on its own — i.e. whether it shows up in Manage Maintenance Schedules
     too, or whether that screen is populated only by the /api2/ layer with
     AlertSuppression just being the effect underneath. That part can only
     be answered by watching the real SolarWinds UI after running this.

This is a genuine write (SuppressAlerts actually mutes alerting for the
node) — dry-run by default, same posture as scripts/import_registry.py:
prints what it would do and stops. Pass --apply to actually call it.
--resume calls ResumeAlerts instead, to reverse an --apply run early rather
than waiting out the window.

Env vars (.env): SOLARWINDS_URL (required), SOLARWINDS_DOMAIN/PORT/TIMEOUT
(optional), SOLARWINDS_USERNAME/PASSWORD (default to DOMAIN_USERNAME/PASSWORD),
SOLARWINDS_VERIFY_SSL (default false).

Usage:
    python -m scripts.solarwinds_test_alert_suppression --node <caption>                 # dry-run
    python -m scripts.solarwinds_test_alert_suppression --node <caption> --apply          # suppress for --minutes
    python -m scripts.solarwinds_test_alert_suppression --node <caption> --resume --apply # cancel early
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


def _endpoint(username: str, password: str, verify_ssl: bool, timeout: int):
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


def resolve_uri(call, node: str) -> str | None:
    resp = call("POST", "Query", {"query": f"SELECT Uri, Caption FROM Orion.Nodes WHERE Caption = '{node}' OR Caption LIKE '%{node}%'"})
    if resp.status_code != 200:
        return None
    rows = resp.json().get("results", [])
    if not rows:
        print(f"\nNo node matched '{node}'.")
        return None
    exact = [r for r in rows if (r.get("Caption") or "").lower() == node.lower()]
    match = exact[0] if exact else rows[0]
    print(f"\nResolved '{node}' -> {match.get('Caption')} ({match.get('Uri')})")
    return match.get("Uri")


def get_state(call, uri: str):
    call("POST", "Invoke/Orion.AlertSuppression/GetAlertSuppressionState", [[uri]])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node", required=True, help="Node Caption (or substring) to test against")
    ap.add_argument("--minutes", type=int, default=5, help="Suppression window length (default 5)")
    ap.add_argument("--resume", action="store_true", help="Call ResumeAlerts instead of SuppressAlerts")
    ap.add_argument("--apply", action="store_true", help="Actually make the write call (default: dry-run)")
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

    call = _endpoint(username, password, verify_ssl, timeout)
    uri = resolve_uri(call, args.node)
    if not uri:
        sys.exit(1)

    print("\n--- Current suppression state (before) ---")
    get_state(call, uri)

    if args.resume:
        if not args.apply:
            print(f"\nDRY RUN — would call ResumeAlerts([{uri!r}]). Pass --apply to actually cancel it.")
            return
        print("\n--- Calling ResumeAlerts ---")
        call("POST", "Invoke/Orion.AlertSuppression/ResumeAlerts", [[uri]])
    else:
        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=args.minutes)
        if not args.apply:
            print(f"\nDRY RUN — would call SuppressAlerts([{uri!r}], {start.isoformat()!r}, {end.isoformat()!r}).")
            print("Pass --apply to actually suppress alerts for this node.")
            return
        print(f"\n--- Calling SuppressAlerts for {args.minutes} minute(s) ---")
        call("POST", "Invoke/Orion.AlertSuppression/SuppressAlerts", [[uri], start.isoformat(), end.isoformat()])

    print("\n--- Current suppression state (after) ---")
    get_state(call, uri)

    print()
    print("=" * 78)
    print("Now check the SolarWinds UI: does this node show up in Settings > All")
    print("Settings > Manage Maintenance Schedules? That's the deciding question —")
    print("paste back yes/no (and what you see) either way.")
    print("=" * 78)


if __name__ == "__main__":
    main()
