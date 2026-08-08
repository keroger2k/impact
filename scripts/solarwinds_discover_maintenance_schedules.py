#!/usr/bin/env python3
"""scripts/solarwinds_discover_maintenance_schedules.py — SolarWinds Maintenance
Mode / AlertSuppression discovery probe.

Read-only reconnaissance for the Maintenance Mode Scheduler report
(utils/maintenance_report.py). That report was first built against the
classic `Orion.Nodes/Unmanage` SWIS verb, confirmed correct against
SolarWinds' own orionsdk-python sample — but a real submission through
Orion's own "Scheduled Maintenance" UI dialog proved that verb doesn't
populate Settings > All Settings > Manage Maintenance Schedules. Browser
DevTools capture of that dialog's own submit request showed it actually
POSTs to a *different* API entirely: `/api2/schedules/createOneTime`, a
cookie+XSRF-session-authenticated endpoint (not SWIS), with a payload whose
`scheduleType: "AlertSuppression"` field strongly suggests the underlying
SWIS entity is `Orion.AlertSuppression` (verb `SuppressAlerts`) — a
plausible, SDK-precedented, stateless-Basic-Auth-compatible alternative to
the cookie-session REST API, IF calling it directly actually creates
something visible in that same list.

This script asks SolarWinds directly, rather than guessing a third time:

  1. Metadata.Entity — search for any entity whose name suggests it backs
     "Schedule"/"Maintenance"/"Suppress" features, so we're not assuming
     Orion.AlertSuppression is the only (or the right) one.
  2. Metadata.Verb — every verb exposed on Orion.AlertSuppression (confirms
     SuppressAlerts exists and its exact name, and reveals any sibling verb
     like an UnSuppress/cancel counterpart) and on any other candidate
     entities STEP 1 turns up.
  3. Metadata.Property — every column on Orion.AlertSuppression (and any
     Schedule-like candidate entity), so STEP 4/5's SELECTs use real column
     names instead of guesses.
  4. A live read of Orion.AlertSuppression's current rows — if you've
     already created a "Mute alerts" schedule through the real UI dialog (as
     in the screenshot that prompted this), it should show up here if this
     entity is really what stores it.
  5. A live read of whatever Schedule-like entity STEP 1 found, same
     reasoning — this is the one that would confirm or rule out a *separate*
     "Schedules" bookkeeping layer sitting above AlertSuppression.
  6. Orion.Engines — the Scheduled-Maintenance dialog's captured payload used
     an EntityUri like "swis://KCKVGX200.network.ad.tsa.gov/Orion/Orion.Nodes/
     NodeID=8318", where the hostname looks like a polling engine's
     ServerName rather than the web console's own DNS name. This resolves
     that mapping for real (NodeID -> EngineID -> Engines.ServerName) rather
     than hardcoding a hostname that only happens to be right for one poller.

Nothing here writes anything — every query is a plain SWQL SELECT, same
posture as scripts/solarwinds_discover_site_properties.py (whose docstring
explains why this bypasses clients.solarwinds.query() and prints raw
response bodies: a 400's body usually names the exact invalid field/entity,
which is the fastest way to correct a bad guess).

Env vars (.env): same as scripts/solarwinds_discover_site_properties.py —
SOLARWINDS_URL (required), SOLARWINDS_DOMAIN/PORT/TIMEOUT (optional),
SOLARWINDS_USERNAME/PASSWORD (default to DOMAIN_USERNAME/PASSWORD),
SOLARWINDS_VERIFY_SSL (default false).

    SW_DISCOVER_NODE   required — a node Caption (or substring) to resolve
                       for the Orion.Engines mapping in STEP 6. Use the same
                       node you scheduled maintenance against in the UI
                       (e.g. K056WMA005) so STEP 4/5's results are easy to
                       recognize as "the one I just created."

Usage:
    python -m scripts.solarwinds_discover_maintenance_schedules
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from requests.auth import HTTPBasicAuth  # noqa: E402

load_dotenv()

# Candidate entity-name fragments for whatever backs "Manage Maintenance
# Schedules" — cast wide since we don't know the real name yet.
_NAME_PATTERNS = ["Schedul", "Maintenance", "Suppress"]


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


def _print_header(title: str):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _print_rows(rows: list[dict], max_rows: int = 60):
    if not rows:
        print("(no rows returned)")
        return
    print(f"{len(rows)} row(s){' — showing first ' + str(max_rows) if len(rows) > max_rows else ''}:")
    for row in rows[:max_rows]:
        print(json.dumps(row, indent=2, default=str))


def run_query(swql: str, username: str, password: str, verify_ssl: bool, timeout: int) -> list[dict] | None:
    port = os.getenv("SOLARWINDS_PORT", "17774")
    endpoint = f"{_base_url()}:{port}/SolarWinds/InformationService/v3/Json/Query"
    print(f"SWQL:\n{swql.strip()}\n")
    try:
        resp = requests.post(
            endpoint,
            json={"query": swql},
            auth=HTTPBasicAuth(_format_username(username), password),
            verify=verify_ssl,
            timeout=timeout,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

    print(f"← HTTP {resp.status_code}")
    if resp.status_code != 200:
        print(resp.text[:3000])
        return None

    try:
        return resp.json().get("results", [])
    except ValueError:
        print("200 but not JSON — raw body:")
        print(resp.text[:2000])
        return None


def probe_candidate_entities(username: str, password: str, verify_ssl: bool, timeout: int) -> list[str]:
    _print_header("STEP 1 — Entities whose name suggests Schedule/Maintenance/Suppress")
    # Metadata.Entity's own name column is just "Name" (it's self-referential,
    # no foreign key needed) — unlike Metadata.Verb/Metadata.Property, which
    # both use "EntityName" to point at the entity they describe. Confirmed
    # against a real run that "EntityName" here 400s ("Cannot resolve
    # property EntityName") while Metadata.Verb's own EntityName column
    # worked fine in the same run — that asymmetry is exactly why STEP 1
    # failed the first time.
    where = " OR ".join(f"Name LIKE '%{p}%'" for p in _NAME_PATTERNS)
    swql = f"SELECT Name FROM Metadata.Entity WHERE {where} ORDER BY Name"
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        print("\nMetadata.Entity query failed — can't enumerate candidates; "
              "the rest of this script will fall back to Orion.AlertSuppression alone.")
        return ["Orion.AlertSuppression"]
    _print_rows(rows, max_rows=200)
    # Metadata.Entity.Name comes back bare ("MaintenancePlan"), but
    # Metadata.Verb/Metadata.Property need the fully-qualified name
    # ("Orion.MaintenancePlan") — confirmed against a real run where every
    # bare candidate 0-rowed (no error, just empty) while the one candidate
    # manually hardcoded with the "Orion." prefix (AlertSuppression) worked.
    # Silent 0-rows made that look like "these entities have no verbs" when
    # it was actually just the missing prefix.
    bare_names = sorted({r.get("Name") for r in rows if r.get("Name")})
    names = sorted({n if "." in n else f"Orion.{n}" for n in bare_names})
    if "Orion.AlertSuppression" not in names:
        names.append("Orion.AlertSuppression")
    print(f"\nBare names found: {bare_names}")
    print(f"Candidate entities to probe further (Orion.-qualified): {names}")
    print(
        "If a name here looks like the real 'Schedules' bookkeeping table "
        "(e.g. something containing 'Schedule' that ISN'T AlertSuppression "
        "itself), that's the one likely to actually populate Manage "
        "Maintenance Schedules — AlertSuppression may just be the effect it "
        "applies underneath, not the list entry itself."
    )
    return names


def probe_verbs(entity: str, username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header(f"STEP 2 — Verbs on {entity}")
    swql = f"SELECT EntityName, Name FROM Metadata.Verb WHERE EntityName = '{entity}' ORDER BY Name"
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return
    _print_rows(rows)
    if rows:
        verb_names = [r.get("Name") for r in rows]
        print(f"\nVerb names on {entity}: {verb_names}")
        print(
            "Look for a create/suppress verb (e.g. SuppressAlerts) and, "
            "separately, a cancel/remove verb — the cancel one matters for "
            "building a 'Manage Again'-equivalent without going through the "
            "web UI."
        )


def probe_properties(entity: str, username: str, password: str, verify_ssl: bool, timeout: int) -> list[str]:
    _print_header(f"STEP 3 — Columns on {entity}")
    # Same EntityName-vs-Name correction as STEP 1: Metadata.Property points
    # at its owning entity via "EntityName" (matching Metadata.Verb, which
    # already worked), and its own bare column name is "Name", not "FullName".
    swql = f"SELECT Uri, Name, Type FROM Metadata.Property WHERE EntityName = '{entity}' ORDER BY Name"
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return []
    _print_rows(rows, max_rows=200)
    return [r.get("Name") for r in rows if r.get("Name")]


def probe_rows(entity: str, columns: list[str], username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header(f"STEP 4/5 — Current rows in {entity}")
    if not columns:
        print(f"No columns discovered for {entity} in STEP 3 — skipping (entity may not exist on this instance).")
        return
    select_list = ", ".join(columns[:25])  # SWQL rejects SELECT * — cap to keep the query readable
    swql = f"SELECT TOP 20 {select_list} FROM {entity}"
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return
    _print_rows(rows)
    if rows:
        print(
            f"\nIf you created a 'Mute alerts' schedule through the real UI "
            f"dialog earlier, look for it above — if it's here, {entity} is "
            f"confirmed as (at least part of) the real backing store."
        )
    else:
        print(f"\n{entity} exists but has no current rows — inconclusive on its own; "
              "check whether any earlier UI-created schedule has already expired.")


def probe_engine_mapping(node: str, username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header(f"STEP 6 — Polling engine hostname for '{node}' (for EntityUri construction)")
    swql = f"""
SELECT NodeID, Caption, EngineID
FROM Orion.Nodes
WHERE Caption = '{node}' OR Caption LIKE '%{node}%'
"""
    node_rows = run_query(swql, username, password, verify_ssl, timeout)
    if not node_rows:
        print(f"\nNo node matched '{node}' — set SW_DISCOVER_NODE to a real Caption and re-run.")
        return

    _print_rows(node_rows)
    engine_ids = sorted({r.get("EngineID") for r in node_rows if r.get("EngineID") is not None})

    print()
    swql2 = "SELECT EngineID, ServerName, IP FROM Orion.Engines ORDER BY EngineID"
    engine_rows = run_query(swql2, username, password, verify_ssl, timeout)
    if engine_rows is None:
        return
    _print_rows(engine_rows)

    by_id = {r.get("EngineID"): r for r in engine_rows}
    for eid in engine_ids:
        match = by_id.get(eid)
        if match:
            print(
                f"\nNodeID(s) with EngineID={eid} should use ServerName "
                f"'{match.get('ServerName')}' in their EntityUri "
                f"(swis://{match.get('ServerName')}/Orion/Orion.Nodes/NodeID=<id>) "
                f"— NOT necessarily the same host as SOLARWINDS_URL."
            )
    if len(engine_rows) == 1:
        print(
            "\nOnly one polling engine on this instance — if that stays true "
            "fleet-wide, EntityUri's hostname can safely be a single resolved "
            "value rather than a per-node lookup. Confirm EngineID is uniform "
            "across a few more nodes before assuming that, though."
        )


def main():
    username = os.getenv("SOLARWINDS_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SOLARWINDS_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    node = os.getenv("SW_DISCOVER_NODE", "").strip()
    verify_ssl = _bool_env("SOLARWINDS_VERIFY_SSL", False)
    timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not os.getenv("SOLARWINDS_URL"):
        print("ERROR: SOLARWINDS_URL must be set (see .env.template).")
        sys.exit(1)
    if not username or not password:
        print("ERROR: SOLARWINDS_USERNAME/SOLARWINDS_PASSWORD (or DOMAIN_USERNAME/"
              "DOMAIN_PASSWORD) must be set.")
        sys.exit(1)
    if not node:
        print("ERROR: SW_DISCOVER_NODE is required — set it to the Caption of the "
              "node you scheduled maintenance against in the UI (e.g. K056WMA005).")
        sys.exit(1)

    entities = probe_candidate_entities(username, password, verify_ssl, timeout)
    for entity in entities:
        probe_verbs(entity, username, password, verify_ssl, timeout)
        cols = probe_properties(entity, username, password, verify_ssl, timeout)
        probe_rows(entity, cols, username, password, verify_ssl, timeout)

    probe_engine_mapping(node, username, password, verify_ssl, timeout)

    print()
    print("=" * 78)
    print("Done. Paste this whole output back. It should settle: (1) whether")
    print("Orion.AlertSuppression alone is enough or a separate Schedules entity")
    print("exists, (2) the real verb name(s), and (3) how to build EntityUri per node.")
    print("=" * 78)


if __name__ == "__main__":
    main()
