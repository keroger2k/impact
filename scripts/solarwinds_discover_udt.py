#!/usr/bin/env python3
"""scripts/solarwinds_discover_udt.py — is SolarWinds User Device Tracker
licensed here, and does it already answer "which port is this user on?"

Read-only reconnaissance for the cross-platform endpoint search
(docs/ROADMAP.md item #1). This is the cheapest possible outcome for that
feature and the first thing worth ruling in or out: UDT is a SolarWinds module
that continuously polls switch CAM tables, ARP caches and AD logon events, and
stores MAC → port → user with *history*. If it is licensed on this Orion
instance, most of the endpoint search already exists as a database we can
query through `clients/solarwinds.py`, which every /reports page already uses.

It would also cover two things ISE structurally cannot:

  * HISTORY. ISE's MNT session tables answer "where is this user now" and,
    for a bounded window, "where were they". UDT keeps port-to-endpoint
    history for as long as its retention allows, which is the difference
    between "where is this laptop" and "where has this laptop been".

  * UNAUTHENTICATED PORTS. Anything not doing 802.1X — a port in a lab, a
    device on a MAB-exempt VLAN — is invisible to ISE and perfectly visible
    to a CAM-table poller.

Nothing is assumed about the schema. The probe asks SWIS's own metadata
entities what exists rather than guessing table and column names:

  1. Metadata.Entity for anything named Orion.UDT.* — if this returns nothing,
     UDT is not installed and the answer is simply no.
  2. Metadata.Property per discovered entity, to learn its real columns.
     Necessary rather than tidy: SWQL rejects `SELECT *` outright ("no viable
     alternative at input '*'", confirmed by the earlier site-properties
     probe), so a sample row cannot be fetched without knowing column names.
  3. A row count per entity — the schema being installed is not the same as
     it being licensed, polled and populated. An empty UDT table looks
     identical to a working one with nothing to report.
  4. A sample row from each populated entity, so the actual shape is visible.

Uses clients.solarwinds.query() directly rather than raw requests: unlike the
other clients, that wrapper already includes Orion's own response body in the
exception it raises (see its docstring), which is where a SWQL error names the
invalid entity or column. There is nothing to bypass.

Every query is a SWQL SELECT. The module's one write verb, suppress_alerts(),
is not imported here.

⚠️  OUTPUT MAY CONTAIN REAL USERNAMES, MAC AND IP ADDRESSES. Pass --redact
    before pasting it anywhere.

Env vars (.env): SOLARWINDS_URL, SOLARWINDS_USERNAME, SOLARWINDS_PASSWORD
(the dedicated service account clients/solarwinds.py reads for itself).

Usage:
    .venv/bin/python -m scripts.solarwinds_discover_udt
    .venv/bin/python -m scripts.solarwinds_discover_udt --user jsmith
    .venv/bin/python -m scripts.solarwinds_discover_udt --mac 00:11:22:33:44:55
    .venv/bin/python -m scripts.solarwinds_discover_udt --full --redact
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.solarwinds as solarwinds  # noqa: E402

# Column types that cannot appear in a plain SELECT list.
_UNSELECTABLE = ("navigation", "collection", "entity")

# Entities worth commenting on by name if they turn up.
_NOTES = {
    "Orion.UDT.Port": "switch ports UDT polls — the port side of the answer",
    "Orion.UDT.Endpoint": "endpoints seen (MAC-keyed) — the device side",
    "Orion.UDT.IPAddress": "IP ↔ MAC from ARP — the join to everything else",
    "Orion.UDT.PortToEndpointHistory": "THE table: which MAC was on which port, when",
    "Orion.UDT.EndpointHistory": "endpoint sightings over time",
    "Orion.UDT.UserLogon": "AD logon events — user ↔ machine, the hop ISE may not give",
    "Orion.UDT.UserLogonHistory": "historical user ↔ machine logons",
    "Orion.UDT.User": "user records UDT knows about",
    "Orion.UDT.DeviceInfo": "per-device UDT capability/state",
    "Orion.UDT.NodeCapability": "which nodes are UDT-capable and licensed",
}

_SENSITIVE_COL = re.compile(
    r"(mac|ipaddress|ip_address|username|user_name|accountname|dnsname|hostname|caption)",
    re.I,
)


def _mask(val) -> str:
    s = str(val)
    if not s or s in ("None", "-"):
        return s
    if s.count(".") == 3 and all(p.isdigit() for p in s.split(".")):
        p = s.split(".")
        return f"{p[0]}.{p[1]}.x.x"
    if len(s) > 6:
        return f"{s[:3]}***{s[-2:]}"
    return "***"


class Redactor:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def cell(self, col: str, val) -> str:
        if self.enabled and _SENSITIVE_COL.search(col or ""):
            return _mask(val)
        return str(val)


def _hr(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _q(swql: str, timeout: int = 60):
    """Run a SWQL SELECT, returning (rows, error_text)."""
    try:
        return solarwinds.query(swql, timeout=timeout), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def step_entities() -> list[str]:
    _hr("STEP 1  —  DOES UDT EXIST?  (Metadata.Entity)")
    rows, err = _q("SELECT FullName FROM Metadata.Entity "
                   "WHERE FullName LIKE 'Orion.UDT%' ORDER BY FullName")
    if err:
        print(f"  QUERY FAILED — {err}")
        print("\n  If the error names Metadata.Entity itself, this Orion version does")
        print("  not expose schema introspection and the entities must be probed by")
        print("  name instead. Any other error is a connectivity or auth problem.")
        return []
    names = [r.get("FullName") for r in (rows or []) if r.get("FullName")]
    if not names:
        print("  NO Orion.UDT.* ENTITIES.")
        print()
        print("  VERDICT: User Device Tracker is not installed on this Orion instance.")
        print("  That closes this option — the endpoint search gets its port data from")
        print("  ISE (nas_port_id) and, for unauthenticated ports, would need CAM/ARP")
        print("  collection the app does not do today.")
        return []
    print(f"  {len(names)} UDT entity(ies) present:\n")
    for n in names:
        note = _NOTES.get(n, "")
        print(f"    {n:<44} {note}")
    print("\n  Schema present. That is NOT the same as licensed and polling — step 2.")
    return names


def _columns(entity: str) -> list[str]:
    rows, err = _q(f"SELECT Name, Type FROM Metadata.Property "
                   f"WHERE EntityName = '{entity}' ORDER BY Name")
    if err or not rows:
        return []
    cols = []
    for r in rows:
        name, typ = r.get("Name"), (r.get("Type") or "").lower()
        if not name or any(t in typ for t in _UNSELECTABLE):
            continue
        cols.append(name)
    return cols


def step_counts(entities: list[str], red: Redactor, full: bool) -> dict[str, int]:
    _hr("STEP 2  —  IS IT ACTUALLY POPULATED?  (row counts + sample rows)")
    counts: dict[str, int] = {}
    for entity in entities:
        print(f"\n  ── {entity}")
        rows, err = _q(f"SELECT COUNT(*) AS Cnt FROM {entity}", timeout=90)
        if err:
            print(f"     COUNT failed — {err}")
            count = None
        else:
            count = (rows[0].get("Cnt") if rows else 0) or 0
            counts[entity] = int(count)
            print(f"     {count} row(s)")
            if count == 0:
                print("     empty — installed but nothing polled into it.")
                continue

        cols = _columns(entity)
        if not cols:
            print("     (could not read column list; skipping sample)")
            continue
        take = cols if full else cols[:8]
        sample, err = _q(f"SELECT TOP 2 {', '.join(take)} FROM {entity}")
        if err:
            print(f"     sample failed — {err}")
            continue
        print(f"     columns ({len(cols)}): {', '.join(cols[:14])}"
              f"{' ...' if len(cols) > 14 else ''}")
        for row in (sample or []):
            shown = {k: red.cell(k, v) for k, v in row.items() if v not in (None, "")}
            print(f"     e.g. {shown}")
    return counts


def step_by_user(username: str, entities: list[str], red: Redactor) -> None:
    _hr(f"STEP 3  —  CAN WE SEARCH BY USER?  [{username}]")
    candidates = [e for e in entities if "user" in e.lower() or "logon" in e.lower()]
    if not candidates:
        print("  No user/logon entity in this UDT install — UDT can answer MAC→port")
        print("  but not user→port. The user hop would still come from ISE or AD.")
        return
    safe = username.replace("'", "''")
    for entity in candidates:
        cols = _columns(entity)
        name_cols = [c for c in cols if re.search(r"(user|account|name)", c, re.I)]
        if not name_cols:
            continue
        print(f"\n  ── {entity}  (matching on {', '.join(name_cols[:3])})")
        where = " OR ".join(f"{c} LIKE '%{safe}%'" for c in name_cols[:3])
        take = cols[:10]
        rows, err = _q(f"SELECT TOP 5 {', '.join(take)} FROM {entity} WHERE {where}")
        if err:
            print(f"     FAILED — {err}")
            continue
        if not rows:
            print("     no rows matched that name.")
            continue
        print(f"     {len(rows)} row(s):")
        for row in rows:
            shown = {k: red.cell(k, v) for k, v in row.items() if v not in (None, "")}
            print(f"       {shown}")
        print("\n     → user → endpoint is answerable directly from SolarWinds.")


def step_by_mac(mac: str, entities: list[str], red: Redactor) -> None:
    _hr(f"STEP 4  —  CAN WE SEARCH BY MAC?  [{red.cell('mac', mac)}]")
    # UDT normally stores MACs with no separators, uppercase.
    variants = {
        mac.upper(),
        mac.upper().replace(":", "").replace("-", "").replace(".", ""),
        mac.lower(),
    }
    candidates = [e for e in entities
                  if any(t in e for t in ("Endpoint", "Port", "IPAddress"))]
    for entity in candidates:
        cols = _columns(entity)
        mac_cols = [c for c in cols if "mac" in c.lower()]
        if not mac_cols:
            continue
        print(f"\n  ── {entity}  (matching on {', '.join(mac_cols)})")
        hit = False
        for v in variants:
            safe = v.replace("'", "''")
            where = " OR ".join(f"{c} = '{safe}'" for c in mac_cols)
            rows, err = _q(f"SELECT TOP 5 {', '.join(cols[:10])} FROM {entity} WHERE {where}")
            if err:
                print(f"     FAILED ({v}) — {err}")
                break
            if rows:
                hit = True
                print(f"     matched with format {v!r}: {len(rows)} row(s)")
                for row in rows:
                    shown = {k: red.cell(k, val) for k, val in row.items()
                             if val not in (None, "")}
                    print(f"       {shown}")
                break
        if not hit:
            print("     no match in any MAC format tried "
                  "(colon-separated, bare, lowercase).")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--user", help="Username to search UDT's logon tables for")
    ap.add_argument("--mac", help="MAC address to search UDT's endpoint tables for")
    ap.add_argument("--redact", action="store_true",
                    help="Mask MACs/IPs/usernames — use before pasting output anywhere")
    ap.add_argument("--full", action="store_true",
                    help="Sample every column, not just the first eight")
    args = ap.parse_args()

    missing = [v for v in ("SOLARWINDS_URL", "SOLARWINDS_USERNAME", "SOLARWINDS_PASSWORD")
               if not os.getenv(v)]
    if missing:
        print(f"ERROR: missing env var(s): {', '.join(missing)} (see .env.template).")
        return 1

    red = Redactor(args.redact)
    print(f"SolarWinds UDT probe — {os.getenv('SOLARWINDS_URL')}")
    print("Read-only: every query below is a SWQL SELECT.")
    if not args.redact:
        print("NOTE: output may contain real MACs/IPs/usernames. Re-run with --redact")
        print("      before pasting it anywhere it will be stored.")

    entities = step_entities()
    if not entities:
        return 0

    counts = step_counts(entities, red, args.full)

    if args.user:
        step_by_user(args.user, entities, red)
    if args.mac:
        step_by_mac(args.mac, entities, red)

    _hr("VERDICT")
    populated = {e: c for e, c in counts.items() if c}
    if not populated:
        print("  UDT's schema is installed but every table is empty. That is an")
        print("  unlicensed or unconfigured module, not a working one — treat this")
        print("  source as unavailable unless someone turns it on.")
    else:
        print(f"  {len(populated)} populated UDT entity(ies):")
        for e, c in sorted(populated.items(), key=lambda kv: -kv[1])[:10]:
            print(f"     {e:<44} {c:>10,} rows")
        print()
        print("  This is a live port-tracking database reachable through the SolarWinds")
        print("  client already in the app. Weigh it against the ISE path deliberately:")
        print("  UDT gives history and covers unauthenticated ports; ISE gives identity,")
        print("  authorization policy and SGT. A good search probably uses both, but")
        print("  which one is the spine of the feature is now an informed choice.")
        if not args.user:
            print("\n  Re-run with --user NAME to test the user→endpoint direction.")

    _hr("NEXT")
    print("  ise_discover_user_sessions   the identity/authorization side")
    print("  dnac_discover_clients        Catalyst Center's own per-client record")
    return 0


if __name__ == "__main__":
    sys.exit(main())
