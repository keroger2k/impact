#!/usr/bin/env python3
"""scripts/solarwinds_discover_site_properties.py — SolarWinds site-metadata discovery probe.

Read-only reconnaissance for adding a "Site Information" section to the
Bandwidth Utilization report (Site Code, Airport Code, Category, Building,
Type, City/ST, Local POC, FRM, Circuit Size & Provider, Transition Date —
see the example report pasted into the conversation that prompted this).
We don't yet know whether these live as SolarWinds custom node properties,
standard Orion.Nodes columns (Location/Contact/Description are common
dumping grounds for exactly this kind of text), or aren't in SolarWinds at
all — so this script asks SolarWinds directly rather than guessing:

  1. SELECT of common standard Orion.Nodes columns for one sample router
     (Location, Contact, Description, Vendor, MachineType, SysName, Comments)
     — some of this site info may already be sitting in plain node fields.
  2. Orion.CustomProperty — the metadata table listing every custom property
     configured anywhere in this SolarWinds instance, filtered to ones
     targeting Orion.Nodes. This is the authoritative "what custom fields
     exist" answer, independent of whether the sample node has them filled in.
  3. Orion.NodesCustomProperties for the sample router — the actual custom
     property values on that node, to cross-reference against step 2's field
     names and confirm the values look like the report fields we're after.

Nothing here writes anything — every query is a plain SWQL SELECT via the
same read-only clients.solarwinds.query() the rest of the app uses. Run it
against your real SolarWinds and paste the output back; that's what nails
down the real field names before any of this gets wired into the Bandwidth
Utilization report.

Env vars (.env):
    SOLARWINDS_URL              already required elsewhere in the app
    SOLARWINDS_DOMAIN           optional NTLM-style prefix (default "network")
    SOLARWINDS_PORT             default 17774
    SOLARWINDS_TIMEOUT          default 180
    SOLARWINDS_USERNAME         defaults to DOMAIN_USERNAME
    SOLARWINDS_PASSWORD         defaults to DOMAIN_PASSWORD
    SW_DISCOVER_NODE            required — a router Caption (or substring) to
                                 sample, e.g. a router you know has this site
                                 info filled in today

Usage:
    .venv/bin/python -m scripts.solarwinds_discover_site_properties
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.solarwinds as solarwinds  # noqa: E402


def _print_header(title: str):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _print_rows(rows: list[dict], max_rows: int = 20):
    if not rows:
        print("(no rows returned)")
        return
    print(f"{len(rows)} row(s){' — showing first ' + str(max_rows) if len(rows) > max_rows else ''}:")
    for row in rows[:max_rows]:
        print(json.dumps(row, indent=2, default=str))


def probe_standard_node_fields(node: str, username: str, password: str):
    _print_header(f"STEP 1 — Standard Orion.Nodes fields for '{node}'")
    swql = f"""
SELECT NodeID, Caption, IPAddress, Location, Contact, Description,
       Vendor, MachineType, SysName, Comments
FROM Orion.Nodes
WHERE Caption = '{node}' OR Caption LIKE '%{node}%'
"""
    try:
        rows = solarwinds.query(swql, username, password)
    except Exception as e:
        print(f"Query failed: {e}")
        return
    _print_rows(rows)
    if rows:
        print(
            "\nLook at Location/Contact/Description/Comments above — these are "
            "free-text standard fields commonly (ab)used for exactly this kind "
            "of site metadata, worth checking before assuming custom properties."
        )


def probe_custom_property_definitions(username: str, password: str):
    _print_header("STEP 2 — Custom property definitions targeting Orion.Nodes")
    swql = """
SELECT Field, DataType, TargetEntity, Description
FROM Orion.CustomProperty
WHERE TargetEntity = 'Orion.Nodes'
ORDER BY Field
"""
    try:
        rows = solarwinds.query(swql, username, password)
    except Exception as e:
        print(f"Query failed: {e}")
        return
    _print_rows(rows, max_rows=100)
    if rows:
        print(
            "\nThis is the authoritative list of every custom field configured "
            "on nodes in this SolarWinds instance — match these Field names "
            "against the report's fields (Site Code, Airport Code, Category, "
            "Building, Type, Local POC, FRM, Circuit Size & Provider, etc.)."
        )


def probe_node_custom_property_values(node: str, username: str, password: str):
    _print_header(f"STEP 3 — Orion.NodesCustomProperties values for '{node}'")
    swql = f"""
SELECT *
FROM Orion.NodesCustomProperties
WHERE Caption = '{node}' OR Caption LIKE '%{node}%'
"""
    try:
        rows = solarwinds.query(swql, username, password)
    except Exception as e:
        print(f"Query failed: {e}")
        return
    _print_rows(rows)


def main():
    username = os.getenv("SOLARWINDS_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SOLARWINDS_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    node = os.getenv("SW_DISCOVER_NODE", "").strip()

    if not os.getenv("SOLARWINDS_URL"):
        print("ERROR: SOLARWINDS_URL must be set (see .env.template).")
        sys.exit(1)
    if not username or not password:
        print("ERROR: SOLARWINDS_USERNAME/SOLARWINDS_PASSWORD (or DOMAIN_USERNAME/"
              "DOMAIN_PASSWORD) must be set.")
        sys.exit(1)
    if not node:
        print("ERROR: SW_DISCOVER_NODE is required — set it to a router Caption "
              "(or substring) you know has this site info filled in today.")
        sys.exit(1)

    probe_standard_node_fields(node, username, password)
    probe_custom_property_definitions(username, password)
    probe_node_custom_property_values(node, username, password)

    print()
    print("=" * 78)
    print("Done. Paste this whole output back so the real field names can be")
    print("mapped into the Bandwidth Utilization report instead of guesses.")
    print("=" * 78)


if __name__ == "__main__":
    main()
