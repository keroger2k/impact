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
     (Location, Contact, Description) — some of this site info may already
     be sitting in plain node fields. Kept to the handful of columns present
     on every Orion install; a first pass tried more (Vendor, MachineType,
     SysName, Comments) and got a 400 from one of them.
  2. Orion.CustomProperty — the metadata table listing every custom property
     configured anywhere in this SolarWinds instance (no TargetEntity filter,
     so we can see the *actual* TargetEntity strings this install uses rather
     than assuming 'Orion.Nodes' is the right literal — and confirm whether
     any node-targeted custom properties exist at all).
  3. Orion.NodesCustomProperties for the sample router — the actual node-level
     custom property values, to cross-reference against step 2's field names.
  4. Orion.NPM.InterfacesCustomProperties for that router's interfaces —
     circuit info (CarrierName/CircuitID/Bandwith_Utilization) lives here,
     not on the node, since a circuit is naturally per-interface.

This talks to the SWIS endpoint directly with raw requests (rather than
clients.solarwinds.query(), which calls raise_for_status() and discards the
response body) because SolarWinds' SWQL validation errors on a 400 usually
name the exact invalid field/entity in the body — that's the fastest way to
fix a bad query, same reasoning as scripts/sna_discover.py's raw-response
printing. Confirmed empirically: SWQL's SELECT clause rejects `*` outright
("no viable alternative at input '*'") — every SELECT here lists columns
explicitly.

Nothing here writes anything — every query is a plain SWQL SELECT. Run it
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
    SOLARWINDS_VERIFY_SSL       default false (self-signed certs)
    SW_DISCOVER_NODE            required — a router Caption (or substring) to
                                 sample, e.g. a router you know has this site
                                 info filled in today

Usage:
    python -m scripts.solarwinds_discover_site_properties
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


def _print_rows(rows: list[dict], max_rows: int = 40):
    if not rows:
        print("(no rows returned)")
        return
    print(f"{len(rows)} row(s){' — showing first ' + str(max_rows) if len(rows) > max_rows else ''}:")
    for row in rows[:max_rows]:
        print(json.dumps(row, indent=2, default=str))


def run_query(swql: str, username: str, password: str, verify_ssl: bool, timeout: int) -> list[dict] | None:
    """POST a SWQL SELECT and return result rows, or None on failure — prints
    the full response body either way, since a 400's body usually names the
    exact invalid field/entity."""
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
        # SWIS validation errors are plain text or a small JSON envelope
        # naming the bad field/entity — print it raw, don't swallow it.
        print(resp.text[:3000])
        return None

    try:
        return resp.json().get("results", [])
    except ValueError:
        print("200 but not JSON — raw body:")
        print(resp.text[:2000])
        return None


def probe_standard_node_fields(node: str, username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header(f"STEP 1 — Standard Orion.Nodes fields for '{node}'")
    swql = f"""
SELECT NodeID, Caption, IPAddress, Location, Contact, Description
FROM Orion.Nodes
WHERE Caption = '{node}' OR Caption LIKE '%{node}%'
"""
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return
    _print_rows(rows)
    if rows:
        print(
            "\nLook at Location/Contact/Description above — these are free-text "
            "standard fields commonly (ab)used for exactly this kind of site "
            "metadata, worth checking before assuming custom properties."
        )


def probe_custom_property_definitions(username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header("STEP 2 — All custom property definitions (no entity filter)")
    swql = """
SELECT Field, DataType, TargetEntity, Description
FROM Orion.CustomProperty
ORDER BY TargetEntity, Field
"""
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return
    _print_rows(rows, max_rows=200)
    if rows:
        entities = sorted({r.get("TargetEntity") for r in rows if r.get("TargetEntity")})
        print(f"\nDistinct TargetEntity values seen: {entities}")
        print(
            "Match the Field names above (for whichever TargetEntity holds node "
            "data — often 'Orion.Nodes' but confirm from the list) against the "
            "report's fields (Site Code, Airport Code, Category, Building, "
            "Type, Local POC, FRM, Circuit Size & Provider, etc.)."
        )
    else:
        print("\nNo custom properties are configured anywhere in this SolarWinds "
              "instance — this site info isn't stored as a SolarWinds custom "
              "property. Check STEP 1's standard fields, or it may not live in "
              "SolarWinds at all.")


def probe_node_custom_property_values(node: str, username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header(f"STEP 3 — Orion.NodesCustomProperties values for '{node}'")
    # SWQL rejects `SELECT *` — explicit columns only. Narrowed to the fields
    # from STEP 2's list that plausibly map to the report (dropped SLA*,
    # STIP, TAZ, DC15, FISMA, Imported_From_NCM, AssetTag, Application,
    # Country, CDRL118, device_description, FieldSite, Region, ServiceProvider
    # as unlikely for this specific report).
    swql = f"""
SELECT NodeID, Caption, Address, Airport_Code, AirportCategory, Building,
       Carrier, City, State, ZipCode, ContactName, Contract_Vehicle, Site,
       TSADeviceCode, Comments
FROM Orion.NodesCustomProperties
WHERE Caption = '{node}' OR Caption LIKE '%{node}%'
"""
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return
    _print_rows(rows)


def probe_interface_custom_property_values(node: str, username: str, password: str, verify_ssl: bool, timeout: int):
    _print_header(f"STEP 4 — Orion.NPM.InterfacesCustomProperties for '{node}''s interfaces")
    swql = f"""
SELECT i.InterfaceID, i.Caption AS InterfaceCaption, i.Name AS InterfaceName,
       cp.Carrier, cp.CarrierName, cp.CircuitID, cp.Bandwith_Utilization, cp.Comments
FROM Orion.NPM.Interfaces i
JOIN Orion.Nodes n ON i.NodeID = n.NodeID
JOIN Orion.NPM.InterfacesCustomProperties cp ON cp.InterfaceID = i.InterfaceID
WHERE n.Caption = '{node}' OR n.Caption LIKE '%{node}%'
"""
    rows = run_query(swql, username, password, verify_ssl, timeout)
    if rows is None:
        return
    _print_rows(rows)
    if rows:
        print(
            "\nCircuit Size & Provider is likely built from CarrierName/CircuitID/"
            "Bandwith_Utilization on whichever interface here is the WAN circuit "
            "(often Tunnel5000 or the physical WAN-facing interface, not every "
            "row above)."
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
        print("ERROR: SW_DISCOVER_NODE is required — set it to a router Caption "
              "(or substring) you know has this site info filled in today.")
        sys.exit(1)

    probe_standard_node_fields(node, username, password, verify_ssl, timeout)
    probe_custom_property_definitions(username, password, verify_ssl, timeout)
    probe_node_custom_property_values(node, username, password, verify_ssl, timeout)
    probe_interface_custom_property_values(node, username, password, verify_ssl, timeout)

    print()
    print("=" * 78)
    print("Done. Paste this whole output back so the real field names can be")
    print("mapped into the Bandwidth Utilization report instead of guesses.")
    print("=" * 78)


if __name__ == "__main__":
    main()
