#!/usr/bin/env python3
"""scripts/solarwinds_discover_quality.py — what latency/quality data does this
Orion instance actually hold?

Read-only reconnaissance for scripts/site_experience_report.py. That report
scores a site's user experience by correlating `Orion.ResponseTime` against
`Orion.NPM.InterfaceTraffic`, and those two entities are the *only* latency
sources anywhere in this codebase — `Orion.ResponseTime` because
utils/cdrl49_report.py proved it works, and interface traffic because
utils/bandwidth_report.py did. Everything adjacent is unexplored:

  * `Orion.ResponseTime` is only ever selected with four columns
    (ObservationTimestamp, AvgResponseTime, MaxResponseTime, Availability).
    Whether it also carries `PercentLoss` and `MinResponseTime` has never
    been checked, so site_experience_report requests them speculatively and
    retries without them on failure. Confirming settles that.
  * Nothing has ever checked whether this Orion has the IP SLA Manager
    (`Orion.IpSla.*`) or VoIP & Network Quality Manager (`Orion.VoIP.*`)
    modules. If it does, jitter, packet loss and MOS become queryable
    *historically and fleet-wide* — a far stronger user-experience signal
    than ICMP round-trip to a management IP, and it would not require SSH to
    each router the way parsing `show ip sla statistics` does.
  * Retention and rollup entities are unknown. `site_experience_report
    --days 30` may silently return a week of data. The rollup entities
    (hourly/daily) are where a longer window would come from.

This asks the instance directly rather than guessing, using the same
`Metadata.Entity` / `Metadata.Verb` / `Metadata.Property` introspection that
scripts/solarwinds_discover_maintenance_schedules.py established. Two quirks
carried over from that script's own hard-won corrections:

  * `Metadata.Entity`'s own column is `Name`. Using `EntityName` there 400s
    with "Cannot resolve property EntityName", while `Metadata.Verb` and
    `Metadata.Property` *do* use `EntityName` to point at what they describe.
  * `Metadata.Entity.Name` returns *bare* names ("ResponseTime"), but the
    other two need the fully-qualified form ("Orion.ResponseTime"). A bare
    name silently returns zero rows rather than erroring, which reads as
    "this entity has no columns" when it actually means "wrong name".

Nothing here writes anything — every query is a plain SWQL SELECT. It
bypasses clients.solarwinds.query() and posts with raw `requests` for the
same reason scripts/solarwinds_discover_site_properties.py does: that
wrapper truncates the error body, and a 400's body usually names the exact
invalid column, which is the fastest way to correct a bad guess.

Env (.env): SOLARWINDS_URL, SOLARWINDS_USERNAME, SOLARWINDS_PASSWORD,
optionally SOLARWINDS_PORT (17774), SOLARWINDS_DOMAIN (network),
SOLARWINDS_TIMEOUT, SOLARWINDS_VERIFY_SSL. SW_DISCOVER_NODE (a router
Caption) scopes the sample reads.

Usage:
    .venv/bin/python -m scripts.solarwinds_discover_quality
    .venv/bin/python -m scripts.solarwinds_discover_quality --node RTR-EXAMPLE-01
"""
from __future__ import annotations

import argparse
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

# Cast wide: we don't know what modules are licensed on this instance, and a
# name we didn't think of is exactly what this is looking for.
_NAME_PATTERNS = ["ResponseTime", "IpSla", "Sla", "VoIP", "Quality", "Jitter", "Latency"]

# Entities worth probing regardless of whether the name search finds them —
# ResponseTime because the report depends on it, the others because they are
# the documented names for the two modules that would carry real quality data.
_ALWAYS_PROBE = [
    "Orion.ResponseTime",
    "Orion.NPM.InterfaceTraffic",
    "Orion.IpSla.Operations",
    "Orion.IpSla.OperationResults",
    "Orion.VoIP.CallDetails",
]

# Columns site_experience_report requests speculatively. This script exists in
# large part to settle whether they are real.
_UNCONFIRMED_RESPONSETIME_COLUMNS = ["MinResponseTime", "PercentLoss"]


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
    return f"{os.getenv('SOLARWINDS_DOMAIN', 'network')}\\{username}"


def _print_header(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _print_rows(rows: list[dict], max_rows: int = 60) -> None:
    if not rows:
        print("(no rows returned)")
        return
    suffix = f" — showing first {max_rows}" if len(rows) > max_rows else ""
    print(f"{len(rows)} row(s){suffix}:")
    for row in rows[:max_rows]:
        print(json.dumps(row, indent=2, default=str))


def run_query(swql: str, username: str, password: str, verify_ssl: bool,
              timeout: int, quiet: bool = False) -> list[dict] | None:
    port = os.getenv("SOLARWINDS_PORT", "17774")
    endpoint = f"{_base_url()}:{port}/SolarWinds/InformationService/v3/Json/Query"
    if not quiet:
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

    if not quiet:
        print(f"← HTTP {resp.status_code}")
    if resp.status_code != 200:
        # The body is the whole point — it names the invalid column.
        print(f"← HTTP {resp.status_code}" if quiet else "")
        print(resp.text[:3000])
        return None
    try:
        return resp.json().get("results", [])
    except ValueError:
        print("200 but not JSON — raw body:")
        print(resp.text[:2000])
        return None


def probe_entities(username, password, verify_ssl, timeout) -> list[str]:
    _print_header("STEP 1 — Entities whose name suggests latency / SLA / quality")
    where = " OR ".join(f"Name LIKE '%{p}%'" for p in _NAME_PATTERNS)
    rows = run_query(f"SELECT Name FROM Metadata.Entity WHERE {where} ORDER BY Name",
                     username, password, verify_ssl, timeout)
    found: list[str] = []
    if rows is None:
        print("\nMetadata.Entity query failed — falling back to the always-probe list.")
    else:
        _print_rows(rows, max_rows=200)
        bare = sorted({r.get("Name") for r in rows if r.get("Name")})
        # Bare -> fully-qualified, or the follow-up probes silently 0-row.
        found = sorted({n if "." in n else f"Orion.{n}" for n in bare})
        print(f"\nBare names found: {bare}")
        print(
            "\nWhat to look for: an 'IpSla'-ish entity means the IP SLA Manager module "
            "is present, which would make jitter/loss/MOS queryable fleet-wide and "
            "historically — strictly better than the ICMP-to-management-IP proxy the "
            "experience report uses today, and it would remove the need to SSH each "
            "router to parse `show ip sla statistics`."
        )
    return sorted(set(found) | set(_ALWAYS_PROBE))


def probe_properties(entity, username, password, verify_ssl, timeout) -> list[str]:
    _print_header(f"STEP 2 — Columns on {entity}")
    rows = run_query(
        f"SELECT Uri, Name, Type FROM Metadata.Property WHERE EntityName = '{entity}' ORDER BY Name",
        username, password, verify_ssl, timeout,
    )
    if rows is None:
        return []
    if not rows:
        print(f"(no columns — {entity} probably does not exist on this instance, "
              f"i.e. that module is not installed/licensed)")
        return []
    _print_rows(rows, max_rows=200)
    names = [r.get("Name") for r in rows if r.get("Name")]

    if entity == "Orion.ResponseTime":
        print()
        for col in _UNCONFIRMED_RESPONSETIME_COLUMNS:
            verdict = "PRESENT" if col in names else "ABSENT"
            print(f"  {col}: {verdict}")
        print(
            "\n  scripts/site_experience_report.py requests both speculatively and "
            "retries without them on failure. If both are PRESENT, that retry path is "
            "dead code and packet loss can be reported directly instead of inferred "
            "from Availability."
        )
    return names


def probe_sample_rows(entity, columns, username, password, verify_ssl, timeout) -> None:
    _print_header(f"STEP 3 — Sample rows from {entity}")
    if not columns:
        print(f"No columns discovered for {entity} — skipping.")
        return
    # SWQL rejects SELECT * outright ("no viable alternative at input '*'").
    select_list = ", ".join(columns[:20])
    rows = run_query(f"SELECT TOP 5 {select_list} FROM {entity}",
                     username, password, verify_ssl, timeout)
    if rows is not None:
        _print_rows(rows, max_rows=5)


def probe_retention(node: str, username, password, verify_ssl, timeout) -> None:
    """How far back does Orion.ResponseTime actually go for one node?

    `site_experience_report --days 30` will silently return whatever exists;
    knowing the real retention is the difference between "this site got worse
    last month" and "there is no data from last month".
    """
    _print_header(f"STEP 4 — Response-time retention and sample interval for '{node}'")
    rows = run_query(f"""
SELECT TOP 1 N.NodeID, N.Caption
FROM Orion.Nodes N
WHERE N.Caption = '{node}' OR N.Caption LIKE '%{node}%'
""", username, password, verify_ssl, timeout)
    if not rows:
        print(f"\nNo node matched '{node}' — pass --node or set SW_DISCOVER_NODE.")
        return
    node_id = rows[0].get("NodeID")
    print(f"\nUsing NodeID {node_id} ({rows[0].get('Caption')})\n")

    agg = run_query(f"""
SELECT
    COUNT(RT.AvgResponseTime) AS Samples,
    MIN(RT.ObservationTimestamp) AS Oldest,
    MAX(RT.ObservationTimestamp) AS Newest
FROM Orion.ResponseTime RT
WHERE RT.NodeID = {node_id}
""", username, password, verify_ssl, timeout)
    if agg:
        _print_rows(agg)
        print(
            "\nDivide the sample count by the span to get the real polling interval. "
            "If it is coarser than site_experience_report's --bucket-minutes (15 by "
            "default), most buckets will hold a single sample and the p95 figures get "
            "noisy — raise the bucket size to match."
        )

    print()
    print("--- Newest 3 raw rows (check the timestamp's timezone against your wall clock) ---")
    raw = run_query(f"""
SELECT TOP 3 RT.ObservationTimestamp, RT.AvgResponseTime, RT.Availability
FROM Orion.ResponseTime RT
WHERE RT.NodeID = {node_id}
ORDER BY RT.ObservationTimestamp DESC
""", username, password, verify_ssl, timeout)
    if raw is not None:
        _print_rows(raw)
        print(
            "\nCRITICAL: compare that newest timestamp to the current UTC time. "
            "Orion.NPM.InterfaceTraffic.DateTime is UTC (it is filtered with "
            "GETUTCDATE() in utils/bandwidth_report.py), but nothing establishes "
            "what ObservationTimestamp is stored in. If they differ, every latency "
            "sample pairs against the wrong hour's utilisation. "
            "utils.experience.detect_series_offset corrects this automatically — this "
            "is how you confirm the correction it reports is the right one."
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node", default=os.getenv("SW_DISCOVER_NODE", ""),
                    help="Router Caption (or substring) to scope the sample reads to")
    args = ap.parse_args()

    username = os.getenv("SOLARWINDS_USERNAME", "")
    password = os.getenv("SOLARWINDS_PASSWORD", "")
    verify_ssl = _bool_env("SOLARWINDS_VERIFY_SSL", False)
    timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    if not _base_url() or not username or not password:
        print("ERROR: SOLARWINDS_URL, SOLARWINDS_USERNAME and SOLARWINDS_PASSWORD "
              "must be set in .env")
        return 1
    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    entities = probe_entities(username, password, verify_ssl, timeout)
    for entity in entities:
        columns = probe_properties(entity, username, password, verify_ssl, timeout)
        if columns:
            probe_sample_rows(entity, columns, username, password, verify_ssl, timeout)

    if args.node:
        probe_retention(args.node, username, password, verify_ssl, timeout)
    else:
        print("\n(Skipping STEP 4 — pass --node or set SW_DISCOVER_NODE to check "
              "retention, sample interval and timestamp timezone.)")

    print()
    print("=" * 78)
    print("Done. The three questions this was run to answer:")
    print("  1. Does Orion.ResponseTime have PercentLoss / MinResponseTime? (STEP 2)")
    print("  2. Is IP SLA Manager or VNQM present, i.e. are jitter/MOS queryable")
    print("     historically without SSHing every router? (STEP 1)")
    print("  3. What timezone is ObservationTimestamp in, and how far back does it")
    print("     go? (STEP 4)")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
