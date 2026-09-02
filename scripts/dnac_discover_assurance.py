#!/usr/bin/env python3
"""scripts/dnac_discover_assurance.py — is Catalyst Center's Assurance data
available on this instance?

Read-only reconnaissance. `docs/ROADMAP.md` lists DNAC Assurance as the
largest untapped API surface ("Device health, client health, site health
endpoints", P1), and today `clients/dnac.py` uses exactly one piece of it:
`get_recent_issues()` against `/dna/intent/api/v1/issues`.

That matters for scripts/site_experience_report.py. That report scores user
experience by inference — ICMP round-trip to a router's management IP,
correlated against WAN utilisation. It works, and it needs nothing new, but
it is a proxy. Assurance, *if licensed and receiving telemetry*, holds the
real thing:

  * `/dna/intent/api/v1/application-health` — per-application health score
    with latency, jitter and packet loss, per site. This is as close to
    "what is the user's experience of Teams at this site" as any API in the
    estate gets, and it is per-application rather than per-circuit.
  * `/dna/intent/api/v1/client-health` — client health scores, i.e. the
    experience measured at the endpoint rather than at the router.
  * `/dna/intent/api/v1/site-health` — per-site rollup.
  * `/dna/intent/api/v1/network-health` — device-side health over time.

The catch, and the reason this is a probe rather than a feature: all of it
depends on Assurance licensing plus telemetry actually being configured
(NetFlow/AVC export to DNAC for application health, in particular). A branch
router that isn't exporting will return a well-formed empty response, which
is indistinguishable from "no problems" unless you go looking. So this asks
before anything is built on it.

Every call is a GET. Full response bodies are printed on both success and
failure — same reason scripts/solarwinds_discover_site_properties.py bypasses
its own client wrapper: an error body names the real problem (unlicensed vs.
unsupported version vs. bad parameter), and those three need different
responses from us.

Usage:
    .venv/bin/python -m scripts.dnac_discover_assurance
    .venv/bin/python -m scripts.dnac_discover_assurance --site K114
    .venv/bin/python -m scripts.dnac_discover_assurance --hours 24 --full
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

import clients.dnac as dc  # noqa: E402

logger = logging.getLogger("dnac_discover_assurance")

# (label, path, extra params). Windowed endpoints get startTime/endTime added.
# siteId is added where the endpoint accepts it and --site resolved.
_ENDPOINTS = [
    ("site-health", "/dna/intent/api/v1/site-health", {}, False),
    ("network-health", "/dna/intent/api/v1/network-health", {}, False),
    ("client-health", "/dna/intent/api/v1/client-health", {}, False),
    ("application-health", "/dna/intent/api/v1/application-health", {}, True),
    # Newer data-API surface; present only on recent Catalyst Center versions.
    # A 404 here is informative, not a failure.
    ("assurance-events", "/dna/data/api/v1/assuranceEvents", {"limit": 5}, True),
]

_PREVIEW_KEYS = [
    "siteName", "siteId", "name", "applicationName", "healthScore", "health",
    "latency", "jitter", "packetLoss", "clientCount", "usage", "trafficClass",
    "businessRelevance", "networkDeviceCount", "goodCount", "poorCount", "fairCount",
]


def _print_header(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _call(dnac, path: str, params: dict) -> tuple[object | None, str | None]:
    """One GET via custom_caller, returning (payload, error_text).

    custom_caller is used rather than a typed SDK method because these
    endpoints move between SDK versions and several have no binding at all;
    clients/dnac.py already reaches for it for the same reason
    (`get_recent_issues`, `paginated_get`).
    """
    try:
        resp = dnac.custom_caller.call_api("GET", path, params=params)
        return getattr(resp, "response", resp), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _summarise(payload) -> None:
    if payload is None:
        print("(no payload)")
        return
    if isinstance(payload, dict):
        items = payload.get("response", payload)
    else:
        items = payload
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        print(json.dumps(items, indent=2, default=str)[:2000])
        return
    if not items:
        # The response every un-telemetried instance gives, and the whole
        # reason this script exists: it is not an error, and it looks exactly
        # like "everything is fine".
        print("EMPTY RESPONSE — the endpoint exists and answered, but returned no rows.")
        print("  That is what an unlicensed or un-telemetried instance looks like; it is")
        print("  NOT the same as 'no problems'. Check Assurance licensing and whether the")
        print("  site's devices are exporting telemetry before reading anything into it.")
        return

    print(f"{len(items)} item(s). First item's keys:")
    first = items[0]
    if isinstance(first, dict):
        print(f"  {sorted(first.keys())}")
        interesting = {k: first[k] for k in _PREVIEW_KEYS if k in first}
        if interesting:
            print("  Fields relevant to a user-experience score:")
            for k, v in interesting.items():
                print(f"    {k}: {v}")
    print()
    print(json.dumps(items[0], indent=2, default=str)[:1500])


def probe(dnac, label: str, path: str, extra: dict, windowed: bool,
          site_id: str | None, hours: int, full: bool) -> bool:
    _print_header(f"{label}  —  GET {path}")
    params = dict(extra)
    if windowed:
        end = int(time.time() * 1000)
        params["startTime"] = end - hours * 3600 * 1000
        params["endTime"] = end
    if site_id:
        params["siteId"] = site_id
    print(f"params: {params}\n")

    payload, err = _call(dnac, path, params)
    if err:
        print(f"FAILED — {err}")
        print("  A 404 means this version has no such endpoint. A 403 usually means")
        print("  Assurance is not licensed. A 400 usually means a parameter this")
        print("  version does not accept — the message normally names it.")
        return False

    if full:
        print(json.dumps(payload, indent=2, default=str)[:8000])
    else:
        _summarise(payload)
    return True


def resolve_site_id(dnac, term: str) -> str | None:
    """Site id for a hierarchy substring, preferring the shallowest match.

    Same preference and same reason as
    scripts/wan_qos_report.find_best_site_match_prefer_shallow: a Floor's path
    always substring-matches whenever its parent Building does, and this fleet
    floor-assigns only APs.
    """
    from scripts.wan_qos_report import find_best_site_match_prefer_shallow
    site_id, site_name = find_best_site_match_prefer_shallow(dc.get_site_cache(dnac), term)
    if site_id:
        logger.info("Site '%s' resolved to: %s (%s)", term, site_name, site_id)
    else:
        logger.warning("No site matching '%s' — probing without a site filter", term)
    return site_id


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--site", help="Scope the probe to this site (DNAC hierarchy substring)")
    ap.add_argument("--hours", type=int, default=24,
                    help="Window for the time-scoped endpoints (default: 24)")
    ap.add_argument("--full", action="store_true",
                    help="Print whole response bodies rather than a summary")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S",
    )
    if not args.verbose:
        logging.getLogger("clients.dnac").setLevel(logging.WARNING)

    dnac = dc.get_client()
    site_id = resolve_site_id(dnac, args.site) if args.site else None

    ok = 0
    for label, path, extra, windowed in _ENDPOINTS:
        if probe(dnac, label, path, extra, windowed, site_id, args.hours, args.full):
            ok += 1

    print()
    print("=" * 78)
    print(f"Done. {ok} of {len(_ENDPOINTS)} endpoints answered.")
    print()
    print("What to take from this:")
    print("  * If application-health returned rows WITH latency/jitter/packetLoss")
    print("    fields populated, that is a materially better user-experience signal")
    print("    than the ICMP proxy site_experience_report uses today — it is")
    print("    per-application and measured on the real traffic. Worth building on.")
    print("  * If it answered but came back EMPTY, Assurance is reachable but not")
    print("    receiving telemetry from these devices. That is a config project, not")
    print("    a code one, and nothing should be built on it until it is fixed.")
    print("  * If it 403'd or 404'd, the module is not licensed or this version")
    print("    predates the endpoint. Stay on the SolarWinds correlation.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
