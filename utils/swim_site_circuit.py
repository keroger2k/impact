"""utils/swim_site_circuit.py — per-site WAN circuit lookup for SWIM
concurrency sizing.

SWIM's per-site concurrency (utils/swim_scheduler.py) exists to avoid
saturating a site's WAN circuit while an IOS image is distributed.
Historically that cap was one flat, operator-typed number for the whole job;
this module derives it per site instead, from that site's actual
SolarWinds-reported circuit speed — reusing the same Site custom-property
join and Tunnel5000 interface convention the Bandwidth Utilization report
already established (utils/bandwidth_report.py), rather than inventing a
second way to talk to SolarWinds.

Runs once, at job-creation time (routers/swim.py::create_job) — not a
background poller, and never re-resolved on job resume, matching how
utils/device_sites.py already snapshots a device's site_code once rather
than re-deriving it live.

Every failure mode collapses to the same unconditional, deliberately
un-clever fallback: concurrency 1. This module never raises and never
reports a concurrency higher than what a real Speed value from Orion
actually backs up — a wrong guess here means silently oversubscribing the
WAN circuit this whole feature exists to protect.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

import clients.solarwinds as solarwinds
from utils.bandwidth_report import _SITE_INFO_JOIN, _SITE_INFO_SELECT, _escape_literal, bare_interface_name
from utils.swim_scheduler import _SITE_CONCURRENCY_CEILING

logger = logging.getLogger(__name__)

# Short timeout — this backs an interactive job-creation request the operator
# is waiting on, not a report build. Mirrors bandwidth_report._DROPDOWN_TIMEOUT.
_LOOKUP_TIMEOUT = int(os.getenv("SWIM_CIRCUIT_LOOKUP_TIMEOUT", "20"))

# Caps how many SolarWinds lookups run at once for one job-creation call — a
# job spanning many distinct sites shouldn't queue unbounded blocking calls
# onto the shared default executor (used app-wide for DNAC/SSH/etc.), each
# burning the full timeout during a SolarWinds outage.
_LOOKUP_FANOUT_LIMIT = int(os.getenv("SWIM_CIRCUIT_LOOKUP_CONCURRENCY", "15"))

FALLBACK_CONCURRENCY = 1

# Starting guideline — a plain constant, not env vars: this is a
# business-logic guess meant to be tuned by a developer after real-world
# validation, not a per-deployment operational knob. (min_mbps, concurrency);
# the highest tier whose threshold the circuit meets or exceeds wins.
_CONCURRENCY_TIERS: list[tuple[float, int]] = [
    (0.0, 1),                             # < 10 Mbps
    (10.0, 2),                            # 10-25 Mbps
    (25.0, 3),                            # 25-50 Mbps
    (50.0, 5),                            # 50-100 Mbps
    (100.0, _SITE_CONCURRENCY_CEILING),   # 100+ Mbps
]

_TUNNEL_RE = re.compile(r"^(?:Tunnel|Tu)\d+$", re.IGNORECASE)

# Sentinel utils/swim_targeting.py's snapshot_for_job() stamps onto a device
# whose site couldn't be resolved at all (see utils/device_sites.py) — never
# worth a SolarWinds call, there's no site_code to match against.
_UNKNOWN_SITE = "UNKNOWN"


def _concurrency_for_mbps(mbps: float) -> int:
    concurrency = FALLBACK_CONCURRENCY
    for threshold, value in _CONCURRENCY_TIERS:
        if mbps >= threshold:
            concurrency = value
    return concurrency


def _pick_wan_interface(rows: list[dict]) -> dict | None:
    """Pick the one interface that represents this site's WAN circuit.

    Prefers an exact bare-named "Tunnel5000" match (the standard DMVPN
    hub-facing interface — see bandwidth_report.DEFAULT_INTERFACE), falling
    back to some other Tunnel*/Tu<N> interface only when there's exactly one
    candidate. Anything else — zero candidates, or 2+ at either step (e.g. a
    dual-router site with two live Tunnel5000s) — is genuinely ambiguous and
    returns None, which the caller folds into the same concurrency-1
    fallback as "no data at all". Deliberately never averages/sums/takes-
    the-max across multiple candidates: guessing wrong here directly
    oversubscribes the circuit this feature exists to protect.
    """
    named = [
        (r, bare_interface_name(r.get("InterfaceCaption") or r.get("InterfaceName") or ""))
        for r in rows
    ]

    exact = [r for r, name in named if name.lower() == "tunnel5000"]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None

    tunnels = [r for r, name in named if _TUNNEL_RE.match(name)]
    if len(tunnels) == 1:
        return tunnels[0]
    return None


def _lookup_one_site(site_code: str, username: str, password: str) -> dict:
    """Synchronous, blocking — always called via run_in_executor. Never
    raises; every failure mode returns a dict with source != 'solarwinds'
    and concurrency == FALLBACK_CONCURRENCY."""
    lit = _escape_literal(site_code)
    swql = f"""
SELECT{_SITE_INFO_SELECT}{_SITE_INFO_JOIN}
WHERE cp.Site = '{lit}'
"""
    try:
        rows = solarwinds.query(swql, username, password, timeout=_LOOKUP_TIMEOUT)
    except Exception as e:
        logger.warning("swim_site_circuit: SolarWinds lookup failed for site %s: %s", site_code, e)
        return {"concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "solarwinds-unreachable"}

    iface = _pick_wan_interface(rows)
    if iface is None:
        return {"concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "no-circuit-data"}

    speed = iface.get("InterfaceSpeed")
    try:
        mbps = float(speed) / 1_000_000 if speed not in (None, "") else None
    except (TypeError, ValueError):
        mbps = None
    if not mbps or mbps <= 0:
        return {"concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "no-circuit-data"}

    return {
        "concurrency": _concurrency_for_mbps(mbps),
        "circuit_mbps": round(mbps, 1),
        "source": "solarwinds",
    }


async def resolve_site_concurrency(site_codes: list[str], username: str, password: str) -> dict[str, dict]:
    """Resolve per-site concurrency for every distinct site_code in a job, in
    parallel. Never raises — a total SolarWinds outage must not block job
    creation, it just means every site lands on the concurrency-1 fallback.

    Returns one entry per input site_code (deduped), each shaped like
    _lookup_one_site()'s return value:
    {"concurrency": int, "circuit_mbps": float | None, "source": str}.
    """
    distinct = sorted(set(site_codes))
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(_LOOKUP_FANOUT_LIMIT)

    async def _resolve(site_code: str) -> tuple[str, dict]:
        if site_code == _UNKNOWN_SITE:
            return site_code, {
                "concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "unresolved-site",
            }
        async with sem:
            result = await loop.run_in_executor(None, lambda code=site_code: _lookup_one_site(code, username, password))
        return site_code, result

    results = await asyncio.gather(*(_resolve(code) for code in distinct))
    return dict(results)
