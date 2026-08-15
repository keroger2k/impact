"""utils/swim_site_circuit.py — per-site WAN circuit lookup for SWIM
concurrency sizing.

SWIM's per-site concurrency (utils/swim_scheduler.py) exists to avoid
saturating a site's WAN circuit while an IOS image is distributed.
Historically that cap was one flat, operator-typed number for the whole job;
this module derives it per site instead, from that site's actual WAN circuit
speed.

Originally sourced from SolarWinds (Orion's polled interface Speed). Switched
to DNAC's cached running-config instead after this org disabled domain-account
login to SolarWinds, which broke every per-user AD-credentialed SolarWinds
call in this app (see clients/solarwinds.py) — DNAC access was unaffected, and
this app already depends on DNAC being reachable for the rest of the SWIM
feature to function at all, so it isn't a new dependency. The two sources are
actually measuring the same underlying fact by different routes: for a
logical interface like a GRE/DMVPN tunnel with no physical line rate, IOS's
SNMP agent reports the interface's configured `bandwidth <kbps>` value as
ifSpeed/ifHighSpeed — which is exactly what SolarWinds' Orion.NPM.Interfaces.
Speed was reading. Reading the `bandwidth` line straight out of the device's
own running-config (already cached for config-search/device-detail under the
same `config_{device_id}` key, see routers/dnac.py) removes a layer of
indirection rather than approximating a different signal. If SolarWinds
access is restored later, re-adding it as an alternate/fallback source is a
reasonable follow-up, but isn't built here — see utils/bandwidth_report.py
for the SolarWinds-based interface-lookup precedent this module was
originally modeled on.

Runs once, at job-creation time (routers/swim.py::create_job) — not a
background poller, and never re-resolved on job resume, matching how
utils/device_sites.py already snapshots a device's site_code once rather
than re-deriving it live.

Every failure mode collapses to the same unconditional, deliberately
un-clever fallback: concurrency 1. This module never raises and never
reports a concurrency higher than what an explicit `bandwidth` line in a
real running-config actually backs up — a wrong guess here means silently
oversubscribing the WAN circuit this whole feature exists to protect.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

import clients.dnac as dnac_client
from cache import cache
from utils.bandwidth_report import bare_interface_name
from utils.device_sites import resolve_site_code
from utils.ipsec_parser import _RE_INTERFACE, _block_lines, _iter_blocks
from utils.swim_scheduler import _SITE_CONCURRENCY_CEILING

logger = logging.getLogger(__name__)

# Caps how many sites' config lookups run at once for one job-creation call —
# a job spanning many distinct sites shouldn't queue unbounded blocking calls
# (DNAC config fetches) onto the shared default executor used app-wide for
# DNAC/SSH/etc.
_LOOKUP_FANOUT_LIMIT = int(os.getenv("SWIM_CIRCUIT_LOOKUP_CONCURRENCY", "15"))

# Same cache key format routers/dnac.py already uses for the device-detail
# config viewer and config-search — sharing it means a config already warmed
# by either of those pays no second DNAC round trip here, and vice versa.
_CONFIG_CACHE_TTL = 600


def _config_cache_key(device_id: str) -> str:
    return f"config_{device_id}"


FALLBACK_CONCURRENCY = 1

# Starting guideline — a plain constant, not env vars: this is a
# business-logic guess meant to be tuned by a developer after real-world
# validation, not a per-deployment operational knob. (min_mbps, concurrency);
# the highest tier whose threshold the circuit meets or exceeds wins.
_CONCURRENCY_TIERS: list[tuple[float, int]] = [
    (0.0, 1),                             # < 25 Mbps — these sites are live/in-use,
    (10.0, 1),                            # not down for maintenance, so anything under
                                           # 25 Mbps stays at 1 device at a time even
                                           # alongside normal production traffic.
    (25.0, 3),                            # 25-50 Mbps
    (50.0, 5),                            # 50-100 Mbps
    (100.0, _SITE_CONCURRENCY_CEILING),   # 100+ Mbps
]

_TUNNEL_RE = re.compile(r"^(?:Tunnel|Tu)\d+$", re.IGNORECASE)
_BANDWIDTH_RE = re.compile(r"^bandwidth\s+(\d+)\s*$", re.IGNORECASE)

# Sentinel utils/swim_targeting.py's snapshot_for_job() stamps onto a device
# whose site couldn't be resolved at all (see utils/device_sites.py) — never
# worth a config lookup, there's no site_code to match a router against.
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


def _tunnel_bandwidth_rows_from_config(config: str) -> list[dict]:
    """Every Tunnel*/Tu<N> interface in a running-config that carries an
    explicit `bandwidth <kbps>` line, shaped like the interface rows
    _pick_wan_interface() already expects (InterfaceCaption/InterfaceName,
    InterfaceSpeed in bps — bandwidth is configured in Kbit/sec) so that
    function needs no changes to work against config-derived data instead of
    SolarWinds rows. Reuses utils.ipsec_parser's generic IOS config
    block-walker (_iter_blocks/_block_lines/_RE_INTERFACE) rather than
    duplicating that parsing — it isn't actually IPsec-specific, just
    colocated with the module that needed it first.
    """
    if not config:
        return []
    lines = list(_iter_blocks(config))
    rows: list[dict] = []
    i = 0
    while i < len(lines):
        indent, stripped, _ = lines[i]
        if indent != 0:
            i += 1
            continue
        m = _RE_INTERFACE.match(stripped)
        if not m:
            i += 1
            continue
        name = m.group(1)
        children, i = _block_lines(lines, i + 1)
        if not _TUNNEL_RE.match(name):
            continue
        for line in children:
            bw = _BANDWIDTH_RE.match(line)
            if bw:
                rows.append({"InterfaceCaption": name, "InterfaceName": name, "InterfaceSpeed": int(bw.group(1)) * 1000})
                break
    return rows


def _router_devices_for_site(site_code: str, devices: list[dict], device_site_map: dict[str, str]) -> list[dict]:
    """DNAC-known devices at this site whose family is 'Routers' — the WAN
    router(s) whose config actually carries the site's circuit bandwidth.
    Searches the full devices cache, not just this job's targeted devices:
    a SWIM job might target only switches at a site whose WAN router isn't
    itself part of the job."""
    out = []
    for d in devices:
        if d.get("family") != "Routers":
            continue
        code, _source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
        if code == site_code:
            out.append(d)
    return out


def _lookup_one_site(site_code: str, devices: list[dict], device_site_map: dict[str, str], dnac) -> dict:
    """Synchronous, blocking — always called via run_in_executor. Never
    raises; every failure mode returns a dict with source != 'dnac-config'
    and concurrency == FALLBACK_CONCURRENCY."""
    routers = _router_devices_for_site(site_code, devices, device_site_map)
    if not routers:
        return {"concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "no-circuit-data"}

    rows: list[dict] = []
    for r in routers:
        device_id = r.get("id")
        try:
            config = cache.get_or_set(
                _config_cache_key(device_id),
                lambda did=device_id: dnac_client.get_device_config(dnac, did),
                _CONFIG_CACHE_TTL,
            )
        except Exception as e:
            logger.warning("swim_site_circuit: DNAC config fetch failed for device %s (site %s): %s", device_id, site_code, e)
            continue
        rows.extend(_tunnel_bandwidth_rows_from_config(config or ""))

    iface = _pick_wan_interface(rows)
    if iface is None:
        return {"concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "no-circuit-data"}

    mbps = (iface.get("InterfaceSpeed") or 0) / 1_000_000
    if mbps <= 0:
        return {"concurrency": FALLBACK_CONCURRENCY, "circuit_mbps": None, "source": "no-circuit-data"}

    return {
        "concurrency": _concurrency_for_mbps(mbps),
        "circuit_mbps": round(mbps, 1),
        "source": "dnac-config",
    }


async def resolve_site_concurrency(
    site_codes: list[str], dnac, devices: list[dict], device_site_map: dict[str, str],
) -> dict[str, dict]:
    """Resolve per-site concurrency for every distinct site_code in a job, in
    parallel. Never raises — a config-fetch failure for one or more sites
    must not block job creation, it just means those sites land on the
    concurrency-1 fallback.

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
            result = await loop.run_in_executor(
                None, lambda code=site_code: _lookup_one_site(code, devices, device_site_map, dnac)
            )
        return site_code, result

    results = await asyncio.gather(*(_resolve(code) for code in distinct))
    return dict(results)
