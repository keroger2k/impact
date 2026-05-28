"""routers/site.py — Per-site rollup endpoints.

Given a site code (K023, SDCZ, …), aggregate every per-site data
source the platform already collects:

  * DNAC site hierarchy match
  * Devices (DNAC + Nexus + Panorama, joined by site_code)
  * Routing protocol detection (BGP/OSPF/EIGRP) via config-grep on the
    cached running-configs; the per-protocol panels are lazy-loaded by
    htmx hitting the existing /api/routing/ endpoints
  * IPAM (DNAC reserve subpools attributed to this site)
  * IPv6 registry (site row + vvvv allocations) — name-match, best-effort
  * Tunnels (filtered by local_site_code in the normalized inventory)

Every helper is a pure cache read. The "overview" endpoint runs them in
parallel inside a thread executor so a cold cache doesn't serialize the
work.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Request

from auth import SessionEntry, require_auth
from templates_module import templates
from utils import site_aggregator as agg

router = APIRouter()
logger = logging.getLogger(__name__)


def _overview(code: str) -> dict:
    """Synchronous bundle of every section's data. Called from a thread
    executor so the per-section cache reads (including SQLite I/O for
    the IPv6 registry) don't block the event loop."""
    resolved = agg.resolve_site(code)
    devices = agg.list_devices_for_site(code)
    routing = agg.routing_devices(devices)
    ipv6 = agg.ipv6_for_site(code)
    tunnels = agg.tunnels_for_site(code, site_devices=devices)

    by_source = {"DNAC": 0, "Nexus": 0, "Panorama": 0}
    by_role: dict[str, int] = {}
    for d in devices:
        by_source[d["source"]] = by_source.get(d["source"], 0) + 1
        role = d.get("role") or "UNKNOWN"
        by_role[role] = by_role.get(role, 0) + 1

    return {
        "code": resolved["code"],
        "hierarchies": resolved["hierarchies"],
        "devices": devices,
        "routing_devices": routing,
        "ipv6": ipv6,
        "tunnels": tunnels,
        "stats": {
            "device_count": len(devices),
            "by_source": by_source,
            "by_role": by_role,
            "routing_device_count": len(routing),
            "tunnel_count": len(tunnels),
            "ipv6_present": ipv6 is not None,
        },
    }


@router.get("/overview/{code}")
async def get_overview(
    request: Request,
    code: str,
    session: SessionEntry = Depends(require_auth),
):
    """Main site rollup. Returns the full content partial when HX-Request
    is set (htmx swap), or JSON otherwise."""
    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, _overview, code)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "partials/site_overview.html",
            {**data, "code_input": code},
        )
    return data
