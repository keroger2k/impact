import logging
import asyncio
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import JSONResponse, Response, StreamingResponse
from auth import SessionEntry, require_auth
from utils.ipam_engine import IPAMEngine
from utils.ipam_export import generate_solarwinds_csv
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/refresh")
async def refresh_ipam(
    request: Request,
    sources: Optional[List[str]] = Query(None),
    session: SessionEntry = Depends(require_auth)
):
    # Ensure sources is a list if it's a Query object
    actual_sources = sources.default if hasattr(sources, "default") else sources

    async def generate():
        def emit(msg: str, type: str = "log"):
            return f"data: {json.dumps({'type': type, 'message': msg})}\n\n"

        engine = IPAMEngine()
        loop = asyncio.get_event_loop()

        yield emit(f"Starting discovery for sources: {actual_sources or 'ALL'}")

        # Load existing subnets if we are doing a partial refresh
        existing_tree = cache.get("ipam_tree")
        if sources and existing_tree:
             # This is a bit complex since we store the tree, not flat subnets.
             # For now, if partial refresh is requested, we still rebuild the whole tree
             # but only 'refresh' discovery for requested sources.
             # Better: IPAMEngine should probably support additive discovery or we store flat subnets.
             # For simplicity in this step, we just do selective discovery but result replaces all.
             pass

        # We redefine yield_progress to be usable
        progress_queue = asyncio.Queue()
        async def progress_callback(msg):
            await progress_queue.put(msg)

        # Run discovery in background
        discovery_task = asyncio.create_task(engine.discover_all(session, loop, sources=actual_sources, yield_progress=progress_callback))

        while not discovery_task.done() or not progress_queue.empty():
            try:
                msg = await asyncio.wait_for(progress_queue.get(), timeout=0.1)
                yield emit(msg)
            except asyncio.TimeoutError:
                continue

        await discovery_task

        yield emit("Building hierarchy tree...")
        engine.build_tree()

        tree_data = engine.get_tree()
        cache.set("ipam_tree", tree_data, ttl=3600*24)

        yield emit("Discovery complete!", type="complete")

    return StreamingResponse(generate(), media_type="text/event-stream")

@router.get("/tree")
async def get_ipam_tree(session: SessionEntry = Depends(require_auth)):
    tree_data = cache.get("ipam_tree")
    if not tree_data:
        return JSONResponse(status_code=404, content={"message": "No IPAM data found. Please run refresh."})
    return tree_data

@router.get("/debug")
async def debug_ipam_sources(session: SessionEntry = Depends(require_auth)):
    """Inspect raw cache data for IPAM sources — no network calls."""
    from cache import cache

    # ── Panorama ──────────────────────────────────────────────────────────────
    pan_ifaces = cache.get("pan_interfaces") or []
    pan_sample, pan_with_prefix, pan_without_prefix = [], 0, 0
    for dev in pan_ifaces:
        for iface in dev.get("interfaces", []):
            ipv4 = iface.get("ipv4") or ""
            has_prefix = "/" in ipv4
            if has_prefix:
                pan_with_prefix += 1
            else:
                pan_without_prefix += 1
            if len(pan_sample) < 15:
                pan_sample.append({
                    "hostname": dev.get("hostname"),
                    "iface": iface.get("name"),
                    "ipv4": ipv4 or "none",
                    "has_prefix": has_prefix,
                })

    # ── Nexus ─────────────────────────────────────────────────────────────────
    nex_ifaces = cache.get("nexus_interfaces") or []
    nex_sample, nex_with_ip, nex_na = [], 0, 0
    for iface in nex_ifaces:
        ipv4 = iface.get("ipv4_address") or "N/A"
        if ipv4 and ipv4 != "N/A":
            nex_with_ip += 1
        else:
            nex_na += 1
        if len(nex_sample) < 15:
            nex_sample.append({
                "hostname": iface.get("hostname"),
                "iface": iface.get("interface_name"),
                "ipv4": ipv4,
            })

    # ── DNAC ──────────────────────────────────────────────────────────────────
    devices = cache.get("devices") or []
    sites   = cache.get("sites") or []
    sitemap = cache.get("device_site_map") or {}

    # ── ACI ───────────────────────────────────────────────────────────────────
    aci_nodes = cache.get("aci_nodes") or {"imdata": []}

    # ── ipam_tree ────────────────────────────────────────────────────────────
    tree = cache.get("ipam_tree")
    tree_v4 = len(tree.get("ipv4", [])) if tree else 0
    tree_v6 = len(tree.get("ipv6", [])) if tree else 0

    # Count sources in the existing tree
    source_counts: dict = {}
    if tree:
        def _count_sources(nodes: list):
            for n in nodes:
                src = n.get("source", "Unknown")
                source_counts[src] = source_counts.get(src, 0) + 1
                _count_sources(n.get("children", []))
        _count_sources(tree.get("ipv4", []))
        _count_sources(tree.get("ipv6", []))

    return {
        "ipam_tree": {
            "cached": tree is not None,
            "v4_roots": tree_v4,
            "v6_roots": tree_v6,
            "source_counts": source_counts,
        },
        "dnac": {"devices_cached": len(devices), "sites_cached": len(sites), "sitemap_entries": len(sitemap)},
        "aci_nodes_cached": len(aci_nodes.get("imdata", [])),
        "panorama": {
            "devices_in_cache": len(pan_ifaces),
            "interfaces_with_prefix": pan_with_prefix,
            "interfaces_without_prefix": pan_without_prefix,
            "sample": pan_sample,
        },
        "nexus": {
            "interfaces_in_cache": len(nex_ifaces),
            "interfaces_with_ip": nex_with_ip,
            "interfaces_na": nex_na,
            "sample": nex_sample,
        },
    }


@router.get("/export")
async def export_ipam_csv(session: SessionEntry = Depends(require_auth)):
    tree_data = cache.get("ipam_tree")
    if not tree_data:
        return JSONResponse(status_code=404, content={"message": "No IPAM data found. Please run refresh."})

    # Flatten tree for CSV
    all_nodes = tree_data["ipv4"] + tree_data["ipv6"]
    csv_content = generate_solarwinds_csv(all_nodes)

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=solarwinds_ipam_import.csv"}
    )
