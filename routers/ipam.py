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
    async def generate():
        def emit(msg: str, type: str = "log"):
            return f"data: {json.dumps({'type': type, 'message': msg})}\n\n"

        engine = IPAMEngine()
        loop = asyncio.get_event_loop()

        yield emit(f"Starting discovery for sources: {sources or 'ALL'}")

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
        discovery_task = asyncio.create_task(engine.discover_all(session, loop, sources=sources, yield_progress=progress_callback))

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
    """
    Run a quick per-source discovery and report exactly what was found,
    what was excluded, and why. Does NOT rebuild the ipam_tree cache.
    """
    import netaddr
    from utils.ipam_engine import IPAMEngine, EXCLUDED_RANGES, HA_PATTERNS, PRIVATE_RANGES
    from cache import cache

    loop = asyncio.get_event_loop()
    engine = IPAMEngine()

    report = {}
    for source in ["aci", "dnac", "panorama", "nexus", "ise"]:
        before = len(engine.subnets)
        try:
            method = {
                "aci": engine._discover_aci,
                "dnac": engine._discover_dnac,
                "panorama": engine._discover_panorama,
                "nexus": engine._discover_nexus,
                "ise": engine._discover_ise,
            }[source]
            await method(session, loop)
        except Exception as e:
            report[source] = {"error": str(e), "found": 0, "samples": []}
            continue

        new_subnets = engine.subnets[before:]
        report[source] = {
            "found": len(new_subnets),
            "samples": [
                {"cidr": s.cidr, "device": s.device, "site": s.site, "display_name": s.display_name}
                for s in new_subnets[:10]
            ],
        }

    # Also report raw cache state
    pan_ifaces = cache.get("pan_interfaces") or []
    nex_ifaces = cache.get("nexus_interfaces") or []

    pan_summary = []
    for dev in pan_ifaces[:3]:
        for iface in dev.get("interfaces", [])[:3]:
            pan_summary.append({
                "hostname": dev.get("hostname"),
                "iface": iface.get("name"),
                "ipv4": iface.get("ipv4"),
                "has_prefix": "/" in (iface.get("ipv4") or ""),
            })

    nex_summary = [
        {"hostname": i.get("hostname"), "iface": i.get("interface_name"), "ipv4": i.get("ipv4_address")}
        for i in nex_ifaces[:10]
    ]

    return {
        "discovery": report,
        "raw_pan_interfaces_sample": pan_summary,
        "raw_nexus_interfaces_sample": nex_summary,
        "pan_interfaces_total": len(pan_ifaces),
        "nexus_interfaces_total": len(nex_ifaces),
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
