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

        # Helper for progress tracking
        async def yield_progress(msg):
             nonlocal loop
             # We can't directly yield from here as it's not the generator
             # But we are in the generator scope!
             pass

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
