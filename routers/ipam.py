import logging
import asyncio
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from auth import SessionEntry, require_auth
from utils.ipam_engine import IPAMEngine
from utils.ipam_export import generate_solarwinds_csv
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/refresh")
async def refresh_ipam(request: Request, session: SessionEntry = Depends(require_auth)):
    engine = IPAMEngine()
    loop = asyncio.get_event_loop()

    # Run discovery
    await engine.discover_all(session, loop)
    # Build tree
    engine.build_tree()

    tree_data = engine.get_tree()
    # Store in DiskCache
    cache.set("ipam_tree", tree_data, ttl=3600*24) # Cache for 24 hours

    return {"status": "success", "message": "IPAM discovery complete"}

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
