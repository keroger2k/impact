import json
import logging
import asyncio
import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from auth import SessionEntry, require_auth
from cache import cache
import clients.nexus as nexus_client

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/cache/info")
async def nexus_cache_info():
    return {
        "inventory": cache.cache_info("nexus_inventory"),
        "interfaces": cache.cache_info("nexus_interfaces"),
    }

@router.post("/cache/refresh")
async def refresh_nexus_cache(session: SessionEntry = Depends(require_auth)):
    """Force full Nexus cache refresh via SSH. Streams SSE progress."""

    async def generate():
        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        username = os.getenv("DOMAIN_USERNAME")
        password = os.getenv("DOMAIN_PASSWORD")

        if not username or not password:
            yield emit({"type": "log", "level": "error", "message": "Missing DOMAIN_USERNAME or DOMAIN_PASSWORD env vars"})
            return

        async def progress_callback(data):
            yield emit(data)

        try:
            inventory, interfaces, configs = await nexus_client.collect_all_nexus(
                username, password, progress_callback=progress_callback
            )

            # Cache the results (TTL: 7 days)
            TTL = 604800
            cache.set("nexus_inventory", inventory, TTL)
            cache.set("nexus_interfaces", interfaces, TTL)
            for ip, cfg in configs.items():
                cache.set(f"nexus_config_{ip}", cfg, TTL)

            yield emit({"type": "log", "level": "info", "message": f"Successfully cached {len(inventory)} devices"})
            yield emit({"type": "complete", "count": len(inventory)})

        except Exception as e:
            logger.error(f"Nexus refresh failed: {e}")
            yield emit({"type": "log", "level": "error", "message": f"Refresh failed: {str(e)}"})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
