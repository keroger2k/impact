"""routers/cache_mgmt.py — cache status UI + the single refresh endpoint.

Everything here derives from the dataset registry in datasets.py: the sidebar
widget, the Cache Management cards, and POST /api/cache/refresh/{dataset}.
"""

import asyncio
import logging
import time
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from auth import require_auth, SessionEntry
from cache import cache
from datasets import (
    DATASETS,
    dataset_count_key,
    refresh_dataset,
    _refresh_dnac,
    _refresh_ise,
    _refresh_panorama,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_time(ts: float | None) -> str:
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_age(ts: float | None) -> str:
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 60:
        return f"{int(age)}s ago"
    if age < 3600:
        return f"{int(age / 60)}m ago"
    if age < 86400:
        return f"{int(age / 3600)}h ago"
    return f"{int(age / 86400)}d ago"


def _count_cached(key: str) -> int:
    data = cache.get_stale(key)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        if "ipv4" in data and "ipv6" in data:
            return len(data.get("ipv4", [])) + len(data.get("ipv6", []))
        if "imdata" in data:
            return len(data["imdata"])
        return len(data)
    return 0


def _dataset_status(ds: dict) -> dict:
    # A dataset is "warm" whenever its primary key is *physically present* in
    # the cache — even if logically expired — because stale-while-revalidate
    # keeps that data usable and refreshes it in the background. Only a
    # never-loaded primary is "empty" (red).
    count_key = dataset_count_key(ds)
    primary_info = cache.cache_info(count_key) if count_key else None
    present = primary_info is not None
    stale = present and primary_info["is_expired"]
    set_at = primary_info["set_at"] if primary_info else None

    return {
        **ds,
        "key": ds["id"],
        "count": _count_cached(count_key) if count_key else 0,
        "status": "warm" if present else "empty",
        "stale": stale,
        "set_at": _fmt_time(set_at),
        "age": _fmt_age(set_at),
        "sse": ds["kind"] == "collect",
        "is_expired": stale,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status", response_class=HTMLResponse)
async def get_cache_status(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates
    cards = [_dataset_status(ds) for ds in DATASETS]
    return templates.TemplateResponse(request, "partials/cache_cards.html", {"cards": cards})


@router.get("/widget", response_class=HTMLResponse)
async def get_cache_widget(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates
    systems = [_dataset_status(ds) for ds in DATASETS]
    return templates.TemplateResponse(request, "partials/cache_widget.html", {"systems": systems})


@router.post("/refresh/{dataset_id}")
async def refresh_specific_cache(dataset_id: str, request: Request,
                                 session: SessionEntry = Depends(require_auth)):
    """Refresh one dataset (or `clear_all`). Behavior is driven by the registry."""
    if dataset_id == "clear_all":
        from dev import DEV_MODE, seed_cache
        cache.clear()
        if DEV_MODE:
            # The platforms aren't reachable in dev — restore the mock fixtures
            # instead of letting the refetchers spray connection errors.
            seed_cache(cache)
            msg = "Cache cleared and re-seeded with dev fixtures."
        else:
            # Re-warm in the background so the app isn't left fully cold — a cold
            # miss still blocks the first reader (stale-while-revalidate only helps
            # once a value exists), so kick the API-backed systems off immediately.
            # ACI re-warms lazily on visit; Nexus/F5/IPAM need an explicit Collect.
            asyncio.create_task(_refresh_dnac(session))
            asyncio.create_task(_refresh_ise(session))
            asyncio.create_task(_refresh_panorama(session))
            msg = "Full application cache has been cleared and is re-warming in the background."
    else:
        msg = await refresh_dataset(dataset_id, session,
                                    fabric=request.query_params.get("fabric"))
        if msg is None:
            return HTMLResponse(f"""
                <div class="alert alert-warning alert-dismissible fade show mb-0" role="alert">
                    Unknown dataset: {dataset_id}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            """, status_code=404)

    return HTMLResponse(f"""
        <div class="alert alert-success alert-dismissible fade show mb-0" role="alert">
            <strong>Done.</strong> {msg}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    """)
