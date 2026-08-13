"""routers/swim.py — /api/swim/*: golden-image distribution/activation jobs
and the read-only compliance dashboard.

Two independent env flags gate the mutating surface — `SWIM_DISTRIBUTION_
ENABLED` and `SWIM_ACTIVATION_ENABLED` — checked per job_type, never a
single combined flag, since activation (a device reboot) is a materially
different risk tier than distribution (staging an image) and a site may
want one enabled without the other. Every handler that creates, starts, or
cancels a job re-checks the relevant flag independently (same three-layer
posture as SOLARWINDS_WRITES_ENABLED — see routers/pages.py for the matching
page-route checks). Compliance endpoints carry no gate; they're read-only.

Job creation/execution/cancellation reuse this codebase's established
patterns rather than inventing new ones:
  * SSE + bounded concurrency: the queue-drain pattern from
    routers/import_.py, generalized in utils/swim_scheduler.py to two
    concurrency levels (global + per-site).
  * Confirmation gate: a typed `confirm` string re-validated server-side,
    same mechanics as routers/commands.py's config-mode `"DEPLOY"` gate —
    but the activation phrase embeds the live device count
    (`"ACTIVATE <N> DEVICES"`) so it can't be typed from muscle memory.
  * Durable job state: clients/swim_jobs.py's SQLite registry, mirroring
    clients/ip_registry.py's conventions.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import auth as auth_module
import clients.swim as swim_client
import clients.swim_jobs as swim_jobs
import utils.swim_compliance as swim_compliance
import utils.swim_scheduler as swim_scheduler
import utils.swim_targeting as swim_targeting
from auth import SessionEntry, require_auth
from cache import TTL_STANDARD, cache
from logger_config import run_with_context
from utils.device_sites import resolve_site_code

router = APIRouter()
logger = logging.getLogger(__name__)

# Module-level, single-process claim that a job is actively executing —
# same in-memory-dict assumption main.py's SSE-concurrency tracker already
# makes (check-and-add happens with no await in between, so it's atomic
# under asyncio's single-threaded event loop without a lock).
_running_jobs: set[int] = set()


def _get_dnac(session: SessionEntry):
    try:
        return auth_module.get_dnac_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"DNAC connection failed: {e}")


def _distribution_enabled() -> bool:
    return os.getenv("SWIM_DISTRIBUTION_ENABLED", "false").lower() == "true"


def _activation_enabled() -> bool:
    return os.getenv("SWIM_ACTIVATION_ENABLED", "false").lower() == "true"


def _require_job_type_enabled(job_type: str) -> None:
    if job_type == "distribution" and not _distribution_enabled():
        raise HTTPException(403, "SWIM distribution jobs are disabled")
    if job_type == "activation" and not _activation_enabled():
        raise HTTPException(403, "SWIM activation jobs are disabled")
    if job_type not in swim_jobs.JOB_TYPES:
        raise HTTPException(400, f"invalid job_type: {job_type!r}")


def _devices_cache() -> tuple[list[dict], dict[str, str]]:
    return cache.get_stale("devices") or [], cache.get_stale("device_site_map") or {}


# ── Images ────────────────────────────────────────────────────────────────

@router.get("/images")
async def list_images(golden: bool = Query(True), session: SessionEntry = Depends(require_auth)):
    """Image picker source for the job wizard. Golden images are cached
    (dnac_golden_images, registered in datasets.py so the Cache Management
    page can refresh them); a full unfiltered browse is fetched live and
    uncached, since it's a less common wizard action."""
    dnac = _get_dnac(session)
    loop = asyncio.get_event_loop()
    if golden:
        images = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "dnac_golden_images",
            lambda: swim_client.list_golden_images(dnac), TTL_STANDARD,
        )
    else:
        images = await loop.run_in_executor(None, run_with_context(swim_client.list_images, dnac, None))
    return {"images": images or []}


# ── Compliance dashboard (read-only, no gate) ───────────────────────────────

@router.get("/compliance/summary")
async def compliance_summary(
    product_family: Optional[str] = Query(None),
    family: Optional[str] = Query(None),
    site: Optional[str] = Query(None),
    session: SessionEntry = Depends(require_auth),
):
    dnac = _get_dnac(session)
    loop = asyncio.get_event_loop()
    golden_images = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set), "dnac_golden_images",
        lambda: swim_client.list_golden_images(dnac), TTL_STANDARD,
    )
    devices, device_site_map = _devices_cache()
    return swim_compliance.compute_compliance(
        devices, device_site_map, golden_images or [],
        product_family=product_family, family=family, site=site,
    )


# ── Device targeting (modes a/b: filter picker + site/family auto-target) ──

@router.get("/devices/facets")
async def devices_facets(job_type: str = Query(...), session: SessionEntry = Depends(require_auth)):
    _require_job_type_enabled(job_type)
    devices, device_site_map = _devices_cache()
    return swim_targeting.list_facets(devices, device_site_map)


class DeviceSearchRequest(BaseModel):
    job_type: str
    image_uuid: Optional[str] = None
    site_codes: list[str] = []
    platforms: list[str] = []
    families: list[str] = []
    hostname_contains: Optional[str] = None
    reachability: Optional[str] = None
    page: int = 1
    page_size: int = 50


@router.post("/devices/search")
async def devices_search(req: DeviceSearchRequest, session: SessionEntry = Depends(require_auth)):
    _require_job_type_enabled(req.job_type)
    devices, device_site_map = _devices_cache()
    matched = swim_targeting.search_devices(
        devices, device_site_map,
        site_codes=req.site_codes or None, platforms=req.platforms or None,
        families=req.families or None, hostname_contains=req.hostname_contains,
        reachability=req.reachability,
    )

    incompatible_count = 0
    if req.image_uuid:
        # Preview-time compatibility filter — mirrors the authoritative gate
        # in create_job() below, so a device that will be rejected there
        # never shows up here as a false "match" in the first place. Always
        # live (see clients.swim.get_assigned_products): this is a safety
        # signal, not a display value.
        loop = asyncio.get_event_loop()
        dnac = _get_dnac(session)
        compat = await loop.run_in_executor(None, run_with_context(swim_client.get_assigned_products, dnac, req.image_uuid))
        before = len(matched)
        matched = [d for d in matched if swim_targeting.is_compatible(d, compat)]
        incompatible_count = before - len(matched)

    total = len(matched)
    page_size = max(1, min(req.page_size, 200))
    start = max(0, (req.page - 1) * page_size)
    page_rows = matched[start:start + page_size]

    def _row(d: dict) -> dict:
        code, source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
        return {
            "id": d.get("id"), "hostname": d.get("hostname"),
            "managementIpAddress": d.get("managementIpAddress"),
            "platformId": d.get("platformId"), "family": d.get("family") or d.get("deviceFamily"),
            "softwareVersion": d.get("softwareVersion"), "reachabilityStatus": d.get("reachabilityStatus"),
            "site_code": code or "UNKNOWN", "site_code_source": source,
        }

    return {
        "total_matches": total, "incompatible_count": incompatible_count,
        "page": req.page, "page_size": page_size, "rows": [_row(d) for d in page_rows],
    }


# ── Device targeting (mode c: CSV paste) ────────────────────────────────────

class ResolveCsvRequest(BaseModel):
    job_type: str
    image_uuid: Optional[str] = None
    lines: list[str]


@router.post("/devices/resolve-csv")
async def devices_resolve_csv(req: ResolveCsvRequest, session: SessionEntry = Depends(require_auth)):
    _require_job_type_enabled(req.job_type)
    devices, device_site_map = _devices_cache()
    matched, unmatched = swim_targeting.resolve_csv_lines(req.lines, devices)

    incompatible: list[dict] = []
    if req.image_uuid:
        # Same live compatibility filter as devices_search — a device that
        # resolves fine from the pasted list but isn't assigned to the
        # selected image is reported separately from "unmatched" (couldn't
        # find the device at all), since the fix for each is different.
        loop = asyncio.get_event_loop()
        dnac = _get_dnac(session)
        compat = await loop.run_in_executor(None, run_with_context(swim_client.get_assigned_products, dnac, req.image_uuid))
        still_matched, incompatible_devices = [], []
        for d in matched:
            (still_matched if swim_targeting.is_compatible(d, compat) else incompatible_devices).append(d)
        matched = still_matched
        incompatible = swim_targeting.snapshot_for_job(incompatible_devices, device_site_map)

    rows = swim_targeting.snapshot_for_job(matched, device_site_map)
    return {"matched": rows, "unmatched": unmatched, "incompatible": incompatible}


# ── Jobs ──────────────────────────────────────────────────────────────────

class DeviceFilterCriteria(BaseModel):
    site_codes: list[str] = []
    platforms: list[str] = []
    families: list[str] = []
    hostname_contains: Optional[str] = None
    reachability: Optional[str] = None
    excluded_device_ids: list[str] = []


class CreateJobRequest(BaseModel):
    job_type: str
    name: Optional[str] = None
    image_uuid: str
    image_name: Optional[str] = None
    image_version: Optional[str] = None
    platform_id: Optional[str] = None
    site_concurrency: int = 3
    targeting_mode: str
    criteria: Optional[DeviceFilterCriteria] = None
    device_ids: Optional[list[str]] = None
    # activation-only
    schedule_validate: Optional[bool] = None
    activate_lower_image_version: bool = False
    device_upgrade_mode: Optional[str] = None
    distribute_if_needed: bool = False


@router.post("/jobs")
async def create_job(req: CreateJobRequest, session: SessionEntry = Depends(require_auth)):
    _require_job_type_enabled(req.job_type)

    devices, device_site_map = _devices_cache()

    if req.targeting_mode == "csv":
        if not req.device_ids:
            raise HTTPException(400, "device_ids is required for csv targeting mode")
        wanted = set(req.device_ids)
        resolved = [d for d in devices if d.get("id") in wanted]
        criteria_snapshot = {"device_ids": req.device_ids}
    else:
        if not req.criteria:
            raise HTTPException(400, "criteria is required for filter/site_family targeting mode")
        resolved = swim_targeting.search_devices(
            devices, device_site_map,
            site_codes=req.criteria.site_codes or None, platforms=req.criteria.platforms or None,
            families=req.criteria.families or None, hostname_contains=req.criteria.hostname_contains,
            reachability=req.criteria.reachability,
        )
        if req.criteria.excluded_device_ids:
            excluded = set(req.criteria.excluded_device_ids)
            resolved = [d for d in resolved if d.get("id") not in excluded]
        criteria_snapshot = req.criteria.model_dump()

    if not resolved:
        raise HTTPException(400, "No devices matched the given targeting criteria")

    # Authoritative compatibility gate — this is the check that actually
    # decides which devices this job is allowed to touch, not just a preview
    # nicety like the one in devices_search/devices_resolve_csv above (which
    # exist so an operator sees the same answer before they get here, but a
    # client could in principle skip straight to this endpoint). Always
    # live: see clients.swim.get_assigned_products for why this is never
    # cached, and why an empty compatibility set blocks rather than allows.
    dnac = _get_dnac(session)
    loop = asyncio.get_event_loop()
    compat = await loop.run_in_executor(None, run_with_context(swim_client.get_assigned_products, dnac, req.image_uuid))
    if not compat:
        raise HTTPException(
            400,
            "DNAC has no product-compatibility data for the selected image — cannot verify "
            "which devices it belongs on, refusing to create this job.",
        )
    incompatible_count = sum(1 for d in resolved if not swim_targeting.is_compatible(d, compat))
    resolved = [d for d in resolved if swim_targeting.is_compatible(d, compat)]
    if not resolved:
        raise HTTPException(
            400,
            f"{incompatible_count} device(s) matched the targeting criteria, but none are "
            "assigned to the selected image in DNAC — refusing to create this job.",
        )

    if len(resolved) > swim_targeting.MAX_DEVICES_PER_JOB:
        raise HTTPException(400, f"Too many devices matched ({len(resolved)}); "
                                  f"max per job is {swim_targeting.MAX_DEVICES_PER_JOB}")

    site_concurrency = max(1, min(req.site_concurrency, 10))
    rows = swim_targeting.snapshot_for_job(resolved, device_site_map)

    job_id = swim_jobs.create_job(
        job_type=req.job_type, image_uuid=req.image_uuid, image_name=req.image_name,
        image_version=req.image_version, platform_id=req.platform_id,
        site_concurrency=site_concurrency, targeting_mode=req.targeting_mode,
        targeting_criteria=criteria_snapshot, created_by=session.username, name=req.name,
        schedule_validate=req.schedule_validate,
        activate_lower_image_version=req.activate_lower_image_version,
        device_upgrade_mode=req.device_upgrade_mode, distribute_if_needed=req.distribute_if_needed,
    )
    swim_jobs.add_devices(job_id, rows)

    from collections import Counter
    site_counts = Counter(r["site_code"] for r in rows)
    platform_counts = Counter(r.get("platform_id") or "(unknown)" for r in rows)

    return {
        "job": swim_jobs.get_job(job_id),
        "total_devices": len(rows),
        "site_counts": dict(site_counts),
        "platform_counts": dict(platform_counts),
        "homogeneity_warning": swim_targeting.homogeneity_warning(rows),
        "unresolved_site_count": swim_targeting.unresolved_site_count(rows),
        "incompatible_excluded_count": incompatible_count,
    }


@router.get("/jobs")
async def list_jobs(job_type: Optional[str] = Query(None), session: SessionEntry = Depends(require_auth)):
    jobs = swim_jobs.list_jobs(job_type)
    for j in jobs:
        j["device_counts"] = swim_jobs.device_status_counts(j["id"])
    return {"jobs": jobs}


@router.get("/jobs/{job_id}")
async def get_job(job_id: int, session: SessionEntry = Depends(require_auth)):
    job = swim_jobs.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    job["device_counts"] = swim_jobs.device_status_counts(job_id)
    job["is_running_here"] = job_id in _running_jobs
    return job


@router.get("/jobs/{job_id}/devices")
async def get_job_devices(
    job_id: int,
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    session: SessionEntry = Depends(require_auth),
):
    job = swim_jobs.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    offset = (page - 1) * page_size
    rows = swim_jobs.list_job_devices(job_id, status=status, limit=page_size, offset=offset)
    return {"rows": rows, "page": page, "page_size": page_size}


def _active_device_count(job_id: int) -> int:
    counts = swim_jobs.device_status_counts(job_id)
    return sum(n for status, n in counts.items() if status != "cancelled")


class StartJobRequest(BaseModel):
    job_id: int
    confirm: str


@router.post("/jobs/start")
async def start_job(req: StartJobRequest, session: SessionEntry = Depends(require_auth)):
    """Run (or resume) a job. SSE for the lifetime of the connection — see
    utils/swim_scheduler.py for the resumable, no-background-poller design.

    Confirmation is required once per job, on the first successful Start —
    stamped via clients.swim_jobs.confirm_job() and never re-demanded on a
    later Resume (the operator already authorized this job; resuming after a
    dropped connection is "continue what was approved," not a new action).
    """
    job = swim_jobs.get_job(req.job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    _require_job_type_enabled(job["job_type"])

    if job["confirmed_at"] is None:
        n_active = _active_device_count(req.job_id)
        expected = "DISTRIBUTE" if job["job_type"] == "distribution" else f"ACTIVATE {n_active} DEVICES"
        if req.confirm != expected:
            raise HTTPException(400, "Confirmation phrase incorrect")
        swim_jobs.confirm_job(req.job_id, session.username)

    if req.job_id in _running_jobs:
        raise HTTPException(409, "This job is already running (in this tab or another)")
    _running_jobs.add(req.job_id)

    dnac = _get_dnac(session)

    async def generate():
        def emit(d: dict) -> str:
            return f"data: {json.dumps(d)}\n\n"
        try:
            async for event in swim_scheduler.run_job(req.job_id, dnac):
                yield emit(event)
        finally:
            _running_jobs.discard(req.job_id)

    return StreamingResponse(
        generate(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/jobs/{job_id}/cancel-queued")
async def cancel_queued(job_id: int, session: SessionEntry = Depends(require_auth)):
    """Cancel every still-queued (not-yet-submitted-to-DNAC) device on this
    job — see clients.swim_jobs.cancel_queued for why submitting/in_progress
    rows are never touched (no DNAC-side abort exists)."""
    job = swim_jobs.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    _require_job_type_enabled(job["job_type"])
    return swim_jobs.cancel_queued(job_id)
