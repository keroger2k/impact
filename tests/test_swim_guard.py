"""tests/test_swim_guard.py — env-flag gates + confirmation phrase for
routers/swim.py, mirroring tests/test_commands_guard.py's shape.

SWIM_DISTRIBUTION_ENABLED and SWIM_ACTIVATION_ENABLED are independent flags
(see routers/swim.py's module docstring) — every mutating/targeting endpoint
re-checks the one matching the job_type it was asked to act on, never a
single combined flag.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import clients.swim_jobs as jobs
from routers import swim as s

_SESSION = SimpleNamespace(username="kyle.rogers", password="p")
# Guard-check tests all raise before generate() ever touches `request` — a
# bare placeholder is fine, no real Starlette Request needed.
_REQUEST = SimpleNamespace()


@pytest.fixture
def db(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "swim_jobs_test.db"
    monkeypatch.setattr(jobs, "DB_PATH", path)
    monkeypatch.setattr(jobs, "_initialized", False)
    jobs.init_schema(path)
    monkeypatch.setattr(jobs, "_initialized", True)
    return path


# ── job-type gate, independently per flag ───────────────────────────────────

@pytest.mark.asyncio
async def test_create_job_distribution_disabled_returns_403(monkeypatch):
    monkeypatch.delenv("SWIM_DISTRIBUTION_ENABLED", raising=False)
    req = s.CreateJobRequest(job_type="distribution", image_uuid="i1", targeting_mode="filter",
                              criteria=s.DeviceFilterCriteria())
    with pytest.raises(HTTPException) as e:
        await s.create_job(req, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_create_job_activation_disabled_returns_403(monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")  # distribution on, activation still off
    monkeypatch.delenv("SWIM_ACTIVATION_ENABLED", raising=False)
    req = s.CreateJobRequest(job_type="activation", image_uuid="i1", targeting_mode="filter",
                              criteria=s.DeviceFilterCriteria())
    with pytest.raises(HTTPException) as e:
        await s.create_job(req, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_devices_facets_gated_per_job_type(monkeypatch):
    monkeypatch.delenv("SWIM_DISTRIBUTION_ENABLED", raising=False)
    with pytest.raises(HTTPException) as e:
        await s.devices_facets(job_type="distribution", session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_devices_search_gated_per_job_type(monkeypatch):
    monkeypatch.delenv("SWIM_ACTIVATION_ENABLED", raising=False)
    req = s.DeviceSearchRequest(job_type="activation")
    with pytest.raises(HTTPException) as e:
        await s.devices_search(req, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_devices_resolve_csv_gated_per_job_type(monkeypatch):
    monkeypatch.delenv("SWIM_DISTRIBUTION_ENABLED", raising=False)
    req = s.ResolveCsvRequest(job_type="distribution", lines=["host-1"])
    with pytest.raises(HTTPException) as e:
        await s.devices_resolve_csv(req, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_invalid_job_type_rejected(monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    monkeypatch.setenv("SWIM_ACTIVATION_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await s.devices_facets(job_type="bogus", session=_SESSION)
    assert e.value.status_code == 400


# ── start_job(): gate + typed confirmation ──────────────────────────────────

def _create_draft_job(job_type="distribution") -> int:
    job_id = jobs.create_job(
        job_type=job_type, image_uuid="img-1", image_name="golden.bin", image_version="17.9.3",
        platform_id="C9300-48U", site_concurrency=3, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle.rogers",
    )
    jobs.add_devices(job_id, [{"device_id": "d1", "hostname": "h1", "management_ip": "10.0.0.1",
                                "platform_id": "C9300-48U", "family": "Switches and Hubs",
                                "site_code": "K001", "site_code_source": "device_site_map",
                                "current_software_version": "17.6.5"}])
    return job_id


@pytest.mark.asyncio
async def test_start_job_disabled_returns_403(db: Path, monkeypatch):
    monkeypatch.delenv("SWIM_DISTRIBUTION_ENABLED", raising=False)
    job_id = _create_draft_job("distribution")
    with pytest.raises(HTTPException) as e:
        await s.start_job(s.StartJobRequest(job_id=job_id, confirm="DISTRIBUTE"), _REQUEST, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_start_job_wrong_confirm_phrase_rejected(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    job_id = _create_draft_job("distribution")
    with pytest.raises(HTTPException) as e:
        await s.start_job(s.StartJobRequest(job_id=job_id, confirm="yes please"), _REQUEST, session=_SESSION)
    assert e.value.status_code == 400
    # Confirmation must not have been stamped on a rejected attempt.
    assert jobs.get_job(job_id)["confirmed_at"] is None


@pytest.mark.asyncio
async def test_start_job_activation_confirm_phrase_embeds_live_device_count(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_ACTIVATION_ENABLED", "true")
    job_id = _create_draft_job("activation")
    # Wrong count in the phrase must be rejected even though the words are right.
    with pytest.raises(HTTPException) as e:
        await s.start_job(s.StartJobRequest(job_id=job_id, confirm="ACTIVATE 99 DEVICES"), _REQUEST, session=_SESSION)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_start_job_missing_returns_404(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await s.start_job(s.StartJobRequest(job_id=999999, confirm="DISTRIBUTE"), _REQUEST, session=_SESSION)
    assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_cancel_queued_gated_per_job_type(db: Path, monkeypatch):
    monkeypatch.delenv("SWIM_ACTIVATION_ENABLED", raising=False)
    job_id = _create_draft_job("activation")
    with pytest.raises(HTTPException) as e:
        await s.cancel_queued(job_id, session=_SESSION)
    assert e.value.status_code == 403


# ── start_device(): manual per-device start guards ──────────────────────────
# Only the guard checks are exercised here — every path below raises before
# _get_dnac(session) is ever reached, so a bare SimpleNamespace session is
# fine (no real DNAC connection needed).

@pytest.mark.asyncio
async def test_start_device_disabled_returns_403(db: Path, monkeypatch):
    monkeypatch.delenv("SWIM_DISTRIBUTION_ENABLED", raising=False)
    job_id = _create_draft_job("distribution")
    row_id = jobs.list_job_devices(job_id)[0]["id"]
    with pytest.raises(HTTPException) as e:
        await s.start_device(job_id, row_id, _REQUEST, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_start_device_missing_job_returns_404(monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await s.start_device(999999, 1, _REQUEST, session=_SESSION)
    assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_start_device_requires_job_confirmed_first(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    job_id = _create_draft_job("distribution")  # never confirmed via start_job
    row_id = jobs.list_job_devices(job_id)[0]["id"]
    with pytest.raises(HTTPException) as e:
        await s.start_device(job_id, row_id, _REQUEST, session=_SESSION)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_start_device_blocked_while_job_running(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    job_id = _create_draft_job("distribution")
    jobs.confirm_job(job_id, "kyle.rogers")
    row_id = jobs.list_job_devices(job_id)[0]["id"]
    s._running_jobs.add(job_id)
    try:
        with pytest.raises(HTTPException) as e:
            await s.start_device(job_id, row_id, _REQUEST, session=_SESSION)
        assert e.value.status_code == 409
    finally:
        s._running_jobs.discard(job_id)


@pytest.mark.asyncio
async def test_start_device_missing_row_returns_404(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    job_id = _create_draft_job("distribution")
    jobs.confirm_job(job_id, "kyle.rogers")
    with pytest.raises(HTTPException) as e:
        await s.start_device(job_id, 999999, _REQUEST, session=_SESSION)
    assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_start_device_non_queued_row_returns_409(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    job_id = _create_draft_job("distribution")
    jobs.confirm_job(job_id, "kyle.rogers")
    row = jobs.list_job_devices(job_id)[0]
    jobs.set_device_status(row["id"], "success", completed_at="2026-08-12T00:00:00+00:00")
    with pytest.raises(HTTPException) as e:
        await s.start_device(job_id, row["id"], _REQUEST, session=_SESSION)
    assert e.value.status_code == 409
