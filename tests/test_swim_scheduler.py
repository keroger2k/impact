"""tests/test_swim_scheduler.py — the two-level concurrency/resume engine.

This is the subtlest code in the SWIM feature (see utils/swim_scheduler.py's
module docstring) and the most worth testing directly, per the plan's
Verification section. Four properties matter:

  1. A per-site semaphore slot is held for a device's *entire* lifecycle
     (submit through terminal poll), not released after submission —
     otherwise unlimited devices could be simultaneously mid-distribution at
     one site, defeating the whole feature.
  2. The global semaphore is held only around individual DNAC HTTP calls,
     not the whole lifecycle — otherwise total in-flight devices across a
     job would be capped at the global limit regardless of site count.
  3. Resume never re-submits an already-submitted device, and correctly
     resolves the ambiguous 'submitting' state by asking DNAC rather than
     guessing.
  4. A device cancelled out from under a worker before it acts is skipped,
     never submitted.

Timing-based assertions (1 and 2) use a short, monkeypatched poll interval
and a wide pass/fail margin (parallel vs. serial execution differ by several
multiples of that interval) so they stay fast and non-flaky.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

import clients.swim_jobs as jobs
import utils.swim_scheduler as scheduler


@pytest.fixture
def db(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "swim_jobs_test.db"
    monkeypatch.setattr(jobs, "DB_PATH", path)
    monkeypatch.setattr(jobs, "_initialized", False)
    jobs.init_schema(path)
    monkeypatch.setattr(jobs, "_initialized", True)
    return path


@pytest.fixture(autouse=True)
def _fast_polling(monkeypatch):
    monkeypatch.setattr(scheduler, "SWIM_POLL_INTERVAL", 0.05)
    monkeypatch.setattr(scheduler, "SWIM_POLL_TIMEOUT_HOURS", 1)


def _device(n: int, site="K001") -> dict:
    return {
        "device_id": f"dev-{n}", "hostname": f"host-{n}", "management_ip": f"10.0.0.{n}",
        "platform_id": "C9300-48U", "family": "Switches and Hubs", "site_code": site,
        "site_code_source": "device_site_map", "current_software_version": "17.6.5",
    }


def _make_job(job_type="distribution", site_concurrency=3, flash_cleanup=False, n=1) -> tuple[int, list[int]]:
    job_id = jobs.create_job(
        job_type=job_type, image_uuid="img-1", image_name="golden.bin", image_version="17.9.3",
        platform_id="C9300-48U", site_concurrency=site_concurrency, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle.rogers", flash_cleanup=flash_cleanup,
    )
    return job_id


async def _collect(job_id: int, dnac=object(), ssh_username=None, ssh_password=None) -> list[dict]:
    events = []
    async for event in scheduler.run_job(job_id, dnac, ssh_username, ssh_password):
        events.append(event)
    return events


# ── Happy path ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_queued_device_runs_to_success(db: Path, monkeypatch):
    job_id = _make_job()
    jobs.add_devices(job_id, [_device(1)])

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", lambda dnac, dev, img: "task-1")
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    events = await _collect(job_id)
    assert events[-1]["type"] == "complete"
    assert events[-1]["status"] == "completed"

    row = jobs.list_job_devices(job_id)[0]
    assert row["status"] == "success"


@pytest.mark.asyncio
async def test_failed_device_marks_job_completed_with_errors(db: Path, monkeypatch):
    job_id = _make_job()
    jobs.add_devices(job_id, [_device(1)])

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", lambda dnac, dev, img: "task-1")
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "failed", "failure_reason": "boom"})

    events = await _collect(job_id)
    assert events[-1]["status"] == "completed_with_errors"
    row = jobs.list_job_devices(job_id)[0]
    assert row["status"] == "failed"
    assert row["error_message"] == "boom"


# ── Flash cleanup pre-step ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flash_cleanup_runs_before_distribution_trigger_when_enabled(db: Path, monkeypatch):
    job_id = _make_job(flash_cleanup=True)
    jobs.add_devices(job_id, [_device(1)])

    call_order = []
    monkeypatch.setattr(scheduler, "_run_cleanup",
                         lambda row, u, p: call_order.append("cleanup") or
                         _async_result({"status": "success", "error": None}))
    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution",
                         lambda dnac, dev, img: call_order.append("trigger") or "task-1")
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    events = await _collect(job_id, ssh_username="u", ssh_password="p")
    assert events[-1]["status"] == "completed"
    assert call_order == ["cleanup", "trigger"]
    assert jobs.list_job_devices(job_id)[0]["status"] == "success"


@pytest.mark.asyncio
async def test_flash_cleanup_failure_skips_distribution_and_marks_failed(db: Path, monkeypatch):
    job_id = _make_job(flash_cleanup=True)
    jobs.add_devices(job_id, [_device(1)])

    def fail_if_called(*a, **k):
        raise AssertionError("trigger_distribution must not be called when cleanup fails")

    monkeypatch.setattr(scheduler, "_run_cleanup",
                         lambda row, u, p: _async_result({"status": "error", "error": "not enough flash space"}))
    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", fail_if_called)

    events = await _collect(job_id, ssh_username="u", ssh_password="p")
    assert events[-1]["status"] == "completed_with_errors"
    row = jobs.list_job_devices(job_id)[0]
    assert row["status"] == "failed"
    assert "Flash cleanup failed" in row["error_message"]
    assert "not enough flash space" in row["error_message"]


@pytest.mark.asyncio
async def test_flash_cleanup_skipped_entirely_when_disabled(db: Path, monkeypatch):
    job_id = _make_job(flash_cleanup=False)
    jobs.add_devices(job_id, [_device(1)])

    def fail_if_called(*a, **k):
        raise AssertionError("_run_cleanup must not be called when flash_cleanup is off")

    monkeypatch.setattr(scheduler, "_run_cleanup", fail_if_called)
    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", lambda dnac, dev, img: "task-1")
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    events = await _collect(job_id)
    assert events[-1]["status"] == "completed"


@pytest.mark.asyncio
async def test_flash_cleanup_not_rerun_on_resume_from_in_progress(db: Path, monkeypatch):
    """A device already resumed as 'in_progress' has necessarily already
    passed the cleanup step in an earlier run — must not run it again."""
    job_id = _make_job(flash_cleanup=True)
    jobs.add_devices(job_id, [_device(1)])
    row = jobs.list_job_devices(job_id)[0]
    jobs.set_device_status(row["id"], "in_progress", submitted_at="2026-08-12T00:00:00+00:00")

    def fail_if_called(*a, **k):
        raise AssertionError("_run_cleanup must not run again on an in_progress resume")

    monkeypatch.setattr(scheduler, "_run_cleanup", fail_if_called)
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    events = await _collect(job_id, ssh_username="u", ssh_password="p")
    assert events[-1]["status"] == "completed"


def _async_result(value):
    async def _coro():
        return value
    return _coro()


# ── Property 1 & 2: two-level concurrency hold-scope ────────────────────────

@pytest.mark.asyncio
async def test_site_semaphore_serializes_devices_at_one_site(db: Path, monkeypatch):
    """site_concurrency=1, 3 devices at the same site, each needing two poll
    rounds to succeed. If the site semaphore is correctly held for a
    device's whole lifecycle, the three devices run one at a time and total
    wall time is close to 3 x (2 poll intervals). If it were (incorrectly)
    released right after submission, all three could overlap and finish in
    roughly 1 x (2 poll intervals)."""
    job_id = _make_job(site_concurrency=1)
    jobs.add_devices(job_id, [_device(1), _device(2), _device(3)])

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", lambda dnac, dev, img: "task")

    poll_counts: dict[str, int] = {}

    def fake_poll(dnac, device_id, since):
        poll_counts[device_id] = poll_counts.get(device_id, 0) + 1
        if poll_counts[device_id] < 2:
            return {"status": "in_progress", "failure_reason": None}
        return {"status": "success", "failure_reason": None}

    monkeypatch.setattr(scheduler.swim_client, "poll_device_status", fake_poll)

    start = time.monotonic()
    events = await _collect(job_id)
    elapsed = time.monotonic() - start

    assert events[-1]["status"] == "completed"
    # Serialized: ~3 * 2 * 0.05s = 0.30s. Parallel (bug) would be ~2 * 0.05s = 0.10s.
    assert elapsed > 0.20, f"devices at one site ran concurrently (elapsed={elapsed:.3f}s) — site semaphore not serializing"


@pytest.mark.asyncio
async def test_global_semaphore_does_not_span_device_lifecycle(db: Path, monkeypatch):
    """5 devices at one site, site_concurrency=5 (no site-level contention),
    GLOBAL_SEM forced to capacity 1. If the global semaphore only wraps
    individual HTTP calls (correct), all 5 devices can sleep through their
    one poll interval concurrently and the whole job finishes in ~1 poll
    interval. If it were (incorrectly) held for each device's whole
    lifecycle, devices would run one at a time and the job would take ~5
    poll intervals."""
    job_id = _make_job(site_concurrency=5)
    jobs.add_devices(job_id, [_device(i, site="K001") for i in range(5)])

    monkeypatch.setattr(scheduler, "GLOBAL_SEM", asyncio.Semaphore(1))
    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", lambda dnac, dev, img: "task")
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    start = time.monotonic()
    events = await _collect(job_id)
    elapsed = time.monotonic() - start

    assert events[-1]["status"] == "completed"
    # Parallel-through-the-sleep: ~1 * 0.05s plus scheduling overhead.
    # Serialized (bug) would be ~5 * 0.05s = 0.25s.
    assert elapsed < 0.20, f"devices did not overlap their poll sleeps (elapsed={elapsed:.3f}s) — global semaphore held too long"


# ── Property 3: resume semantics ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resume_from_in_progress_never_resubmits(db: Path, monkeypatch):
    job_id = _make_job()
    jobs.add_devices(job_id, [_device(1)])
    row = jobs.list_job_devices(job_id)[0]
    jobs.set_device_status(row["id"], "in_progress", submitted_at="2026-08-12T00:00:00+00:00")

    def fail_if_called(*a, **k):
        raise AssertionError("trigger_distribution must not be called for an in_progress resume")

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", fail_if_called)
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    events = await _collect(job_id)
    assert events[-1]["status"] == "completed"
    assert jobs.list_job_devices(job_id)[0]["status"] == "success"


@pytest.mark.asyncio
async def test_resume_from_submitting_with_no_dnac_record_requeues_and_resubmits(db: Path, monkeypatch):
    job_id = _make_job()
    jobs.add_devices(job_id, [_device(1)])
    row = jobs.list_job_devices(job_id)[0]
    jobs.set_device_status(row["id"], "submitting")

    calls = {"trigger": 0, "poll": 0}

    def fake_trigger(dnac, dev, img):
        calls["trigger"] += 1
        return "task-1"

    def fake_poll(dnac, dev, since):
        calls["poll"] += 1
        # First poll (the up-front reconciliation check) finds nothing —
        # DNAC never got the original submit. Every poll after the real
        # resubmission succeeds immediately.
        if calls["poll"] == 1:
            return {"status": "pending", "failure_reason": None}
        return {"status": "success", "failure_reason": None}

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", fake_trigger)
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status", fake_poll)

    events = await _collect(job_id)
    assert events[-1]["status"] == "completed"
    assert calls["trigger"] == 1  # requeued, then genuinely (re)submitted exactly once
    assert jobs.list_job_devices(job_id)[0]["status"] == "success"


@pytest.mark.asyncio
async def test_resume_from_submitting_with_dnac_record_never_resubmits(db: Path, monkeypatch):
    job_id = _make_job()
    jobs.add_devices(job_id, [_device(1)])
    row = jobs.list_job_devices(job_id)[0]
    jobs.set_device_status(row["id"], "submitting")

    def fail_if_called(*a, **k):
        raise AssertionError("trigger_distribution must not be called — DNAC already has a record")

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", fail_if_called)
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status",
                         lambda dnac, dev, since: {"status": "success", "failure_reason": None})

    events = await _collect(job_id)
    assert events[-1]["status"] == "completed"
    assert jobs.list_job_devices(job_id)[0]["status"] == "success"


# ── Property 4: cancel race-safety ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_cancelled_device_is_never_submitted(db: Path, monkeypatch):
    job_id = _make_job()
    jobs.add_devices(job_id, [_device(1), _device(2)])
    rows = jobs.list_job_devices(job_id)
    # Simulate a cancel-queued call that landed between the job list being
    # loaded and the worker actually running (§5.2's race-safety check).
    jobs.cancel_queued(job_id)  # both rows are still 'queued' at this point -> both cancelled
    assert jobs.device_status_counts(job_id)["cancelled"] == 2

    def fail_if_called(*a, **k):
        raise AssertionError("a cancelled device must never be submitted")

    monkeypatch.setattr(scheduler.swim_client, "trigger_distribution", fail_if_called)
    monkeypatch.setattr(scheduler.swim_client, "poll_device_status", fail_if_called)

    events = await _collect(job_id)
    assert events[-1]["type"] == "complete"
    counts = jobs.device_status_counts(job_id)
    assert counts["cancelled"] == 2
