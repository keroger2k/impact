"""tests/test_swim_jobs.py — clients/swim_jobs.py schema + CRUD.

Mirrors tests/test_ip_registry.py's shape. Unlike ip_registry's functions
(which thread an explicit `path=` kwarg through every call), swim_jobs'
functions always resolve against the module-level DB_PATH via connect() — so
tests point at a temp DB by monkeypatching that module attribute directly
and resetting the lazy-init guard, rather than passing a path per call."""
from __future__ import annotations

from pathlib import Path

import pytest

import clients.swim_jobs as jobs


@pytest.fixture
def db(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "swim_jobs_test.db"
    monkeypatch.setattr(jobs, "DB_PATH", path)
    monkeypatch.setattr(jobs, "_initialized", False)
    jobs.init_schema(path)
    monkeypatch.setattr(jobs, "_initialized", True)
    return path


def _device(n: int, site="K001", platform="C9300-48U", status="queued") -> dict:
    return {
        "device_id": f"dev-{n}", "hostname": f"host-{n}", "management_ip": f"10.0.0.{n}",
        "platform_id": platform, "family": "Switches and Hubs", "site_code": site,
        "site_code_source": "device_site_map", "current_software_version": "17.6.5",
    }


# ── schema ────────────────────────────────────────────────────────────────────

def test_init_schema_is_idempotent(tmp_path: Path):
    path = tmp_path / "x.db"
    jobs.init_schema(path)
    jobs.init_schema(path)  # second call must not raise
    with jobs.connect(path) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert {"jobs", "job_devices"}.issubset(tables)


def test_init_schema_migrates_flash_cleanup_onto_pre_existing_db(tmp_path: Path):
    """A `jobs` table created before flash_cleanup existed must gain the
    column via ALTER TABLE — CREATE TABLE IF NOT EXISTS silently does nothing
    once the table is already present, which is exactly what let a real
    deployed database miss this column and fail every create_job() call with
    'table jobs has no column named flash_cleanup'."""
    path = tmp_path / "old_schema.db"
    old_schema = jobs.SCHEMA.replace(
        "    flash_cleanup                 INTEGER NOT NULL DEFAULT 0,\n", ""
    )
    assert "flash_cleanup" not in old_schema
    conn = jobs._connect_raw(path)
    try:
        conn.executescript(old_schema)
        conn.commit()
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
        assert "flash_cleanup" not in cols
    finally:
        conn.close()

    jobs.init_schema(path)

    with jobs.connect(path) as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
        assert "flash_cleanup" in cols


# ── jobs + job_devices CRUD ──────────────────────────────────────────────────

def test_create_job_and_add_devices(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="img-1", image_name="golden.bin",
        image_version="17.9.3", platform_id="C9300-48U", site_concurrency=3,
        targeting_mode="filter", targeting_criteria={"platforms": ["C9300-48U"]},
        created_by="kyle.rogers",
    )
    assert job_id > 0
    inserted = jobs.add_devices(job_id, [_device(1), _device(2), _device(3)])
    assert inserted == 3

    job = jobs.get_job(job_id)
    assert job["total_devices"] == 3
    assert job["status"] == "draft"
    assert job["job_type"] == "distribution"

    rows = jobs.list_job_devices(job_id)
    assert len(rows) == 3
    assert {r["status"] for r in rows} == {"queued"}


def test_add_devices_dedupes_by_device_id(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="img-1", image_name=None, image_version=None,
        platform_id=None, site_concurrency=3, targeting_mode="csv", targeting_criteria=None,
        created_by="kyle.rogers",
    )
    jobs.add_devices(job_id, [_device(1), _device(1)])  # duplicate device_id
    assert jobs.get_job(job_id)["total_devices"] == 1


def test_invalid_job_type_rejected(db: Path):
    with pytest.raises(ValueError):
        jobs.create_job(
            job_type="bogus", image_uuid="i", image_name=None, image_version=None,
            platform_id=None, site_concurrency=3, targeting_mode="filter",
            targeting_criteria=None, created_by="kyle",
        )


# ── status transitions ───────────────────────────────────────────────────────

def test_set_job_status_and_confirm(db: Path):
    job_id = jobs.create_job(
        job_type="activation", image_uuid="img-1", image_name=None, image_version=None,
        platform_id=None, site_concurrency=2, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle.rogers",
    )
    jobs.confirm_job(job_id, "kyle.rogers")
    job = jobs.get_job(job_id)
    assert job["confirmed_by"] == "kyle.rogers"
    assert job["confirmed_at"] is not None

    # confirm_job is a no-op once already confirmed (first-confirm-wins).
    first_confirmed_at = job["confirmed_at"]
    jobs.confirm_job(job_id, "someone.else")
    job2 = jobs.get_job(job_id)
    assert job2["confirmed_by"] == "kyle.rogers"
    assert job2["confirmed_at"] == first_confirmed_at

    jobs.set_job_status(job_id, "running", started_at="2026-08-12T00:00:00")
    assert jobs.get_job(job_id)["status"] == "running"


def test_set_device_status_and_status_counts(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="i", image_name=None, image_version=None,
        platform_id=None, site_concurrency=3, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle",
    )
    jobs.add_devices(job_id, [_device(1), _device(2), _device(3)])
    rows = jobs.list_job_devices(job_id)

    jobs.set_device_status(rows[0]["id"], "success", completed_at="2026-08-12T00:00:00")
    jobs.set_device_status(rows[1]["id"], "failed", error_message="boom")

    counts = jobs.device_status_counts(job_id)
    assert counts["success"] == 1
    assert counts["failed"] == 1
    assert counts["queued"] == 1


def test_unfinished_job_devices_excludes_terminal_rows(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="i", image_name=None, image_version=None,
        platform_id=None, site_concurrency=3, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle",
    )
    jobs.add_devices(job_id, [_device(1), _device(2), _device(3), _device(4)])
    rows = jobs.list_job_devices(job_id)
    jobs.set_device_status(rows[0]["id"], "success")
    jobs.set_device_status(rows[1]["id"], "in_progress")
    jobs.set_device_status(rows[2]["id"], "submitting")
    # rows[3] stays 'queued'

    unfinished = jobs.unfinished_job_devices(job_id)
    assert {r["status"] for r in unfinished} == {"in_progress", "submitting", "queued"}
    assert len(unfinished) == 3


def test_invalid_device_status_rejected(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="i", image_name=None, image_version=None,
        platform_id=None, site_concurrency=3, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle",
    )
    jobs.add_devices(job_id, [_device(1)])
    row_id = jobs.list_job_devices(job_id)[0]["id"]
    with pytest.raises(ValueError):
        jobs.set_device_status(row_id, "bogus")


# ── cancel_queued() ───────────────────────────────────────────────────────────

def test_cancel_queued_only_touches_queued_rows(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="i", image_name=None, image_version=None,
        platform_id=None, site_concurrency=3, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle",
    )
    jobs.add_devices(job_id, [_device(1), _device(2), _device(3), _device(4)])
    rows = jobs.list_job_devices(job_id)
    jobs.set_device_status(rows[0]["id"], "in_progress")
    jobs.set_device_status(rows[1]["id"], "success")
    # rows[2], rows[3] stay 'queued'

    result = jobs.cancel_queued(job_id)
    assert result["cancelled_count"] == 2
    assert result["already_in_flight_count"] == 1
    assert result["already_terminal_count"] == 1

    counts = jobs.device_status_counts(job_id)
    assert counts["cancelled"] == 2
    assert counts["in_progress"] == 1
    assert counts["success"] == 1
    assert counts["queued"] == 0


def test_get_device_status_single_column_read(db: Path):
    job_id = jobs.create_job(
        job_type="distribution", image_uuid="i", image_name=None, image_version=None,
        platform_id=None, site_concurrency=3, targeting_mode="filter",
        targeting_criteria=None, created_by="kyle",
    )
    jobs.add_devices(job_id, [_device(1)])
    row_id = jobs.list_job_devices(job_id)[0]["id"]
    assert jobs.get_device_status(row_id) == "queued"
    jobs.set_device_status(row_id, "cancelled")
    assert jobs.get_device_status(row_id) == "cancelled"
    assert jobs.get_device_status(999999) is None
