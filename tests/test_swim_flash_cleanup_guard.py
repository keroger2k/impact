"""tests/test_swim_flash_cleanup_guard.py — env-flag gate and job_type
restriction for the flash_cleanup option on create_job().

flash_cleanup runs a new mutating SSH operation (install remove inactive,
deletes files from a device's flash) — it needs its own explicit opt-in gate
(SWIM_FLASH_CLEANUP_ENABLED) distinct from SWIM_DISTRIBUTION_ENABLED, and
only makes sense for distribution jobs (activation doesn't push a new image
to flash, so there's nothing for cleanup to make room for).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import clients.swim_jobs as jobs
from routers import swim as s

_SESSION = SimpleNamespace(username="kyle.rogers", password="p")


@pytest.fixture
def db(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "swim_jobs_test.db"
    monkeypatch.setattr(jobs, "DB_PATH", path)
    monkeypatch.setattr(jobs, "_initialized", False)
    jobs.init_schema(path)
    monkeypatch.setattr(jobs, "_initialized", True)
    return path


def _device(id_, hostname, platform) -> dict:
    return {
        "id": str(id_), "hostname": hostname, "managementIpAddress": f"10.0.0.{id_}",
        "platformId": platform, "family": "Switches and Hubs", "softwareVersion": "17.6.5",
    }


@pytest.fixture(autouse=True)
def _enabled_and_faked_dnac(monkeypatch):
    monkeypatch.setenv("SWIM_DISTRIBUTION_ENABLED", "true")
    monkeypatch.setenv("SWIM_ACTIVATION_ENABLED", "true")
    monkeypatch.setattr(s, "_get_dnac", lambda session: MagicMock())
    monkeypatch.setattr(s, "_devices_cache", lambda: ([_device(1, "sw-1", "C9300-48U")], {}))
    monkeypatch.setattr(
        s.swim_client, "get_assigned_products",
        lambda dnac, image_id: {"C9300-48U": "Cisco Catalyst 9300 Series Switches"},
    )


@pytest.mark.asyncio
async def test_flash_cleanup_requires_its_own_flag(db: Path, monkeypatch):
    monkeypatch.delenv("SWIM_FLASH_CLEANUP_ENABLED", raising=False)
    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(), flash_cleanup=True,
    )
    with pytest.raises(HTTPException) as e:
        await s.create_job(req, session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_flash_cleanup_allowed_when_flag_enabled(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_FLASH_CLEANUP_ENABLED", "true")
    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(), flash_cleanup=True,
    )
    result = await s.create_job(req, session=_SESSION)
    assert result["job"]["flash_cleanup"] == 1


@pytest.mark.asyncio
async def test_flash_cleanup_rejected_on_activation_job(db: Path, monkeypatch):
    monkeypatch.setenv("SWIM_FLASH_CLEANUP_ENABLED", "true")
    req = s.CreateJobRequest(
        job_type="activation", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(), flash_cleanup=True,
    )
    with pytest.raises(HTTPException) as e:
        await s.create_job(req, session=_SESSION)
    assert e.value.status_code == 400
    assert "distribution" in e.value.detail.lower()


@pytest.mark.asyncio
async def test_flash_cleanup_defaults_off_without_flag(db: Path, monkeypatch):
    """Distribution jobs work fine with the flag unset, as long as
    flash_cleanup isn't explicitly requested — the flag only gates the
    option itself, not distribution jobs in general."""
    monkeypatch.delenv("SWIM_FLASH_CLEANUP_ENABLED", raising=False)
    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(),  # flash_cleanup defaults False
    )
    result = await s.create_job(req, session=_SESSION)
    assert result["job"]["flash_cleanup"] == 0
