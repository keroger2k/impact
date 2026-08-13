"""tests/test_swim_compatibility.py — the image/device compatibility gate.

Confirms the actual safety property this gate exists for: create_job()
never lets a job through that would push an image to a device DNAC hasn't
assigned it to, and fails closed (blocks) rather than open (allows) when
compatibility can't be determined at all. See routers/swim.py's create_job
and clients/swim.py's get_assigned_products docstrings for the full
rationale — this was added after a review flagged that the original wizard
let any image be targeted at any device regardless of platform.
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
    # Bypass real auth/DNAC client construction entirely — these tests only
    # care about how create_job() reacts to what get_assigned_products
    # returns, not how a real dnac client is obtained.
    monkeypatch.setattr(s, "_get_dnac", lambda session: MagicMock())


def _fake_devices(monkeypatch, devices: list[dict]):
    monkeypatch.setattr(s, "_devices_cache", lambda: (devices, {}))


@pytest.mark.asyncio
async def test_create_job_blocks_when_no_compatibility_data_at_all(db: Path, monkeypatch):
    """An image DNAC has zero assigned products for is refused outright —
    silently allowing it would defeat the entire gate."""
    _fake_devices(monkeypatch, [_device(1, "sw-1", "C9300-48U")])
    monkeypatch.setattr(s.swim_client, "get_assigned_products", lambda dnac, image_id: {})

    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="bogus-image", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(),
    )
    with pytest.raises(HTTPException) as e:
        await s.create_job(req, session=_SESSION)
    assert e.value.status_code == 400
    assert "compatibility" in e.value.detail.lower()


@pytest.mark.asyncio
async def test_create_job_excludes_incompatible_devices_but_keeps_compatible_ones(db: Path, monkeypatch):
    devices = [
        _device(1, "sw-1", "C9300-48U"),   # compatible
        _device(2, "sw-2", "ISR4451-X/K9"),  # NOT assigned to this image
        _device(3, "sw-3", "C9300-48U"),   # compatible
    ]
    _fake_devices(monkeypatch, devices)
    monkeypatch.setattr(
        s.swim_client, "get_assigned_products",
        lambda dnac, image_id: {"C9300-48U": "Cisco Catalyst 9300 Series Switches"},
    )

    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(),  # no filters -> matches all 3
    )
    result = await s.create_job(req, session=_SESSION)

    assert result["total_devices"] == 2
    assert result["incompatible_excluded_count"] == 1
    rows = jobs.list_job_devices(result["job"]["id"])
    assert {r["device_id"] for r in rows} == {"1", "3"}


@pytest.mark.asyncio
async def test_create_job_blocks_when_all_matched_devices_are_incompatible(db: Path, monkeypatch):
    _fake_devices(monkeypatch, [_device(1, "sw-1", "ISR4451-X/K9")])
    monkeypatch.setattr(
        s.swim_client, "get_assigned_products",
        lambda dnac, image_id: {"C9300-48U": "Cisco Catalyst 9300 Series Switches"},
    )

    req = s.CreateJobRequest(
        job_type="activation", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(),
    )
    with pytest.raises(HTTPException) as e:
        await s.create_job(req, session=_SESSION)
    assert e.value.status_code == 400
    assert "none are" in e.value.detail.lower() or "assigned" in e.value.detail.lower()
    # Nothing should have been persisted for a job that was fully rejected.
    assert jobs.list_jobs() == []


@pytest.mark.asyncio
async def test_create_job_succeeds_when_all_devices_compatible(db: Path, monkeypatch):
    _fake_devices(monkeypatch, [_device(1, "sw-1", "C9300-48U"), _device(2, "sw-2", "C9300-48U")])
    monkeypatch.setattr(
        s.swim_client, "get_assigned_products",
        lambda dnac, image_id: {"C9300-48U": "Cisco Catalyst 9300 Series Switches"},
    )

    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="c9300-golden", targeting_mode="filter",
        criteria=s.DeviceFilterCriteria(),
    )
    result = await s.create_job(req, session=_SESSION)
    assert result["total_devices"] == 2
    assert result["incompatible_excluded_count"] == 0


@pytest.mark.asyncio
async def test_create_job_csv_mode_also_gated(db: Path, monkeypatch):
    """The gate applies uniformly regardless of targeting_mode — CSV-resolved
    device_ids get the same compatibility filter as a criteria search."""
    _fake_devices(monkeypatch, [_device(1, "sw-1", "C9300-48U"), _device(2, "sw-2", "ISR4451-X/K9")])
    monkeypatch.setattr(
        s.swim_client, "get_assigned_products",
        lambda dnac, image_id: {"C9300-48U": "Cisco Catalyst 9300 Series Switches"},
    )

    req = s.CreateJobRequest(
        job_type="distribution", image_uuid="c9300-golden", targeting_mode="csv",
        device_ids=["1", "2"],
    )
    result = await s.create_job(req, session=_SESSION)
    assert result["total_devices"] == 1
    assert result["incompatible_excluded_count"] == 1


# ── devices_search() preview filter ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_devices_search_filters_by_image_compatibility_when_provided(monkeypatch):
    devices = [_device(1, "sw-1", "C9300-48U"), _device(2, "sw-2", "ISR4451-X/K9")]
    _fake_devices(monkeypatch, devices)
    monkeypatch.setattr(
        s.swim_client, "get_assigned_products",
        lambda dnac, image_id: {"C9300-48U": "Cisco Catalyst 9300 Series Switches"},
    )

    req = s.DeviceSearchRequest(job_type="distribution", image_uuid="c9300-golden")
    result = await s.devices_search(req, session=_SESSION)
    assert result["total_matches"] == 1
    assert result["incompatible_count"] == 1
    assert result["rows"][0]["platformId"] == "C9300-48U"


@pytest.mark.asyncio
async def test_devices_search_unfiltered_without_image_uuid(monkeypatch):
    devices = [_device(1, "sw-1", "C9300-48U"), _device(2, "sw-2", "ISR4451-X/K9")]
    _fake_devices(monkeypatch, devices)

    req = s.DeviceSearchRequest(job_type="distribution")  # no image_uuid yet
    result = await s.devices_search(req, session=_SESSION)
    assert result["total_matches"] == 2
    assert result["incompatible_count"] == 0
