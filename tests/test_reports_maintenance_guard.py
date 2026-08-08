"""T1 — guard test for the Maintenance Mode Scheduler (routers/reports.py).

This is the one write path against SolarWinds in the app; the only thing
locked in here is that it's off by default and 403s until
SOLARWINDS_WRITES_ENABLED=true is set, same posture as
tests/test_commands_guard.py for COMMANDS_ENABLED/CONFIG_CHANGES_ENABLED.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from routers import reports as r

_SESSION = SimpleNamespace(username="u", password="p")


def _req():
    return r.MaintenanceScheduleRequest(rows=[
        {"node": "R-SITE01-01", "start_utc": "2026-08-10T08:00:00Z", "stop_utc": "2026-08-10T09:00:00Z"},
    ])


@pytest.mark.asyncio
async def test_schedule_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SOLARWINDS_WRITES_ENABLED", raising=False)
    with pytest.raises(HTTPException) as e:
        await r.schedule_maintenance(_req(), session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_schedule_disabled_when_flag_false(monkeypatch):
    monkeypatch.setenv("SOLARWINDS_WRITES_ENABLED", "false")
    with pytest.raises(HTTPException) as e:
        await r.schedule_maintenance(_req(), session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_schedule_returns_streaming_response_when_enabled(monkeypatch):
    monkeypatch.setenv("SOLARWINDS_WRITES_ENABLED", "true")
    result = await r.schedule_maintenance(_req(), session=_SESSION)
    assert result.media_type == "text/event-stream"


def _cancel_req():
    return r.MaintenanceCancelRequest(uri="swis://host/Orion/Orion.Nodes/NodeID=1")


@pytest.mark.asyncio
async def test_cancel_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SOLARWINDS_WRITES_ENABLED", raising=False)
    with pytest.raises(HTTPException) as e:
        await r.cancel_maintenance(_cancel_req(), session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_cancel_succeeds_when_enabled(monkeypatch):
    from unittest.mock import patch
    monkeypatch.setenv("SOLARWINDS_WRITES_ENABLED", "true")
    with patch("routers.reports.cancel_one") as mock_cancel:
        result = await r.cancel_maintenance(_cancel_req(), session=_SESSION)
    assert result == {"status": "ok"}
    mock_cancel.assert_called_once_with(_cancel_req().uri, "u", "p")
