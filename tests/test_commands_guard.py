"""T1 — guard tests for the SSH command runner (routers/commands.py).

The runner is the app's most safety-critical surface; these lock in the
allow-list, single-line/length limits, the enable flags, and the DEPLOY
confirmation. Validation runs before any SSE/SSH, so the endpoints are called
directly and we assert the HTTPException they raise.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from routers import commands as c

_SESSION = SimpleNamespace(username="u", password="p")
_DEVICE = {"ip": "1.2.3.4", "hostname": "r1", "platform": "C9300"}


def _cmd(command, **kw):
    return c.CommandRequest(devices=[_DEVICE], command=command, **kw)


def _cfg(script="interface Lo0\n description test", confirm="DEPLOY", **kw):
    return c.ConfigRunRequest(devices=[_DEVICE], script=script, confirm=confirm, **kw)


# ── show-mode (/run) ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_disabled_returns_403(monkeypatch):
    monkeypatch.delenv("COMMANDS_ENABLED", raising=False)
    with pytest.raises(HTTPException) as e:
        await c.run_command(_cmd("show version"), session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_run_rejects_non_allowlisted_command(monkeypatch):
    monkeypatch.setenv("COMMANDS_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await c.run_command(_cmd("reload"), session=_SESSION)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_run_rejects_multiline_command(monkeypatch):
    monkeypatch.setenv("COMMANDS_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await c.run_command(_cmd("show run\nreload"), session=_SESSION)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_run_rejects_overlong_command(monkeypatch):
    monkeypatch.setenv("COMMANDS_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await c.run_command(_cmd("show " + "a" * 300), session=_SESSION)
    assert e.value.status_code == 400


# ── config-mode (/config-run) ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_config_disabled_returns_403(monkeypatch):
    monkeypatch.delenv("CONFIG_CHANGES_ENABLED", raising=False)
    with pytest.raises(HTTPException) as e:
        await c.run_config(_cfg(), session=_SESSION)
    assert e.value.status_code == 403


@pytest.mark.asyncio
async def test_config_requires_deploy_confirmation(monkeypatch):
    monkeypatch.setenv("CONFIG_CHANGES_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await c.run_config(_cfg(confirm="yes"), session=_SESSION)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_config_rejects_empty_script(monkeypatch):
    monkeypatch.setenv("CONFIG_CHANGES_ENABLED", "true")
    with pytest.raises(HTTPException) as e:
        await c.run_config(_cfg(script="  \n  \n"), session=_SESSION)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_config_rejects_too_many_lines(monkeypatch):
    monkeypatch.setenv("CONFIG_CHANGES_ENABLED", "true")
    script = "\n".join(f"line {i}" for i in range(c.CONFIG_MAX_SCRIPT_LINES + 1))
    with pytest.raises(HTTPException) as e:
        await c.run_config(_cfg(script=script), session=_SESSION)
    assert e.value.status_code == 400
