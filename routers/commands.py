"""routers/commands.py — Ad-hoc SSH command runner with SSE streaming.

Show-mode  (`/run`)        — single read-only command per device.
Config-mode (`/config-run`) — multi-line config script pushed via Netmiko's
                              send_config_set on each device in parallel.
                              Persists with save_config after a successful push.
"""

import asyncio
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from auth import SessionEntry, require_auth
from logger_config import run_with_context
from utils.device_ssh import guess_device_type

SSH_TIMEOUT = 30
SSH_MAX_WORKERS = 10
RUN_MAX_DEVICES = int(os.getenv("RUN_MAX_DEVICES", "500"))

router = APIRouter()
logger = logging.getLogger(__name__)

ALLOWED_PREFIXES = {
    "show ", "display ", "get ", "ping ", "traceroute ",
    "tracert ",
}
# Block only chars that let a user chain multiple commands on one line.
# Netmiko writes to the Cisco CLI, not a shell, so regex chars used in
# `| include <regex>` filters (parens, braces, anchors, etc.) are safe.
DISALLOWED_CHARS = {"\n", "\r", "\t"}


def _run_on_device(
    ip: str,
    command: str,
    username: str,
    password: str,
    device_type: str,
    timeout: int,
) -> dict:
    """SSH to one device, run one command. Returns result dict."""
    from dev import DEV_MODE
    if DEV_MODE:
        return {
            "ip": ip, "status": "success",
            "output": f"Mock output for '{command}' on {ip}\n(Simulated connection success)",
            "elapsed": 1.0, "error": None,
        }

    start = time.time()
    try:
        from netmiko import ConnectHandler
        with ConnectHandler(
            device_type=device_type,
            host=ip,
            username=username,
            password=password,
            timeout=timeout,
            conn_timeout=timeout,
            fast_cli=False,
        ) as conn:
            output = conn.send_command(command, read_timeout=timeout)
        return {
            "ip": ip, "status": "success",
            "output": output, "elapsed": round(time.time() - start, 1), "error": None,
        }
    except Exception as e:
        return {
            "ip": ip, "status": "error",
            "output": None, "elapsed": round(time.time() - start, 1),
            "error": f"{type(e).__name__}: {str(e)[:200]}",
        }


class CommandRequest(BaseModel):
    devices:              list[dict]   # [{ip, hostname, platform}]
    command:              str
    device_type_override: Optional[str] = None
    # max_workers/timeout come from the client — bounded so a request can't
    # build an arbitrarily large thread pool or pin SSH threads indefinitely.
    max_workers:          int = Field(SSH_MAX_WORKERS, ge=1, le=SSH_MAX_WORKERS)
    timeout:              int = Field(SSH_TIMEOUT, ge=5, le=300)

    @field_validator("devices")
    @classmethod
    def _cap_devices(cls, v):
        if not v:
            raise ValueError("No devices provided")
        if len(v) > RUN_MAX_DEVICES:
            raise ValueError(f"Too many devices (max {RUN_MAX_DEVICES})")
        return v


@router.post("/run")
async def run_command(req: CommandRequest, session: SessionEntry = Depends(require_auth)):
    """Execute a command on multiple devices. Streams SSE progress."""
    if os.getenv("COMMANDS_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Command execution is disabled")

    command = req.command.strip()
    req.command = command

    if len(command) > 256:
        raise HTTPException(400, "Command too long (max 256 chars)")

    username, password = session.username, session.password

    if not any(command.lower().startswith(p) for p in ALLOWED_PREFIXES):
        raise HTTPException(400, "Only read-only show/display commands are permitted")

    if any(c in command for c in DISALLOWED_CHARS):
        raise HTTPException(400, "Command must be a single line")

    # Log each command execution
    for dev in req.devices:
        logger.info(f"User {session.username} executing command on {dev.get('ip')}: {req.command}")

    async def generate():
        loop = asyncio.get_event_loop()
        total = len(req.devices)
        done  = 0

        def make_result(device: dict) -> dict:
            dtype = (
                req.device_type_override
                if req.device_type_override and req.device_type_override != "auto"
                else guess_device_type(device.get("platform", ""))
            )
            result = _run_on_device(
                ip=device.get("ip", ""),
                command=req.command,
                username=username,
                password=password,
                device_type=dtype,
                timeout=req.timeout,
            )
            result["hostname"] = device.get("hostname", device.get("ip", ""))
            result["platform"] = device.get("platform", "")
            return result

        # Await completions rather than blocking in
        # concurrent.futures.as_completed(): this generator runs on the event
        # loop thread, so a synchronous wait here would freeze every other
        # request/stream for the duration of the slowest SSH session.
        executor = ThreadPoolExecutor(max_workers=req.max_workers)
        results = []
        try:
            tasks = [
                loop.run_in_executor(executor, run_with_context(make_result), dev)
                for dev in req.devices
            ]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                done += 1
                yield f"data: {json.dumps({'type':'progress','done':done,'total':total,**result})}\n\n"
        finally:
            # Never block the loop waiting for straggler SSH threads — they
            # finish (or time out) on their own and the pool is reaped.
            executor.shutdown(wait=False)

        succeeded = sum(1 for r in results if r["status"] == "success")
        yield f"data: {json.dumps({'type':'complete','total':total,'succeeded':succeeded,'failed':total-succeeded})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Config mode (direct SSH via Netmiko) ─────────────────────────────────────

CONFIG_MAX_DEVICES = int(os.getenv("CONFIG_MAX_DEVICES", "500"))
CONFIG_MAX_SCRIPT_LINES = int(os.getenv("CONFIG_MAX_SCRIPT_LINES", "200"))


def _config_enabled():
    if os.getenv("CONFIG_CHANGES_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Config-mode pushes are disabled")


def _push_config_to_device(
    ip: str,
    commands: list[str],
    username: str,
    password: str,
    device_type: str,
    timeout: int,
    save: bool,
) -> dict:
    """Open an SSH session, push commands via send_config_set, optionally save.
    Returns a result dict the SSE generator can serialise."""
    from dev import DEV_MODE
    if DEV_MODE:
        return {
            "ip": ip, "status": "success",
            "output": f"[DEV_MODE] Would push {len(commands)} line(s) to {ip}:\n" +
                      "\n".join(commands) + ("\n[DEV_MODE] save_config skipped" if save else ""),
            "elapsed": 0.5, "error": None,
        }

    start = time.time()
    try:
        from netmiko import ConnectHandler
        with ConnectHandler(
            device_type=device_type,
            host=ip,
            username=username,
            password=password,
            timeout=timeout,
            conn_timeout=timeout,
            fast_cli=False,
        ) as conn:
            output = conn.send_config_set(commands, read_timeout=timeout)
            if save:
                try:
                    output += "\n" + conn.save_config()
                except Exception as se:
                    output += f"\n!! save_config failed: {type(se).__name__}: {str(se)[:200]}"
        return {
            "ip": ip, "status": "success",
            "output": output, "elapsed": round(time.time() - start, 1), "error": None,
        }
    except Exception as e:
        return {
            "ip": ip, "status": "error",
            "output": None, "elapsed": round(time.time() - start, 1),
            "error": f"{type(e).__name__}: {str(e)[:200]}",
        }


class ConfigRunRequest(BaseModel):
    devices:              list[dict]   # [{ip, hostname, platform}]
    script:               str          # multi-line config block
    confirm:              str          # must equal "DEPLOY"
    save:                 bool = True
    device_type_override: Optional[str] = None
    # Bounded for the same reason as CommandRequest — client-supplied knobs.
    max_workers:          int = Field(SSH_MAX_WORKERS, ge=1, le=SSH_MAX_WORKERS)
    timeout:              int = Field(SSH_TIMEOUT, ge=5, le=300)


@router.post("/config-run")
async def run_config(req: ConfigRunRequest, session: SessionEntry = Depends(require_auth)):
    """Push a multi-line config script to a list of devices over SSH, in parallel.
    Streams per-device results via SSE."""
    _config_enabled()
    if req.confirm != "DEPLOY":
        raise HTTPException(400, "Confirmation phrase incorrect")

    # Normalise the script into a list of non-empty lines.
    lines = [ln.rstrip() for ln in req.script.splitlines() if ln.strip()]
    if not lines:
        raise HTTPException(400, "Script is empty")
    if len(lines) > CONFIG_MAX_SCRIPT_LINES:
        raise HTTPException(400, f"Script too long (max {CONFIG_MAX_SCRIPT_LINES} lines)")
    if not req.devices:
        raise HTTPException(400, "No devices provided")
    if len(req.devices) > CONFIG_MAX_DEVICES:
        raise HTTPException(400, f"Too many devices (max {CONFIG_MAX_DEVICES})")

    username, password = session.username, session.password

    # Audit log: who pushed what, where. One line per device.
    line_summary = " | ".join(lines)[:300]
    for dev in req.devices:
        logger.info(f"CONFIG_PUSH user={session.username} ip={dev.get('ip')} "
                    f"lines={len(lines)} save={req.save} script=\"{line_summary}\"")

    async def generate():
        loop = asyncio.get_event_loop()
        total = len(req.devices)
        done  = 0

        def make_result(device: dict) -> dict:
            dtype = (
                req.device_type_override
                if req.device_type_override and req.device_type_override != "auto"
                else guess_device_type(device.get("platform", ""))
            )
            result = _push_config_to_device(
                ip=device.get("ip", ""),
                commands=lines,
                username=username,
                password=password,
                device_type=dtype,
                timeout=req.timeout,
                save=req.save,
            )
            result["hostname"] = device.get("hostname", device.get("ip", ""))
            result["platform"] = device.get("platform", "")
            return result

        # Same non-blocking completion pattern as /run — see that generator.
        executor = ThreadPoolExecutor(max_workers=req.max_workers)
        results = []
        try:
            tasks = [
                loop.run_in_executor(executor, run_with_context(make_result), dev)
                for dev in req.devices
            ]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                done += 1
                yield f"data: {json.dumps({'type':'progress','done':done,'total':total,**result})}\n\n"
        finally:
            executor.shutdown(wait=False)

        succeeded = sum(1 for r in results if r["status"] == "success")
        yield f"data: {json.dumps({'type':'complete','total':total,'succeeded':succeeded,'failed':total-succeeded})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

