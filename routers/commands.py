"""routers/commands.py — Ad-hoc SSH command runner with SSE streaming."""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth import SessionEntry, require_auth

SSH_TIMEOUT = 30
SSH_MAX_WORKERS = 10

router = APIRouter()
logger = logging.getLogger(__name__)

ALLOWED_PREFIXES = {
    "show ", "display ", "get ", "ping ", "traceroute ",
    "tracert ",
}
DISALLOWED_CHARS = {";", "&", "|", "`", "$", "(", ")", "{", "}", ">", "<", "\n", "\r", "\t"}

PLATFORM_MAP = [
    ("N9K", "cisco_nxos"), ("N7K", "cisco_nxos"), ("N5K", "cisco_nxos"), ("N3K", "cisco_nxos"),
    ("C9",  "cisco_ios"),  ("C8",  "cisco_ios"),  ("ISR", "cisco_ios"),  ("ASR", "cisco_ios"),
    ("CSR", "cisco_ios"),  ("C38", "cisco_ios"),  ("C36", "cisco_ios"),  ("C35", "cisco_ios"),
    ("CISCO39", "cisco_ios"), ("CISCO38", "cisco_ios"),
    ("ASA", "cisco_asa"), ("FTD", "cisco_ftd"), ("WLC", "cisco_wlc"),
]


def guess_device_type(platform_id: str) -> str:
    if not platform_id:
        return "cisco_ios"
    pid = platform_id.upper()
    for substr, dtype in PLATFORM_MAP:
        if substr in pid:
            return dtype
    return "cisco_ios"


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
        # In DEV_MODE we simulate latency synchronously since we're in ThreadPool
        # simulate synchronously in threadpool
        pass # simulated delay
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
    max_workers:          int = SSH_MAX_WORKERS
    timeout:              int = SSH_TIMEOUT


@router.post("/run")
async def run_command(req: CommandRequest, session: SessionEntry = Depends(require_auth)):
    """Execute a command on multiple devices. Streams SSE progress."""
    from os import getenv
    if getenv("COMMANDS_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Command execution is disabled")

    command = req.command.strip()
    req.command = command

    if len(command) > 256:
        raise HTTPException(400, "Command too long (max 256 chars)")

    username, password = session.username, session.password

    if not any(command.lower().startswith(p) for p in ALLOWED_PREFIXES):
        raise HTTPException(400, "Only read-only show/display commands are permitted")

    if any(c in command for c in DISALLOWED_CHARS):
        raise HTTPException(400, "Command contains disallowed characters")

    import shlex
    try:
        parts = shlex.split(command)
        for p in parts:
            if any(c in p for c in DISALLOWED_CHARS):
                raise HTTPException(400, "Command contains disallowed characters")
    except ValueError as e:
        raise HTTPException(400, f"Invalid command format: {e}")

    # Log each command execution
    for dev in req.devices:
        logger.info(f"User {session.username} executing command on {dev.get('ip')}: {req.command}")

    async def generate():
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

        with ThreadPoolExecutor(max_workers=req.max_workers) as executor:
            futures = {executor.submit(make_result, dev): dev for dev in req.devices}
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                done += 1
                yield f"data: {json.dumps({'type':'progress','done':done,'total':total,**result})}\n\n"

        succeeded = sum(1 for r in results if r["status"] == "success")
        yield f"data: {json.dumps({'type':'complete','total':total,'succeeded':succeeded,'failed':total-succeeded})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
