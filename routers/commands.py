"""routers/commands.py — Ad-hoc SSH command runner with SSE streaming.

Credentials come from the logged-in user's session (AD credentials).
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth import SessionEntry, require_auth

router = APIRouter()
logger = logging.getLogger(__name__)

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
    device_type_override: Optional[str] = None   # None = auto-detect
    max_workers:          int = 10
    timeout:              int = 30


@router.post("/run")
async def run_command(req: CommandRequest, session: SessionEntry = Depends(require_auth)):
    """Execute a command on multiple devices. Streams SSE progress."""
    username, password = session.username, session.password

    async def generate():
        total = len(req.devices)
        done  = [0]

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
                done[0] += 1
                yield f"data: {json.dumps({'type':'progress','done':done[0],'total':total,**result})}\n\n"

        succeeded = sum(1 for r in results if r["status"] == "success")
        yield f"data: {json.dumps({'type':'complete','total':total,'succeeded':succeeded,'failed':total-succeeded})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
