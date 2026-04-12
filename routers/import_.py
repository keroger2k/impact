"""routers/import_.py — Device discovery and site-assignment import with SSE streaming."""

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import auth as auth_module
import clients.dnac as dc
from auth import SessionEntry, require_auth

router = APIRouter()
logger = logging.getLogger(__name__)


class ImportEntry(BaseModel):
    site_code: str
    ip: str


class ImportRequest(BaseModel):
    entries: list[ImportEntry]
    cli_username:  str = "dnac-acct"
    snmp_username: str = "tsa_mon_user"
    poll_interval: int = 10
    max_retries:   int = 60


def _get_credentials(dnac, cli_user: str, snmp_user: str) -> list:
    cli_creds  = dc.get_global_credentials(dnac, "CLI")
    snmp_creds = dc.get_global_credentials(dnac, "SNMPV3")
    cli_ids    = [c.id for c in cli_creds  if getattr(c, "username", "") == cli_user]
    snmp_ids   = [c.id for c in snmp_creds if getattr(c, "username", "") == snmp_user]
    return cli_ids + snmp_ids


def _wait_for_discovery(dnac, task_id: str, max_tries: int, interval: int, log_fn) -> str | None:
    discovery_id = None
    for attempt in range(max_tries):
        try:
            task     = dnac.task.get_task_by_id(task_id=task_id)
            progress = task.response.progress
            is_error = getattr(task.response, "isError", False)
            if is_error:
                failure = getattr(task.response, "failureReason", "Unknown error")
                log_fn({"type": "log", "level": "error", "message": f"Task failed: {failure}"})
                return None
            if not discovery_id and progress and str(progress).isdigit():
                discovery_id = progress
                log_fn({"type": "log", "level": "info", "message": f"Discovery ID {discovery_id} obtained"})
            if discovery_id:
                disc   = dnac.discovery.get_discovery_by_id(id=discovery_id)
                status = disc.response.get("discoveryCondition")
                if status == "Complete":
                    log_fn({"type": "log", "level": "success", "message": f"Discovery {discovery_id} complete"})
                    return discovery_id
                elif status in ("FAILURE", "TERMINATED"):
                    log_fn({"type": "log", "level": "error", "message": f"Discovery ended: {status}"})
                    return None
            log_fn({"type": "log", "level": "info", "message": f"Polling attempt {attempt + 1}/{max_tries}"})
            time.sleep(interval)
        except Exception as e:
            log_fn({"type": "log", "level": "error", "message": f"Poll error: {e}"})
            time.sleep(interval)
    return None


@router.post("/run")
async def run_import(req: ImportRequest, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE

    async def generate():
        loop = asyncio.get_event_loop()
        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        yield emit({"type": "log", "level": "info", "message": f"Starting import of {len(req.entries)} entries"})

        if DEV_MODE:
            for idx, entry in enumerate(req.entries):
                yield emit({"type": "log", "level": "info", "message": f"{entry.ip}: [MOCK] Discovery initiating..."})
                await asyncio.sleep(0.5)
                yield emit({"type": "progress", "done": idx + 1, "total": len(req.entries)})
                yield emit({"type": "log", "level": "success", "message": f"{entry.ip}: [MOCK] Assigned to {entry.site_code}"})
            yield emit({"type": "complete", "total": len(req.entries), "discovered": len(req.entries), "skipped": 0, "failed": 0})
            return

        try:
            dnac = auth_module.get_dnac_for_session(session)
            cred_ids = await loop.run_in_executor(None, _get_credentials, dnac, req.cli_username, req.snmp_username)
            if not cred_ids:
                yield emit({"type": "error", "message": "No valid CLI/SNMP credentials found"})
                return

            sites = await loop.run_in_executor(None, dc.get_site_cache, dnac)
            existing = await loop.run_in_executor(None, dc.get_managed_ips, dnac)

            for idx, entry in enumerate(req.entries):
                site_id, site_name = dc.find_best_site_match(sites, entry.site_code)
                if not site_id:
                     yield emit({"type": "log", "level": "error", "message": f"{entry.ip}: Site {entry.site_code} not found"})
                     continue
                if entry.ip in existing:
                     yield emit({"type": "log", "level": "info", "message": f"{entry.ip}: Already exists"})
                     continue

                # ... rest of real logic ...
                yield emit({"type": "progress", "done": idx + 1, "total": len(req.entries)})

            yield emit({"type": "complete", "total": len(req.entries), "discovered": 0, "skipped": 0, "failed": 0})
        except Exception as e:
            yield emit({"type": "error", "message": str(e)})

    return StreamingResponse(generate(), media_type="text/event-stream")
