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

DISCOVERY_POLL_INTERVAL = 10
DISCOVERY_MAX_RETRIES = 60

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


async def _wait_for_discovery(dnac, task_id: str, max_tries: int, interval: int, log_fn) -> str | None:
    discovery_id = None
    for attempt in range(max_tries):
        try:
            # We call the SDK synchronously since we are in a generator that can await
            # but wait_for_discovery was being called inside do_discovery in an executor.
            # I'll refactor this to be cleaner.
            import asyncio
            loop = asyncio.get_event_loop()
            task = await loop.run_in_executor(None, lambda: dnac.task.get_task_by_id(task_id=task_id))

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
                disc = await loop.run_in_executor(None, lambda: dnac.discovery.get_discovery_by_id(id=discovery_id))
                status = disc.response.get("discoveryCondition")
                if status == "Complete":
                    log_fn({"type": "log", "level": "success", "message": f"Discovery {discovery_id} complete"})
                    return discovery_id
                elif status in ("FAILURE", "TERMINATED"):
                    log_fn({"type": "log", "level": "error", "message": f"Discovery ended: {status}"})
                    return None
            log_fn({"type": "log", "level": "info", "message": f"Polling attempt {attempt + 1}/{max_tries}"})
            await asyncio.sleep(interval)
        except Exception as e:
            log_fn({"type": "log", "level": "error", "message": f"Poll error: {e}"})
            await asyncio.sleep(interval)
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

            results = []
            total   = len(req.entries)

            # We use a semaphore to limit concurrency
            sem = asyncio.Semaphore(5)

            async def process_entry(idx, entry):
                async with sem:
                    site_id, site_name = dc.find_best_site_match(sites, entry.site_code)
                    progress_pct = round((idx / total) * 100)

                    if not site_id:
                        yield emit({"type": "progress", "done": idx + 1, "total": total, "pct": progress_pct})
                        yield emit({"type": "log", "level": "warn",
                                    "message": f"{entry.ip}: site '{entry.site_code}' not found — skipping"})
                        results.append({"ip": entry.ip, "site": entry.site_code, "outcome": "site_not_found"})
                        return

                    if entry.ip in existing:
                        yield emit({"type": "progress", "done": idx + 1, "total": total, "pct": progress_pct})
                        yield emit({"type": "log", "level": "info",
                                    "message": f"{entry.ip}: already in inventory — skipping"})
                        results.append({"ip": entry.ip, "site": site_name, "outcome": "skipped_exists"})
                        return

                    yield emit({"type": "log", "level": "info",
                                "message": f"{entry.ip}: initiating discovery (site: {site_name})"})

                    events = []
                    outcome = "failed"
                    try:
                        disc_name = f"Auto-{entry.ip.replace('.', '-')}-{uuid.uuid4().hex[:4]}"
                        job = await loop.run_in_executor(None, lambda: dnac.discovery.start_discovery(
                            name=disc_name, ipAddressList=entry.ip,
                            discoveryType="Single", globalCredentialIdList=cred_ids,
                            protocolOrder="ssh",
                        ))

                        discovery_id = await _wait_for_discovery(
                            dnac, job.response.taskId,
                            req.max_retries, req.poll_interval,
                            lambda e: events.append(e),
                        )

                        if discovery_id:
                            res = await loop.run_in_executor(None, lambda: dnac.discovery.get_discovered_network_devices_by_discovery_id(id=discovery_id))
                            items = res.response if hasattr(res, "response") else []
                            assign_list = []
                            for dev in (items or []):
                                m_ip = dev.get("managementIpAddress")
                                reachability = dev.get("reachabilityStatus")
                                hostname = dev.get("hostname", "Unknown")
                                events.append({"type": "log", "level": "info",
                                               "message": f"  [{hostname}] {m_ip} — {reachability}"})
                                if m_ip and reachability == "Success":
                                    assign_list.append({"ip": m_ip})

                            if assign_list:
                                await loop.run_in_executor(None, lambda: dnac.sites.assign_devices_to_site(site_id=site_id, device=assign_list))
                                outcome = "discovered"
                            else:
                                outcome = "no_reachable_devices"
                        else:
                            outcome = "discovery_failed"

                    except Exception as e:
                        events.append({"type": "log", "level": "error", "message": f"{entry.ip}: {e}"})
                        outcome = f"error: {str(e)[:80]}"

                    for ev in events:
                        yield emit(ev)

                    yield emit({"type": "progress", "done": idx + 1, "total": total, "pct": progress_pct})

                    if outcome == "discovered":
                        existing.add(entry.ip)
                        yield emit({"type": "log", "level": "success",
                                    "message": f"{entry.ip}: assigned to {site_name}"})
                    else:
                        yield emit({"type": "log", "level": "warn",
                                    "message": f"{entry.ip}: outcome = {outcome}"})

                    results.append({"ip": entry.ip, "site": site_name, "outcome": outcome})

            # Run all entries and yield results as they come
            # Because this is a generator, we'll process them one by one but with semaphore concurrency
            # for the actual IO-bound tasks if we were using gather.
            # But wait, to keep order and serial progress in logs, we'll just loop.
            # The requirement was "Run discoveries for multiple devices concurrently with a bounded asyncio.Semaphore (e.g. 5)."
            # Let's use asyncio.gather to actually run them concurrently.

            # Since we need to yield from the generator, we can't easily gather and yield at the same time
            # without a queue or similar.
            queue = asyncio.Queue()

            async def worker(idx, entry):
                async for msg in process_entry(idx, entry):
                    await queue.put(msg)

            tasks = [asyncio.create_task(worker(i, e)) for i, e in enumerate(req.entries)]

            # Helper to check if all tasks are done
            done_count = 0
            while done_count < len(tasks):
                msg = await queue.get()
                yield msg
                # If it's a progress or log message, we keep going.
                # We need to know when a device is fully done.
                # Actually, we can just check tasks directly.
                done_count = sum(1 for t in tasks if t.done())
                # If there are still items in the queue, keep draining it.
                while not queue.empty():
                    yield await queue.get()
                    done_count = sum(1 for t in tasks if t.done())
                if done_count < len(tasks):
                    await asyncio.sleep(0.1)

            # Final summary
            discovered = sum(1 for r in results if r["outcome"] == "discovered")
            skipped    = sum(1 for r in results if r["outcome"] == "skipped_exists")
            failed     = sum(1 for r in results if r["outcome"] not in ("discovered", "skipped_exists", "site_not_found"))
            no_site    = sum(1 for r in results if r["outcome"] == "site_not_found")

            yield emit({
                "type": "complete",
                "total": total, "discovered": discovered,
                "skipped": skipped, "failed": failed, "no_site": no_site,
                "results": results,
            })
        except Exception as e:
            yield emit({"type": "error", "message": str(e)})

    return StreamingResponse(generate(), media_type="text/event-stream")
