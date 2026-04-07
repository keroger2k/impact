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
    """Two-stage poller: task → discovery ID → completion."""
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

            log_fn({"type": "log", "level": "info",
                    "message": f"Polling attempt {attempt + 1}/{max_tries} — ID: {discovery_id or 'pending'}"})
            time.sleep(interval)
        except Exception as e:
            log_fn({"type": "log", "level": "error", "message": f"Poll error: {e}"})
            time.sleep(interval)

    log_fn({"type": "log", "level": "error", "message": "Timed out waiting for discovery"})
    return None


@router.post("/run")
async def run_import(req: ImportRequest, session: SessionEntry = Depends(require_auth)):
    """
    Discover and import devices via Catalyst Center.
    Streams progress as Server-Sent Events.
    """

    async def generate():
        loop = asyncio.get_event_loop()

        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        yield emit({"type": "log", "level": "info",
                    "message": f"Starting import of {len(req.entries)} entries"})

        try:
            dnac = auth_module.get_dnac_for_session(session)
        except Exception as e:
            yield emit({"type": "error", "message": f"DNAC connection failed: {e}"})
            return

        # Resolve credentials
        try:
            cred_ids = await loop.run_in_executor(None, _get_credentials, dnac, req.cli_username, req.snmp_username)
        except Exception as e:
            yield emit({"type": "error", "message": f"Credential fetch failed: {e}"})
            return

        if not cred_ids:
            yield emit({"type": "error",
                        "message": f"No credentials found for '{req.cli_username}' / '{req.snmp_username}'"})
            return

        yield emit({"type": "log", "level": "info", "message": f"Found {len(cred_ids)} credential ID(s)"})

        # Get site cache + existing IPs
        sites       = await loop.run_in_executor(None, dc.get_site_cache, dnac)
        existing    = await loop.run_in_executor(None, dc.get_managed_ips, dnac)

        yield emit({"type": "log", "level": "info",
                    "message": f"{len(existing):,} devices already in inventory — matching IPs will be skipped"})

        results = []
        total   = len(req.entries)

        for idx, entry in enumerate(req.entries):
            site_id, site_name = dc.find_best_site_match(sites, entry.site_code)
            progress_pct       = round((idx / total) * 100)

            if not site_id:
                yield emit({"type": "progress", "done": idx + 1, "total": total, "pct": progress_pct})
                yield emit({"type": "log", "level": "warn",
                            "message": f"{entry.ip}: site '{entry.site_code}' not found — skipping"})
                results.append({"ip": entry.ip, "site": entry.site_code, "outcome": "site_not_found"})
                continue

            if entry.ip in existing:
                yield emit({"type": "progress", "done": idx + 1, "total": total, "pct": progress_pct})
                yield emit({"type": "log", "level": "info",
                            "message": f"{entry.ip}: already in inventory — skipping"})
                results.append({"ip": entry.ip, "site": site_name, "outcome": "skipped_exists"})
                continue

            yield emit({"type": "log", "level": "info",
                        "message": f"{entry.ip}: initiating discovery (site: {site_name})"})

            def do_discovery(ip=entry.ip, site_id=site_id, site_name=site_name):
                events = []
                try:
                    disc_name = f"Auto-{ip.replace('.', '-')}-{uuid.uuid4().hex[:4]}"
                    job       = dnac.discovery.start_discovery(
                        name=disc_name, ipAddressList=ip,
                        discoveryType="Single", globalCredentialIdList=cred_ids,
                        protocolOrder="ssh",
                    )
                    discovery_id = _wait_for_discovery(
                        dnac, job.response.taskId,
                        req.max_retries, req.poll_interval,
                        lambda e: events.append(e),
                    )
                    if not discovery_id:
                        return None, "discovery_failed", events

                    res   = dnac.discovery.get_discovered_network_devices_by_discovery_id(id=discovery_id)
                    items = res.response if hasattr(res, "response") else []
                    assign_list = []
                    for dev in (items or []):
                        m_ip        = dev.get("managementIpAddress")
                        reachability = dev.get("reachabilityStatus")
                        hostname    = dev.get("hostname", "Unknown")
                        events.append({"type": "log", "level": "info",
                                       "message": f"  [{hostname}] {m_ip} — {reachability}"})
                        if m_ip and reachability == "Success":
                            assign_list.append({"ip": m_ip})

                    if assign_list:
                        dnac.sites.assign_devices_to_site(site_id=site_id, device=assign_list)
                        return ip, "discovered", events
                    else:
                        return None, "no_reachable_devices", events

                except Exception as e:
                    events.append({"type": "log", "level": "error", "message": f"{ip}: {e}"})
                    return None, f"error: {str(e)[:80]}", events

            result_ip, outcome, sub_events = await loop.run_in_executor(None, do_discovery)

            for ev in sub_events:
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

        # Summary
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

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
