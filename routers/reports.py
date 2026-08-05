"""routers/reports.py — On-demand SolarWinds/SNA-backed compliance reports.

- **CDRL49**: daily WAN response-time, AT&T EIS + SOHO routers. Every generate
  call runs a live SWQL query against SolarWinds and streams back a
  freshly-built PDF (optionally zipped with the underlying CSVs).
- **Bandwidth Utilization — In/Out**: per-interface percent-utilization history
  (24h + 7d) for a router, returned as JSON — rendered client-side as an
  inline SVG chart, no PDF/PNG generated.
- **Bandwidth Utilization — Application traffic**: per-application stacked
  traffic for that same router's IP, sourced from Cisco Secure Network
  Analytics (SNA). Unlike the other two, this is genuinely async — SNA flow
  search is a slow scan over raw NetFlow (confirmed via scripts/sna_discover.py:
  a 24h window was still ~52% done after 30 seconds), so the frontend starts
  a job, polls its status, then fetches results once complete.

Nothing here is cached — a report is a point-in-time deliverable, not a
dataset that benefits from staleness (see the "Live verify over local logic"
posture used elsewhere in the app).
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import re
import zipfile
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import Response

import clients.sna as sna_client
import utils.sna_jobs as sna_jobs
from auth import SessionEntry, require_auth
from logger_config import run_with_context
from utils.bandwidth_report import DEFAULT_INTERFACE, InvalidNameError, generate_bandwidth_report
from utils.cdrl49_report import REPORT_DEFS, generate_report, rows_to_csv
from utils.sna_traffic import bucket_traffic

router = APIRouter()
logger = logging.getLogger(__name__)

SNA_RECORD_LIMIT = 5000
_IP_RE = re.compile(r"^[0-9a-fA-F.:]{3,45}$")


def _parse_report_date(value: Optional[str]) -> date:
    if not value:
        return date.today() - timedelta(days=1)
    try:
        day = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(400, "report_date must be YYYY-MM-DD")
    if day > date.today():
        raise HTTPException(400, "report_date cannot be in the future")
    return day


@router.post("/cdrl49/generate")
async def generate_cdrl49(
    report_date: Optional[str] = Form(None),
    include_eis: bool = Form(True),
    include_soho: bool = Form(True),
    include_csv: bool = Form(False),
    session: SessionEntry = Depends(require_auth),
):
    day = _parse_report_date(report_date)

    keys = [k for k, enabled in (("eis", include_eis), ("soho", include_soho)) if enabled]
    if not keys:
        raise HTTPException(400, "Select at least one report to include")

    generated_at = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")
    loop = asyncio.get_event_loop()
    try:
        pdf_bytes, rows_by_key = await loop.run_in_executor(
            None, run_with_context(generate_report),
            day, keys, generated_at, session.username, session.password,
        )
    except Exception as e:
        logger.error(f"CDRL49 report generation failed: {e}", extra={"target": "SolarWinds", "action": "CDRL49_GENERATE"})
        raise HTTPException(502, f"SolarWinds report generation failed: {e}")

    date_part = day.strftime("%Y%m%d")

    if include_csv:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"CDRL49_{date_part}.pdf", pdf_bytes)
            for key in keys:
                zf.writestr(f"{REPORT_DEFS[key]['csv_name']}_{date_part}.csv", rows_to_csv(rows_by_key[key]))
        return Response(
            buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=CDRL49_{date_part}.zip"},
        )

    return Response(
        pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=CDRL49_{date_part}.pdf"},
    )


@router.post("/bandwidth/generate")
async def generate_bandwidth(
    router: Optional[str] = Form(None),
    interface: str = Form(DEFAULT_INTERFACE),
    interface_id: Optional[int] = Form(None),
    session: SessionEntry = Depends(require_auth),
):
    if not router and interface_id is None:
        raise HTTPException(400, "Router name is required")

    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, run_with_context(generate_bandwidth_report),
            router, interface, interface_id, session.username, session.password,
        )
    except InvalidNameError as e:
        raise HTTPException(400, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        logger.error(f"Bandwidth report generation failed: {e}", extra={"target": "SolarWinds", "action": "BANDWIDTH_GENERATE"})
        raise HTTPException(502, f"SolarWinds query failed: {e}")

    return result


@router.post("/bandwidth/application-traffic/start")
async def start_application_traffic(
    ip_address: str = Form(...),
    hours: int = Form(24),
    session: SessionEntry = Depends(require_auth),
):
    base_url = os.getenv("SNA_BASE_URL", "").rstrip("/")
    if not base_url:
        raise HTTPException(503, "SNA_BASE_URL is not configured")
    if hours not in (24, 24 * 7):
        raise HTTPException(400, "hours must be 24 or 168")
    if not _IP_RE.match(ip_address.strip()):
        raise HTTPException(400, "ip_address is not a valid IP address")

    domain = os.getenv("SNA_DOMAIN", "")

    def _start():
        sna_session = sna_client.login(base_url, session.username, session.password, domain)
        tenant_id = sna_client.get_tenant_id(sna_session, base_url)
        query_id = sna_client.create_flow_query(sna_session, base_url, tenant_id, ip_address, hours, SNA_RECORD_LIMIT)
        sna_jobs.register(query_id, sna_session, base_url, tenant_id, SNA_RECORD_LIMIT, hours)
        return query_id

    loop = asyncio.get_event_loop()
    try:
        job_id = await loop.run_in_executor(None, run_with_context(_start))
    except sna_client.SNAError as e:
        logger.error(f"SNA flow query failed to start: {e}", extra={"target": "SNA", "action": "SNA_START"})
        raise HTTPException(502, f"SNA query failed to start: {e}")

    return {"job_id": job_id, "hours": hours}


@router.get("/bandwidth/application-traffic/{job_id}/status")
async def application_traffic_status(job_id: str, session: SessionEntry = Depends(require_auth)):
    job = sna_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found or expired")

    loop = asyncio.get_event_loop()
    try:
        status = await loop.run_in_executor(
            None, run_with_context(sna_client.get_query_status),
            job["session"], job["base_url"], job["tenant_id"], job_id,
        )
    except sna_client.SNAError as e:
        raise HTTPException(502, str(e))
    return status


@router.get("/bandwidth/application-traffic/{job_id}/results")
async def application_traffic_results(job_id: str, session: SessionEntry = Depends(require_auth)):
    job = sna_jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found or expired")

    loop = asyncio.get_event_loop()
    try:
        flows = await loop.run_in_executor(
            None, run_with_context(sna_client.get_query_results),
            job["session"], job["base_url"], job["tenant_id"], job_id,
        )
    except sna_client.SNAError as e:
        raise HTTPException(502, str(e))

    sna_jobs.discard(job_id)

    data = bucket_traffic(flows, job["hours"])
    data["truncated"] = len(flows) >= job["record_limit"]
    data["flow_count"] = len(flows)
    return data
