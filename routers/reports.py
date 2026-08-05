"""routers/reports.py — On-demand SolarWinds/SNA-backed compliance reports.

- **CDRL49**: daily WAN response-time, AT&T EIS + SOHO routers. Every generate
  call runs a live SWQL query against SolarWinds and streams back a
  freshly-built PDF (optionally zipped with the underlying CSVs).
- **Bandwidth Utilization — In/Out**: per-interface percent-utilization history
  (24h + 7d) for a router, returned as JSON — rendered client-side as an
  inline SVG chart, no PDF/PNG generated.
- **Bandwidth Utilization — Application traffic**: per-application stacked
  traffic for that same interface, sourced from Cisco Secure Network
  Analytics (SNA) via its Report Builder API. Synchronous — a handful of
  fast GETs to resolve the router/interface name to SNA's internal IDs, then
  one POST for the report itself; no polling needed (see utils/sna_report.py
  and clients/sna.py for why this replaced an earlier async flow-search
  approach that only ever surfaced a router's own management-plane traffic).

Nothing here is cached — a report is a point-in-time deliverable, not a
dataset that benefits from staleness (see the "Live verify over local logic"
posture used elsewhere in the app).
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import zipfile
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import Response

import clients.sna as sna_client
from auth import SessionEntry, require_auth
from logger_config import run_with_context
from utils.bandwidth_report import DEFAULT_INTERFACE, InvalidNameError, generate_bandwidth_report
from utils.cdrl49_report import REPORT_DEFS, generate_report, rows_to_csv
from utils.sna_report import generate_application_traffic_report

router = APIRouter()
logger = logging.getLogger(__name__)


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


@router.post("/bandwidth/application-traffic")
async def get_application_traffic(
    router: str = Form(...),
    interface: str = Form(DEFAULT_INTERFACE),
    session: SessionEntry = Depends(require_auth),
):
    base_url = os.getenv("SNA_BASE_URL", "").rstrip("/")
    if not base_url:
        raise HTTPException(503, "SNA_BASE_URL is not configured")

    domain = os.getenv("SNA_DOMAIN", "")
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, run_with_context(generate_application_traffic_report),
            base_url, domain, session.username, session.password, router, interface,
        )
    except sna_client.SNAError as e:
        logger.error(f"SNA application traffic query failed: {e}", extra={"target": "SNA", "action": "SNA_APP_TRAFFIC"})
        raise HTTPException(502, f"SNA query failed: {e}")
    except InvalidNameError as e:
        raise HTTPException(400, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        logger.error(f"Application traffic report failed: {e}", extra={"target": "SolarWinds", "action": "SNA_APP_TRAFFIC"})
        raise HTTPException(502, f"SolarWinds lookup failed: {e}")

    return result
