"""routers/reports.py — On-demand SolarWinds-backed compliance reports.

Currently just CDRL49 (daily WAN response-time, AT&T EIS + SOHO routers).
Every generate call runs a live SWQL query against SolarWinds and streams
back a freshly-built PDF (optionally zipped with the underlying CSVs).
Nothing here is cached — a CDRL is a point-in-time deliverable, not a
dataset that benefits from staleness (see the "Live verify over local logic"
posture used elsewhere in the app).
"""
from __future__ import annotations

import asyncio
import io
import logging
import zipfile
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import Response

from auth import SessionEntry, require_auth
from logger_config import run_with_context
from utils.cdrl49_report import REPORT_DEFS, generate_report, rows_to_csv

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
            None, run_with_context(generate_report), day, keys, generated_at
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
