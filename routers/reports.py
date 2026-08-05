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
import html
import io
import logging
import os
import zipfile
from datetime import date, datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

import clients.sna as sna_client
from auth import SessionEntry, require_auth
from cache import cache
from logger_config import run_with_context
from utils.bandwidth_report import DEFAULT_INTERFACE, InvalidNameError, generate_bandwidth_report
from utils.cdrl49_report import REPORT_DEFS, generate_report, rows_to_csv
from utils.sna_report import generate_application_traffic_report

# Cap on how many <option> fragments a datalist endpoint returns — these back
# a live search-as-you-type field, not a full listing, so results stay small
# and fast to render regardless of fleet size.
_DATALIST_LIMIT = 40

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


@router.get("/bandwidth/router-options", response_class=HTMLResponse)
async def bandwidth_router_options(
    router: str = Query("", max_length=100),
    session: SessionEntry = Depends(require_auth),
):
    """Datalist <option> fragment of DNAC-known router hostnames.

    Feeds the Router Name field's autofill on the Bandwidth Utilization
    report. Pure cache read (stale OK — same pattern as
    routers/firewall.py's `_zones_for_dg` datalist) against DNAC's `devices`
    cache, which is already warmed at startup and background-refreshed
    (datasets.py), so this costs nothing extra. Still feeds a free-text
    input rather than a hard-enforced select: SolarWinds' own Node Caption
    is what actually resolves the report, and it usually — but not always —
    matches the DNAC hostname exactly.
    """
    devices = cache.get_stale("devices") or []
    needle = router.strip().lower()
    names = sorted(
        {d["hostname"] for d in devices if d.get("hostname") and (not needle or needle in d["hostname"].lower())},
        key=str.lower,
    )
    return HTMLResponse("".join(f'<option value="{html.escape(n, quote=True)}"></option>' for n in names[:_DATALIST_LIMIT]))


@router.get("/bandwidth/interface-options", response_class=HTMLResponse)
async def bandwidth_interface_options(
    router: str = Query("", max_length=100),
    session: SessionEntry = Depends(require_auth),
):
    """Datalist <option> fragment of every DNAC-known interface name on `router`.

    Same cache-only approach as bandwidth_router_options, against the
    `dnac_interfaces` cache. Exact hostname match preferred, falling back to
    a substring match (mirrors utils.bandwidth_report.find_node_ip's
    exact-then-LIKE pattern) since the Router Name field may still hold a
    partially-typed value when this fires.

    Unlike the router list, this isn't narrowed by the Interface field's own
    text: a single device's interface count is small enough that the
    browser's native datalist filtering handles that, and narrowing
    server-side would go empty as soon as the field still held a value (e.g.
    the Tunnel5000 default) left over from a previously-picked router that
    doesn't happen to have that interface.
    """
    router_needle = router.strip().lower()
    if not router_needle:
        return HTMLResponse("")

    interfaces = cache.get_stale("dnac_interfaces") or []
    exact = [i for i in interfaces if (i.get("deviceName") or "").strip().lower() == router_needle]
    pool = exact if exact else [i for i in interfaces if router_needle in (i.get("deviceName") or "").lower()]

    names = sorted({i["portName"] for i in pool if i.get("portName")}, key=str.lower)
    return HTMLResponse("".join(f'<option value="{html.escape(n, quote=True)}"></option>' for n in names[:_DATALIST_LIMIT]))


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
