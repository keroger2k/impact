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
from cache import TTL_LIVE, cache
from logger_config import run_with_context
from utils.bandwidth_report import (
    DEFAULT_INTERFACE,
    InvalidNameError,
    bare_interface_name,
    generate_bandwidth_report,
    list_interfaces_for_router,
    short_hostname,
)
from utils.cdrl49_report import REPORT_DEFS, generate_report, rows_to_csv
from utils.device_comparison_report import generate_device_comparison_report
from utils.device_comparison_report import to_csv as device_comparison_csv
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

    DNAC's `hostname` field is sometimes a full FQDN — reduced to
    short_hostname() before it ever reaches this datalist, since both
    SolarWinds' Caption and SNA's Exporter name downstream are short-form
    (see short_hostname()'s docstring).
    """
    devices = cache.get_stale("devices") or []
    needle = router.strip().lower()
    names = sorted(
        {
            short_hostname(d["hostname"]) for d in devices
            if d.get("hostname") and (not needle or needle in short_hostname(d["hostname"]).lower())
        },
        key=str.lower,
    )
    return HTMLResponse("".join(f'<option value="{html.escape(n, quote=True)}"></option>' for n in names[:_DATALIST_LIMIT]))


@router.get("/bandwidth/interfaces", response_class=HTMLResponse)
async def bandwidth_interfaces(
    router: str = Query("", max_length=100),
    session: SessionEntry = Depends(require_auth),
):
    """<option> fragment listing every interface SolarWinds is polling on
    `router`, populating the Interface field's dropdown with real options
    instead of a hardcoded "Tunnel5000" guess — which interface a site
    actually uses varies (another tunnel number, or a physical WAN interface).

    Sourced from SolarWinds, not DNAC's `dnac_interfaces` cache: DNAC doesn't
    carry every WAN router in this fleet (confirmed against real production
    data — a router the report itself works for came back empty from that
    cache), and SolarWinds is what generate_bandwidth_report() resolves
    against anyway, so anything offered here is guaranteed to be something
    the report can actually find. Each option carries its `InterfaceID`, so
    Generate posts `interface_id` directly and skips the name-based lookup
    (and its ambiguity round-trip) entirely.

    Each option's **value is the bare interface name**, not the Caption shown
    as its label: Captions carry free-text circuit decoration
    ("Tunnel5000 · DMVPN Tunnel for TSA (ATT)") that fails the SWQL charset
    check and can't match SNA's bare names either — see
    utils.bandwidth_report.bare_interface_name. The label keeps the full
    Caption, since the circuit detail in it is genuinely useful when picking.

    Cached briefly (TTL_LIVE) per router: this is autocomplete, not report
    data, so the no-cache rule that governs the reports themselves doesn't
    apply — and without it every pass through the form re-queries Orion. Same
    posture as `dnac_config_search_result:*`.

    Live queries can genuinely fail, and this fires automatically as the user
    moves through the form — failures degrade to an inline placeholder option
    rather than an HTTP error, so a lightweight dropdown never dumps a stack
    trace into the page. The query runs with a short timeout
    (`_DROPDOWN_TIMEOUT`) rather than SOLARWINDS_TIMEOUT's 180s default.
    """
    router = short_hostname(router)
    if not router:
        return HTMLResponse('<option value="">Select a router first</option>')

    # Cached explicitly rather than via cache.get_or_set: that helper swallows
    # loader exceptions and returns None, which would collapse "Orion is
    # unreachable" and "that name is invalid" into the same misleading
    # "no router matching this name" message. Errors have to stay
    # distinguishable here — they're the user's only diagnostic.
    cache_key = f"sw_interfaces:{router.lower()}"
    rows = cache.get(cache_key)

    if rows is None:
        loop = asyncio.get_event_loop()
        try:
            rows = await loop.run_in_executor(
                None, run_with_context(list_interfaces_for_router),
                router, session.username, session.password,
            )
        except InvalidNameError:
            return HTMLResponse('<option value="">Invalid router name</option>')
        except Exception as e:
            logger.error(f"Interface list lookup failed: {e}", extra={"target": "SolarWinds", "action": "BANDWIDTH_INTERFACES"})
            return HTMLResponse('<option value="">Could not reach SolarWinds — try again</option>')
        # A confirmed-empty result is cached too — a typo'd name shouldn't
        # re-query Orion on every keystroke that follows it.
        cache.set(cache_key, rows, TTL_LIVE)

    if not rows:
        return HTMLResponse('<option value="">No router matching this name in SolarWinds</option>')

    seen = set()
    options = ['<option value="">Select interface…</option>']
    for row in rows:
        caption = row.get("InterfaceCaption") or row.get("InterfaceName") or ""
        name = bare_interface_name(caption) or row.get("InterfaceName") or ""
        if not name or name in seen:
            continue
        seen.add(name)
        status = row.get("StatusDescription") or ""
        label = f"{caption} — {status}" if status else caption
        selected = " selected" if name == DEFAULT_INTERFACE else ""
        options.append(
            f'<option value="{html.escape(name, quote=True)}"'
            f' data-interface-id="{html.escape(str(row.get("InterfaceID") or ""), quote=True)}"{selected}>'
            f'{html.escape(label)}</option>'
        )
    return HTMLResponse("".join(options))


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
        # Deliberately unattributed: this path spans a SolarWinds IP lookup
        # *and* every SNA call, so naming either system would be a guess.
        # The old "SolarWinds lookup failed" text misreported SNA-side
        # failures, and error text is the main diagnostic here.
        logger.error(f"Application traffic report failed: {e}", extra={"target": "SNA", "action": "SNA_APP_TRAFFIC"})
        raise HTTPException(502, f"Application traffic report failed: {e}")

    return result


@router.post("/device-comparison/generate")
async def generate_device_comparison(session: SessionEntry = Depends(require_auth)):
    """Reconcile DNAC's inventory against SolarWinds'.

    DNAC comes from the warmed `devices` cache; SolarWinds is queried live.
    Nexus/ACI/wireless are filtered from both sides — see
    utils/device_comparison_report.py for why that's symmetric, and note the
    response carries an `excluded` breakdown so the filter's effect is
    visible rather than silent.
    """
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(
            None, run_with_context(generate_device_comparison_report),
            session.username, session.password,
        )
    except Exception as e:
        logger.error(
            f"Device comparison report failed: {e}",
            extra={"target": "SolarWinds", "action": "DEVICE_COMPARISON"},
        )
        raise HTTPException(502, f"Device comparison failed: {e}")


@router.get("/device-comparison/export.csv")
async def export_device_comparison(session: SessionEntry = Depends(require_auth)):
    """Same reconciliation as /generate, flattened to CSV.

    Re-runs the comparison rather than accepting the client's copy back: the
    report is uncached and cheap enough to rebuild, and round-tripping it
    through the browser would let anything sent back be written into the
    download as though it came from SolarWinds.

    GET, not POST — it takes no parameters and only reads, so the browser can
    fetch it directly as a download. (utils.csrf only honours the
    X-CSRF-Token header, which a native form submit can't set, so a POST here
    would need a fetch+blob dance for no benefit.)
    """
    loop = asyncio.get_event_loop()
    try:
        report = await loop.run_in_executor(
            None, run_with_context(generate_device_comparison_report),
            session.username, session.password,
        )
    except Exception as e:
        logger.error(
            f"Device comparison export failed: {e}",
            extra={"target": "SolarWinds", "action": "DEVICE_COMPARISON_CSV"},
        )
        raise HTTPException(502, f"Device comparison failed: {e}")

    stamp = datetime.now().strftime("%Y%m%d")
    return Response(
        device_comparison_csv(report),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=device_comparison_{stamp}.csv"},
    )
