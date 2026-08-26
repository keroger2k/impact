import asyncio
import html
import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

import auth as auth_module
from auth import SessionEntry, require_auth
from logger_config import run_with_context
from templates_module import templates
from utils.config_diff import (
    fetch_config_by_id,
    find_candidate_by_id,
    resolve_hostname,
    search_candidates,
)

router = APIRouter()
logger = logging.getLogger(__name__)


def _get_dnac(session: SessionEntry):
    try:
        return auth_module.get_dnac_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"DNAC connection failed: {e}")


@router.get("/device-options", response_class=HTMLResponse)
async def device_options(hostname: str = Query(""), session: SessionEntry = Depends(require_auth)):
    """Datalist <option> fragment of DNAC + Nexus hostnames matching the typed prefix/substring."""
    matches = search_candidates(hostname)
    return HTMLResponse("".join(
        f'<option value="{html.escape(c["hostname"], quote=True)}"></option>' for c in matches
    ))


async def _load_config_for(candidate: dict, session: SessionEntry) -> str:
    loop = asyncio.get_event_loop()
    if candidate["family"] == "nexus":
        return await loop.run_in_executor(None, run_with_context(fetch_config_by_id), candidate["id"])
    dnac = _get_dnac(session)
    return await loop.run_in_executor(None, run_with_context(fetch_config_by_id), candidate["id"], dnac)


@router.get("/load")
async def load_device(
    request: Request,
    side: Literal["left", "right"] = Query(...),
    hostname: str = Query(""),
    device_id: Optional[str] = Query(None),
    session: SessionEntry = Depends(require_auth),
):
    """Resolve a typed hostname (or a picked device_id) and load its config
    into the side's preview panel. Ambiguous hostnames render a picker;
    a device_id short-circuits straight to that exact device."""
    if device_id:
        candidate = find_candidate_by_id(device_id)
        if not candidate:
            return templates.TemplateResponse(request, "partials/config_diff_panel.html", {
                "side": side, "state": "not_found", "hostname": hostname or device_id,
            })
        config = await _load_config_for(candidate, session)
        return templates.TemplateResponse(request, "partials/config_diff_panel.html", {
            "side": side, "state": "loaded", "candidate": candidate, "config": config,
        })

    candidates = resolve_hostname(hostname)
    if not candidates:
        return templates.TemplateResponse(request, "partials/config_diff_panel.html", {
            "side": side, "state": "not_found", "hostname": hostname,
        })
    if len(candidates) > 1:
        return templates.TemplateResponse(request, "partials/config_diff_panel.html", {
            "side": side, "state": "ambiguous", "hostname": hostname, "candidates": candidates,
        })

    candidate = candidates[0]
    config = await _load_config_for(candidate, session)
    return templates.TemplateResponse(request, "partials/config_diff_panel.html", {
        "side": side, "state": "loaded", "candidate": candidate, "config": config,
    })


@router.post("/compare")
async def compare(
    request: Request,
    left_device_id: str = Form(""),
    right_device_id: str = Form(""),
    session: SessionEntry = Depends(require_auth),
):
    """Full side-by-side config diff for two already-loaded devices."""
    left = find_candidate_by_id(left_device_id) if left_device_id else None
    right = find_candidate_by_id(right_device_id) if right_device_id else None
    if not left or not right:
        raise HTTPException(400, "Load a device on both sides before comparing.")

    left_config, right_config = await asyncio.gather(
        _load_config_for(left, session), _load_config_for(right, session),
    )

    import difflib
    diff_table = difflib.HtmlDiff(wrapcolumn=100).make_table(
        left_config.splitlines(),
        right_config.splitlines(),
        fromdesc=html.escape(left["hostname"], quote=True),
        todesc=html.escape(right["hostname"], quote=True),
        context=False,
    )

    return templates.TemplateResponse(request, "partials/config_diff_result.html", {
        "diff_table": diff_table,
        "left": left,
        "right": right,
        "identical": left_config == right_config,
    })
