"""routers/ise.py — ISE read-only API endpoints."""

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

import auth as auth_module
import clients.ise as ic
from auth import SessionEntry, require_auth
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)

ISE_TTL = 1800   # 30 min — ISE data changes less often

ISE_CACHE_KEYS = [
    "ise_nads", "ise_nad_groups", "ise_endpoint_groups", "ise_identity_groups",
    "ise_users", "ise_sgts", "ise_sgacls", "ise_egress_matrix",
    "ise_policy_sets", "ise_authz_profiles", "ise_allowed_protocols",
    "ise_profiling_policies", "ise_deployment_nodes",
]


def _get_ise(session: SessionEntry):
    try:
        return auth_module.get_ise_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"ISE connection failed: {e}")


def _cached(key: str, loader, ttl: int = ISE_TTL):
    """Generic cached fetch helper — synchronous, call via run_in_executor."""
    data = cache.get(key)
    if data is None:
        data = loader()
        cache.set(key, data, ttl)
    return data


# ── Cache management ──────────────────────────────────────────────────────────

@router.get("/cache/info")
async def ise_cache_info():
    infos = {k: cache.cache_info(k) for k in ISE_CACHE_KEYS}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}


@router.post("/cache/refresh")
async def refresh_ise_cache():
    cache.invalidate_prefix("ise_")
    return {"status": "ise cache cleared"}


# ── Network Access Devices ────────────────────────────────────────────────────

@router.get("/nads")
async def list_nads(request: Request, search: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    nads = await loop.run_in_executor(None, _cached, "ise_nads",
               lambda: ic.get_network_devices(ise, ""))
    if search:
        s = search.lower()
        nads = [n for n in nads if s in json.dumps(n).lower()]

    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/ise_nads.html", {"total": len(nads), "items": nads})
    return {"total": len(nads), "items": nads}


@router.get("/nads/{nad_id}")
async def get_nad(nad_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_NADS
    if DEV_MODE:
        match = next((n for n in MOCK_NADS if n["id"] == nad_id), None)
        if not match:
            raise HTTPException(404, "NAD not found")
        return match
    ise    = _get_ise(session)
    loop   = asyncio.get_event_loop()
    detail = await loop.run_in_executor(None, ic.get_network_device_detail, ise, nad_id)
    if not detail:
        raise HTTPException(404, "NAD not found")
    return detail


@router.get("/device-groups")
async def list_device_groups(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    groups = await loop.run_in_executor(None, _cached, "ise_nad_groups",
                 lambda: ic.get_network_device_groups(ise))
    return {"total": len(groups), "items": groups}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/endpoints")
async def search_endpoints(mac: str = Query(..., min_length=2), session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE
    if DEV_MODE:
        return {"total": 0, "items": []}
    ise       = _get_ise(session)
    loop      = asyncio.get_event_loop()
    endpoints = await loop.run_in_executor(None, ic.get_endpoints, ise, mac)
    return {"total": len(endpoints), "items": endpoints}


@router.get("/endpoints/{ep_id}")
async def get_endpoint(ep_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE
    if DEV_MODE:
        raise HTTPException(404, "Endpoint not found")
    ise    = _get_ise(session)
    loop   = asyncio.get_event_loop()
    detail = await loop.run_in_executor(None, ic.get_endpoint_detail, ise, ep_id)
    if not detail:
        raise HTTPException(404, "Endpoint not found")
    return detail


@router.get("/endpoint-groups")
async def list_endpoint_groups(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    groups = await loop.run_in_executor(None, _cached, "ise_endpoint_groups",
                 lambda: ic.get_endpoint_groups(ise))
    return {"total": len(groups), "items": groups}


# ── Identity ──────────────────────────────────────────────────────────────────

@router.get("/identity-groups")
async def list_identity_groups(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    groups = await loop.run_in_executor(None, _cached, "ise_identity_groups",
                 lambda: ic.get_identity_groups(ise))
    return {"total": len(groups), "items": groups}


@router.get("/users")
async def list_users(search: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    users = await loop.run_in_executor(None, _cached, "ise_users",
                lambda: ic.get_internal_users(ise, ""))
    if search:
        s = search.lower()
        users = [u for u in users if s in json.dumps(u).lower()]
    return {"total": len(users), "items": users}


# ── TrustSec ──────────────────────────────────────────────────────────────────

@router.get("/sgts")
async def list_sgts(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    raw  = await loop.run_in_executor(None, _cached, "ise_sgts",
               lambda: ic.get_sgts(ise))
    rows = []
    for s in raw:
        name  = s.get("name",  "—") if isinstance(s, dict) else getattr(s, "name",  "—")
        value = s.get("value", "—") if isinstance(s, dict) else getattr(s, "value", "—")
        desc  = s.get("description", "") if isinstance(s, dict) else getattr(s, "description", "")
        prop  = s.get("propogateToApic", False) if isinstance(s, dict) else getattr(s, "propogateToApic", False)
        rows.append({"name": name, "value": value, "description": desc, "propagateToApic": prop})
    rows.sort(key=lambda r: int(str(r["value"])) if str(r["value"]).isdigit() else 9999)
    return {"total": len(rows), "items": rows}


@router.get("/sgacls")
async def list_sgacls(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    sgacls = await loop.run_in_executor(None, _cached, "ise_sgacls",
                 lambda: ic.get_sgacls(ise))
    return {"total": len(sgacls), "items": sgacls}


@router.get("/egress-matrix")
async def egress_matrix(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    cells = await loop.run_in_executor(None, _cached, "ise_egress_matrix",
                lambda: ic.get_egress_matrix(ise))
    return {"total": len(cells), "items": cells}


# ── Policy ────────────────────────────────────────────────────────────────────

@router.get("/policy-sets")
async def list_policy_sets(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    sets = await loop.run_in_executor(None, _cached, "ise_policy_sets",
               lambda: ic.get_policy_sets(ise))
    return {"total": len(sets), "items": sets}


@router.get("/policy-sets/{policy_id}/auth-rules")
async def get_auth_rules(policy_id: str, session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    rules = await loop.run_in_executor(None, _cached, f"ise_auth_rules_{policy_id}",
                lambda: ic.get_auth_rules(ise, policy_id))
    return {"total": len(rules), "items": rules}


@router.get("/authz-profiles")
async def list_authz_profiles(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    profiles = await loop.run_in_executor(None, _cached, "ise_authz_profiles",
                   lambda: ic.get_authz_profiles(ise))
    return {"total": len(profiles), "items": profiles}


@router.get("/allowed-protocols")
async def list_allowed_protocols(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    protocols = await loop.run_in_executor(None, _cached, "ise_allowed_protocols",
                    lambda: ic.get_allowed_protocols(ise))
    return {"total": len(protocols), "items": protocols}


# ── Profiling & Admin ─────────────────────────────────────────────────────────

@router.get("/profiling-policies")
async def list_profiling_policies(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    policies = await loop.run_in_executor(None, _cached, "ise_profiling_policies",
                   lambda: ic.get_profiling_policies(ise))
    return {"total": len(policies), "items": policies}


@router.get("/deployment-nodes")
async def list_deployment_nodes(session: SessionEntry = Depends(require_auth)):
    ise  = _get_ise(session)
    loop = asyncio.get_event_loop()
    nodes = await loop.run_in_executor(None, _cached, "ise_deployment_nodes",
                lambda: ic.get_deployment_nodes(ise))
    return {"total": len(nodes), "items": nodes}
