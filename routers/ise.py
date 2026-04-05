"""routers/ise.py — ISE read-only API endpoints."""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

import clients.ise as ic
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)

ISE_TTL = 1800   # 30 min — ISE data changes less often


def _get_ise():
    try:
        return ic.get_client()
    except Exception as e:
        raise HTTPException(503, f"ISE connection failed: {e}")


def _cached(key: str, loader, ttl: int = ISE_TTL):
    """Generic cached fetch helper."""
    data = cache.get(key)
    if data is None:
        data = loader()
        cache.set(key, data, ttl)
    return data


# ── Network Access Devices ─────────────────────────────────────────────────────

@router.get("/nads")
async def list_nads(search: Optional[str] = None):
    ise  = _get_ise()
    loop = asyncio.get_event_loop()
    nads = await loop.run_in_executor(None, ic.get_network_devices, ise, search or "")
    return {"total": len(nads), "items": nads}


@router.get("/nads/{nad_id}")
async def get_nad(nad_id: str):
    ise    = _get_ise()
    loop   = asyncio.get_event_loop()
    detail = await loop.run_in_executor(None, ic.get_network_device_detail, ise, nad_id)
    if not detail:
        raise HTTPException(404, "NAD not found")
    return detail


@router.get("/device-groups")
async def list_device_groups():
    ise    = _get_ise()
    loop   = asyncio.get_event_loop()
    groups = await loop.run_in_executor(None, ic.get_network_device_groups, ise)
    return {"total": len(groups), "items": groups}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/endpoints")
async def search_endpoints(mac: str = Query(..., min_length=2)):
    ise       = _get_ise()
    loop      = asyncio.get_event_loop()
    endpoints = await loop.run_in_executor(None, ic.get_endpoints, ise, mac)
    return {"total": len(endpoints), "items": endpoints}


@router.get("/endpoints/{ep_id}")
async def get_endpoint(ep_id: str):
    ise    = _get_ise()
    loop   = asyncio.get_event_loop()
    detail = await loop.run_in_executor(None, ic.get_endpoint_detail, ise, ep_id)
    if not detail:
        raise HTTPException(404, "Endpoint not found")
    return detail


@router.get("/endpoint-groups")
async def list_endpoint_groups():
    ise    = _get_ise()
    loop   = asyncio.get_event_loop()
    groups = await loop.run_in_executor(None, ic.get_endpoint_groups, ise)
    return {"total": len(groups), "items": groups}


# ── Identity ──────────────────────────────────────────────────────────────────

@router.get("/identity-groups")
async def list_identity_groups():
    ise    = _get_ise()
    loop   = asyncio.get_event_loop()
    groups = await loop.run_in_executor(None, ic.get_identity_groups, ise)
    return {"total": len(groups), "items": groups}


@router.get("/users")
async def list_users(search: Optional[str] = None):
    ise   = _get_ise()
    loop  = asyncio.get_event_loop()
    users = await loop.run_in_executor(None, ic.get_internal_users, ise, search or "")
    return {"total": len(users), "items": users}


# ── TrustSec ──────────────────────────────────────────────────────────────────

@router.get("/sgts")
async def list_sgts():
    ise  = _get_ise()
    loop = asyncio.get_event_loop()
    sgts = await loop.run_in_executor(None, ic.get_sgts, ise)

    rows = []
    for s in sgts:
        name  = s.get("name",  "—") if isinstance(s, dict) else getattr(s, "name",  "—")
        value = s.get("value", "—") if isinstance(s, dict) else getattr(s, "value", "—")
        desc  = s.get("description", "") if isinstance(s, dict) else getattr(s, "description", "")
        prop  = s.get("propogateToApic", False) if isinstance(s, dict) else getattr(s, "propogateToApic", False)
        rows.append({"name": name, "value": value, "description": desc, "propagateToApic": prop})

    rows.sort(key=lambda r: int(str(r["value"])) if str(r["value"]).isdigit() else 9999)
    return {"total": len(rows), "items": rows}


@router.get("/sgacls")
async def list_sgacls():
    ise    = _get_ise()
    loop   = asyncio.get_event_loop()
    sgacls = await loop.run_in_executor(None, ic.get_sgacls, ise)
    return {"total": len(sgacls), "items": sgacls}


@router.get("/egress-matrix")
async def egress_matrix():
    ise   = _get_ise()
    loop  = asyncio.get_event_loop()
    cells = await loop.run_in_executor(None, ic.get_egress_matrix, ise)
    return {"total": len(cells), "items": cells}


# ── Policy ────────────────────────────────────────────────────────────────────

@router.get("/policy-sets")
async def list_policy_sets():
    ise  = _get_ise()
    loop = asyncio.get_event_loop()
    sets = await loop.run_in_executor(None, ic.get_policy_sets, ise)
    return {"total": len(sets), "items": sets}


@router.get("/policy-sets/{policy_id}/auth-rules")
async def get_auth_rules(policy_id: str):
    ise   = _get_ise()
    loop  = asyncio.get_event_loop()
    rules = await loop.run_in_executor(None, ic.get_auth_rules, ise, policy_id)
    return {"total": len(rules), "items": rules}


@router.get("/authz-profiles")
async def list_authz_profiles():
    ise      = _get_ise()
    loop     = asyncio.get_event_loop()
    profiles = await loop.run_in_executor(None, ic.get_authz_profiles, ise)
    return {"total": len(profiles), "items": profiles}


@router.get("/allowed-protocols")
async def list_allowed_protocols():
    ise       = _get_ise()
    loop      = asyncio.get_event_loop()
    protocols = await loop.run_in_executor(None, ic.get_allowed_protocols, ise)
    return {"total": len(protocols), "items": protocols}


# ── Profiling & Admin ─────────────────────────────────────────────────────────

@router.get("/profiling-policies")
async def list_profiling_policies():
    ise      = _get_ise()
    loop     = asyncio.get_event_loop()
    policies = await loop.run_in_executor(None, ic.get_profiling_policies, ise)
    return {"total": len(policies), "items": policies}


@router.get("/deployment-nodes")
async def list_deployment_nodes():
    ise   = _get_ise()
    loop  = asyncio.get_event_loop()
    nodes = await loop.run_in_executor(None, ic.get_deployment_nodes, ise)
    return {"total": len(nodes), "items": nodes}
