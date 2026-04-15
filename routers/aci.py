"""routers/aci.py — Cisco ACI API endpoints."""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

import auth as auth_module
import clients.aci as ac
from auth import SessionEntry, require_auth
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)

ACI_TTL = 1800   # 30 min

ACI_CACHE_KEYS = [
    "aci_nodes", "aci_l3outs", "aci_bgp_peers", "aci_ospf_peers",
    "aci_epgs", "aci_faults", "aci_subnets"
]

def _get_aci(session: SessionEntry):
    try:
        return auth_module.get_aci_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"ACI connection failed: {e}")

def _cached(key: str, loader, ttl: int = ACI_TTL):
    """Generic cached fetch helper."""
    data = cache.get(key)
    if data is None:
        data = loader()
        cache.set(key, data, ttl)
    return data

# ── Cache management ──────────────────────────────────────────────────────────

@router.get("/cache/info")
async def aci_cache_info():
    infos = {k: cache.cache_info(k) for k in ACI_CACHE_KEYS}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}

@router.post("/cache/refresh")
async def refresh_aci_cache():
    cache.invalidate_prefix("aci_")
    return {"status": "aci cache cleared"}

# ── Fabric Nodes ──────────────────────────────────────────────────────────────

@router.get("/fabric/nodes")
async def list_fabric_nodes(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    nodes = await loop.run_in_executor(None, _cached, "aci_nodes", aci.get_fabric_nodes)

    # Process nodes to identify roles
    processed = []
    for n in nodes:
        attr = n.get('fabricNode', {}).get('attributes', {})
        role = attr.get('role', 'unknown')
        node_id = int(attr.get('id', '0'))

        # Heuristic if role is generic 'node'
        if role == 'node' or not role:
            if node_id >= 1000: role = 'spine'
            elif node_id >= 100: role = 'leaf'

        processed.append({
            "id": attr.get('id'),
            "name": attr.get('name'),
            "model": attr.get('model'),
            "role": role,
            "status": attr.get('fabricSt', 'unknown'),
            "dn": attr.get('dn')
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_nodes.html", {"nodes": processed})
    return {"items": processed}

# ── L3Outs ────────────────────────────────────────────────────────────────────

@router.get("/l3outs")
async def list_l3outs(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    l3outs_raw = await loop.run_in_executor(None, _cached, "aci_l3outs", aci.get_l3outs)

    processed = []
    for item in l3outs_raw:
        attr = item.get('l3extOut', {}).get('attributes', {})
        dn = attr.get('dn', '')
        # Extract tenant from DN: uni/tn-COMMON/out-L3OUT
        tenant = dn.split('/')[1].replace('tn-', '') if '/' in dn else 'unknown'

        processed.append({
            "name": attr.get('name'),
            "tenant": tenant,
            "dn": dn,
            "descr": attr.get('descr', '')
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_l3outs.html", {"l3outs": processed})
    return {"items": processed}

@router.get("/l3outs/detail")
async def get_l3out_detail(request: Request, dn: str, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    detail = await loop.run_in_executor(None, aci.get_l3out_details, dn)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_l3out_detail.html", {"detail": detail})
    return detail

# ── BGP Troubleshooting ────────────────────────────────────────────────────────

@router.get("/bgp/peers")
async def list_bgp_peers(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()

    # We also need subnets to map advertisements
    peers_raw = await loop.run_in_executor(None, _cached, "aci_bgp_peers", aci.get_bgp_peers)
    subnets_raw = await loop.run_in_executor(None, _cached, "aci_subnets", aci.get_l3_subnets)

    # Map subnets to L3Outs
    ads_map = {}
    for entry in subnets_raw:
        attr = entry.get('l3extSubnet', {}).get('attributes', {})
        if 'export-rtctrl' in attr.get('scope', ''):
            dn_parts = attr.get('dn', '').split('/')
            l3out = next((p.replace('out-', '') for p in dn_parts if p.startswith('out-')), "N/A")
            ads_map.setdefault(l3out, []).append(attr.get('ip'))

    processed = []
    for entry in peers_raw:
        attr = entry.get('bgpPeerEntry', {}).get('attributes', {})
        dn = attr.get('dn', '')
        dn_parts = dn.split('/')
        l3out = next((p.replace('out-', '') for p in dn_parts if p.startswith('out-')), "N/A")

        # Get node ID from DN: topology/pod-1/node-101/...
        node_id = next((p.replace('node-', '') for p in dn_parts if p.startswith('node-')), "N/A")

        processed.append({
            "node": node_id,
            "l3out": l3out,
            "addr": attr.get('addr'),
            "state": attr.get('operSt', 'unknown').upper(),
            "nets": ads_map.get(l3out, ["No Export Subnets"]),
            "dn": dn
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_peers.html", {"peers": processed})
    return {"items": processed}

@router.get("/bgp/routes/{node_id}")
async def get_bgp_routes(request: Request, node_id: str, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    routes = await loop.run_in_executor(None, aci.get_bgp_routes, node_id)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_routes.html", {"node_id": node_id, "routes": routes})
    return {"node_id": node_id, "items": routes}

# ── Traffic & EPGs ───────────────────────────────────────────────────────────

@router.get("/traffic/epgs")
async def list_epgs(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    epgs_raw = await loop.run_in_executor(None, _cached, "aci_epgs", aci.get_epgs)

    processed = []
    for item in epgs_raw:
        attr = item.get('fvAEPg', {}).get('attributes', {})
        dn = attr.get('dn', '')
        tenant = dn.split('/')[1].replace('tn-', '') if '/' in dn else 'unknown'
        app_prof = dn.split('/')[2].replace('ap-', '') if len(dn.split('/')) > 2 else 'unknown'

        processed.append({
            "name": attr.get('name'),
            "tenant": tenant,
            "app_prof": app_prof,
            "dn": dn
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_epgs.html", {"epgs": processed})
    return {"items": processed}

@router.get("/traffic/epg-health")
async def get_epg_health(request: Request, dn: str, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    # This might fetch healthInst and dbgrStats via the rsp-subtree-include
    data = await loop.run_in_executor(None, aci.get_epg_stats, dn)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_epg_health.html", {"data": data})
    return data

@router.get("/traffic/faults")
async def list_faults(request: Request, severity: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    faults = await loop.run_in_executor(None, aci.get_faults, severity)

    processed = []
    for f in faults:
        attr = f.get('faultInst', {}).get('attributes', {})
        processed.append({
            "code": attr.get('code'),
            "severity": attr.get('severity'),
            "descr": attr.get('descr'),
            "dn": attr.get('dn'),
            "created": attr.get('created')
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_faults.html", {"faults": processed})
    return {"items": processed}
