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
    "aci_epgs", "aci_faults", "aci_subnets", "aci_health_overall",
    "aci_health_tenants", "aci_health_pods"
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

async def _get_processed_nodes(aci, loop):
    nodes = await loop.run_in_executor(None, _cached, "aci_nodes", aci.get_fabric_nodes)
    logger.info(f"ACI fabric nodes raw count: {len(nodes)}")
    logger.info(f"ACI fabric nodes raw data: {nodes}")
    processed = []
    for n in nodes:
        attr = n.get('fabricNode', {}).get('attributes', {})
        role = attr.get('role', 'unknown')
        node_id_str = attr.get('id', '0')
        node_id = int(node_id_str) if node_id_str.isdigit() else 0

        if role == 'node' or not role:
            if node_id >= 1000: role = 'spine'
            elif node_id >= 100: role = 'leaf'

        processed.append({
            "id": node_id_str,
            "name": attr.get('name'),
            "model": attr.get('model'),
            "role": role,
            "status": attr.get('fabricSt', 'unknown'),
            "dn": attr.get('dn')
        })
    logger.info(f"ACI fabric nodes processed: {processed}")
    return processed

@router.get("/fabric/nodes")
async def list_fabric_nodes(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    processed = await _get_processed_nodes(aci, loop)

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
    detail_raw = await loop.run_in_executor(None, aci.get_l3out_details, dn)

    # Flatten detail for template
    processed = {"name": dn.split('/')[-1].replace('out-', ''), "dn": dn, "nodes": [], "interfaces": []}
    if detail_raw:
        root = detail_raw[0].get('l3extOut', {})
        children = root.get('children', [])
        for child in children:
            if 'l3extLNodeP' in child:
                node_p = child['l3extLNodeP']['attributes']
                processed['nodes'].append({"name": node_p.get('name'), "dn": node_p.get('dn')})
                # Check for interfaces inside node profile
                for sub in child['l3extLNodeP'].get('children', []):
                    if 'l3extLIfP' in sub:
                        if_p = sub['l3extLIfP']['attributes']
                        processed['interfaces'].append({"name": if_p.get('name'), "node_profile": node_p.get('name')})

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_l3out_detail.html", {"l": processed})
    return processed

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
    routes_raw = await loop.run_in_executor(None, aci.get_bgp_routes, node_id)

    processed = []
    if routes_raw:
        # ACI structure for routes is nested
        for item in routes_raw:
            if 'bgpDom' in item:
                dom_attr = item['bgpDom']['attributes']
                for child in item['bgpDom'].get('children', []):
                    if 'bgpRoute' in child:
                        r_attr = child['bgpRoute']['attributes']
                        processed.append({
                            "prefix": r_attr.get('prefix'),
                            "nextHop": r_attr.get('nextHop'),
                            "origin": r_attr.get('origin'),
                            "asPath": r_attr.get('asPath')
                        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_routes.html", {"node_id": node_id, "routes": processed})
    return {"node_id": node_id, "items": processed}

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

        health = "0"
        for child in item.get('fvAEPg', {}).get('children', []):
            if 'healthInst' in child:
                health = child['healthInst']['attributes'].get('cur', '0')

        processed.append({
            "name": attr.get('name'),
            "tenant": tenant,
            "app_prof": app_prof,
            "dn": dn,
            "health": health
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_epgs.html", {"epgs": processed})
    return {"items": processed}

@router.get("/traffic/epg-health")
async def get_epg_health(request: Request, dn: str, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    data_raw = await loop.run_in_executor(None, aci.get_epg_stats, dn)

    processed = {"dn": dn, "health": "0", "stats": {}}
    if data_raw:
        epg = data_raw[0].get('fvAEPg', {})
        for child in epg.get('children', []):
            if 'healthInst' in child:
                processed['health'] = child['healthInst']['attributes'].get('cur')
            # Add stats parsing here if needed

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_epg_health.html", {"e": processed})
    return processed

@router.get("/health/summary")
async def get_health_summary(session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()

    overall = await loop.run_in_executor(None, _cached, "aci_health_overall", aci.get_overall_health)
    tenants = await loop.run_in_executor(None, _cached, "aci_health_tenants", aci.get_tenant_health)
    pods    = await loop.run_in_executor(None, _cached, "aci_health_pods",    aci.get_pod_health)

    def _extract_health(item, key):
        obj = item.get(key, {})
        for child in obj.get('children', []):
            if 'healthInst' in child:
                return child['healthInst']['attributes'].get('cur', '0')
        return '0'

    res = {
        "overall": _extract_health(overall[0], 'fabricHealthTotal') if overall else '0',
        "tenants": [{"name": t.get('fvTenant', {}).get('attributes', {}).get('name'),
                     "health": _extract_health(t, 'fvTenant')} for t in tenants],
        "pods": [{"id": p.get('fabricPod', {}).get('attributes', {}).get('id'),
                  "health": _extract_health(p, 'fabricPod')} for p in pods]
    }
    return res

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

@router.get("/bgp/peer-routes")
async def get_bgp_peer_routes(request: Request, dn: str, direction: str = "in", session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    routes_raw = await loop.run_in_executor(None, aci.get_bgp_adj_rib, dn, direction)

    processed = []
    cls = "bgpAdjRibIn" if direction == "in" else "bgpAdjRibOut"
    for item in routes_raw:
        attr = item.get(cls, {}).get('attributes', {})
        processed.append({
            "prefix": attr.get('prefix'),
            "nextHop": attr.get('nextHop'),
            "asPath": attr.get('asPath'),
            "origin": attr.get('origin'),
            "status": attr.get('status')
        })

    # Get neighbor IP from DN
    peer_ip = dn.split('peer-[')[-1].rstrip(']') if 'peer-[' in dn else "Unknown"

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_peer_routes.html", {
            "peer_ip": peer_ip,
            "direction": "Received" if direction == "in" else "Advertised",
            "routes": processed
        })
    return {"peer": peer_ip, "direction": direction, "items": processed}
