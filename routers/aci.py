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

from cache import TTL_ACI_STATUS as ACI_TTL

ACI_CACHE_KEYS = [
    "aci_nodes", "aci_l3outs", "aci_bgp_peers", "aci_ospf_peers",
    "aci_epgs", "aci_faults", "aci_subnets", "aci_health_overall",
    "aci_health_tenants", "aci_health_pods", "aci_bgp_doms_all"
]

def _get_aci(session: SessionEntry):
    try:
        return auth_module.get_aci_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"ACI connection failed: {e}")

def _cached(key: str, loader, ttl: int = ACI_TTL):
    """Generic cached fetch helper."""
    def wrapped_loader():
        res = loader()
        if isinstance(res, list):
            res = {"imdata": res}
        return res

    data = cache.get_or_set(key, wrapped_loader, ttl)

    # Final normalization: if data is still a list (from old disk cache), convert to dict
    if isinstance(data, list):
        data = {"imdata": data}

    # Ensure it's a dict for .get() calls in routes, even if None was returned
    return data or {"imdata": []}

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
    nodes_raw = await loop.run_in_executor(None, _cached, "aci_nodes", aci.get_fabric_nodes)
    nodes = nodes_raw.get('imdata', [])
    logger.info(f"ACI fabric nodes raw count: {len(nodes)}")

    route_counts = {}
    try:
        # Fetch BGP route counts for all nodes
        doms_raw = await loop.run_in_executor(None, _cached, "aci_bgp_doms_all", aci.get_all_bgp_doms)
        doms = doms_raw.get('imdata', [])
        logger.info(f"ACI BGP DOMs raw count: {len(doms)}")

        for item in doms:
            # item is {"bgpDomAf": {"attributes": {...}}}
            obj_name = next(iter(item)) if item else None
            obj = item.get(obj_name)
            if not obj:
                continue

            attr = obj.get('attributes', {})
            dn = attr.get('dn', '')
            # Extract node ID from DN: topology/pod-1/node-101/...
            node_id = next((p.replace('node-', '') for p in dn.split('/') if p.startswith('node-')), None)

            if node_id:
                # Sum up count from attributes
                count = int(attr.get('count') or 0)
                route_counts[node_id] = route_counts.get(node_id, 0) + count
        logger.info(f"ACI route counts calculated: {route_counts}")
    except Exception as e:
        logger.warning(f"Failed to calculate ACI route counts: {e}")

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
            "dn": attr.get('dn'),
            "route_count": route_counts.get(node_id_str, 0)
        })
    logger.info(f"ACI fabric nodes processed: {processed}")
    return processed, nodes_raw

@router.get("/fabric/nodes")
async def list_fabric_nodes(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    processed, nodes_raw = await _get_processed_nodes(aci, loop)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_nodes.html", {
            "nodes": processed,
            "raw_json": nodes_raw
        })
    return {"items": processed, "raw": nodes_raw}

# ── L3Outs ────────────────────────────────────────────────────────────────────

@router.get("/l3outs")
async def list_l3outs(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    l3outs_raw = await loop.run_in_executor(None, _cached, "aci_l3outs", aci.get_l3outs)

    processed = []
    for item in l3outs_raw.get('imdata', []):
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
        return templates.TemplateResponse(request, "partials/aci_l3outs.html", {
            "l3outs": processed,
            "raw_json": l3outs_raw
        })
    return {"items": processed, "raw": l3outs_raw}

@router.get("/l3outs/detail")
async def get_l3out_detail(request: Request, dn: str, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    detail_raw_orig = await loop.run_in_executor(None, aci.get_l3out_details, dn)

    if isinstance(detail_raw_orig, list):
        detail_raw = {"imdata": detail_raw_orig}
    elif detail_raw_orig is None:
        detail_raw = {"imdata": []}
    else:
        detail_raw = detail_raw_orig

    # Flatten detail for template
    processed = {"name": dn.split('/')[-1].replace('out-', '') if '/' in dn else dn, "dn": dn, "nodes": [], "interfaces": []}
    imdata = detail_raw.get('imdata', [])
    if imdata:
        root = imdata[0].get('l3extOut', {})
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
        return templates.TemplateResponse(request, "partials/aci_l3out_detail.html", {
            "l": processed,
            "raw_json": detail_raw
        })
    return {"item": processed, "raw": detail_raw}

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
    for entry in subnets_raw.get('imdata', []):
        attr = entry.get('l3extSubnet', {}).get('attributes', {})
        if 'export-rtctrl' in attr.get('scope', ''):
            dn_parts = attr.get('dn', '').split('/')
            l3out = next((p.replace('out-', '') for p in dn_parts if p.startswith('out-')), "N/A")
            ads_map.setdefault(l3out, []).append(attr.get('ip'))

    processed = []
    for entry in peers_raw.get('imdata', []):
        attr = entry.get('bgpPeerEntry', {}).get('attributes', {})
        dn = attr.get('dn', '')
        dn_parts = dn.split('/')
        l3out = next((p.replace('out-', '') for p in dn_parts if p.startswith('out-')), "N/A")

        # Get node ID from DN: topology/pod-1/node-101/...
        node_id = next((p.replace('node-', '') for p in dn_parts if p.startswith('node-')), "N/A")

        # Get VRF from DN: .../dom-NAME/...
        vrf = next((p.replace('dom-', '') for p in dn_parts if p.startswith('dom-')), "N/A")

        # More flexible DN mapping for routes - find the base sys DN
        # topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[10.255.0.1] -> topology/pod-1/node-101
        base_dn = "/".join(dn_parts[:3]) if len(dn_parts) >= 3 else ""

        processed.append({
            "base_dn": base_dn,
            "node": node_id,
            "l3out": l3out,
            "vrf": vrf,
            "type": attr.get('type', 'unknown').upper(),
            "addr": attr.get('addr'),
            "state": attr.get('operSt', 'unknown').upper(),
            "nets": ads_map.get(l3out, ["No Export Subnets"]),
            "dn": dn
        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_peers.html", {
            "peers": processed,
            "raw_json": peers_raw
        })
    return {"items": processed, "raw": peers_raw}

@router.get("/bgp/routes")
async def get_bgp_routes(request: Request, node_id: str = None, dn: str = None, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    target = dn or node_id
    routes_raw_orig = await loop.run_in_executor(None, aci.get_bgp_routes, target)

    # Normalize routes_raw to ensure it's a dict with imdata
    if isinstance(routes_raw_orig, list):
        routes_raw = {"imdata": routes_raw_orig}
    elif routes_raw_orig is None:
        routes_raw = {"imdata": []}
    else:
        routes_raw = routes_raw_orig

    processed = []
    imdata = routes_raw.get('imdata', [])
    route_classes = {'bgpRoute', 'bgpBdpRoute', 'bgpEvpnRoute'}

    for item in imdata:
        cls_name = next(iter(item)) if item else None
        if cls_name in route_classes:
            attr = item[cls_name].get('attributes', {})
            dn = attr.get('dn', '')
            # Extract VRF from DN: .../dom-NAME/af-...
            vrf = "unknown"
            if 'dom-' in dn:
                vrf = dn.split('dom-')[-1].split('/')[0]

            processed.append({
                "vrf": vrf,
                "prefix": attr.get('prefix') or attr.get('pfx'),
                "nextHop": attr.get('nextHop') or attr.get('nh'),
                "origin": attr.get('origin'),
                "asPath": attr.get('asPath')
            })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_routes.html", {
            "node_id": node_id or (target.split('/')[-1] if target and '/' in target else target) or "Unknown",
            "routes": processed,
            "raw_json": routes_raw
        })
    return {"node_id": node_id or (target.split('/')[-1] if target and '/' in target else target) or "Unknown", "items": processed, "raw": routes_raw}

# ── Traffic & EPGs ───────────────────────────────────────────────────────────

@router.get("/traffic/epgs")
async def list_epgs(request: Request, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    epgs_raw = await loop.run_in_executor(None, _cached, "aci_epgs", aci.get_epgs)

    processed = []
    for item in epgs_raw.get('imdata', []):
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
        return templates.TemplateResponse(request, "partials/aci_epgs.html", {
            "epgs": processed,
            "raw_json": epgs_raw
        })
    return {"items": processed, "raw": epgs_raw}

@router.get("/traffic/epg-health")
async def get_epg_health(request: Request, dn: str, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    data_raw_orig = await loop.run_in_executor(None, aci.get_epg_stats, dn)

    if isinstance(data_raw_orig, list):
        data_raw = {"imdata": data_raw_orig}
    elif data_raw_orig is None:
        data_raw = {"imdata": []}
    else:
        data_raw = data_raw_orig

    processed = {"dn": dn, "health": "0", "stats": {}}
    imdata = data_raw.get('imdata', [])
    if imdata:
        epg = imdata[0].get('fvAEPg', {})
        for child in epg.get('children', []):
            if 'healthInst' in child:
                processed['health'] = child['healthInst']['attributes'].get('cur')
            # Add stats parsing here if needed

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_epg_health.html", {
            "e": processed,
            "raw_json": data_raw
        })
    return {"item": processed, "raw": data_raw}

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

    overall_imdata = overall.get('imdata', []) if overall else []
    tenants_imdata = tenants.get('imdata', []) if tenants else []
    pods_imdata    = pods.get('imdata', [])    if pods else []

    res = {
        "overall": _extract_health(overall_imdata[0], 'fabricHealthTotal') if overall_imdata else '0',
        "tenants": [{"name": t.get('fvTenant', {}).get('attributes', {}).get('name'),
                     "health": _extract_health(t, 'fvTenant')} for t in tenants_imdata],
        "pods": [{"id": p.get('fabricPod', {}).get('attributes', {}).get('id'),
                  "health": _extract_health(p, 'fabricPod')} for p in pods_imdata]
    }
    return res

@router.get("/traffic/faults")
async def list_faults(request: Request, severity: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    faults_raw = await loop.run_in_executor(None, aci.get_faults, severity)

    processed = []
    for f in faults_raw.get('imdata', []):
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
        return templates.TemplateResponse(request, "partials/aci_faults.html", {
            "faults": processed,
            "raw_json": faults_raw
        })
    return {"items": processed, "raw": faults_raw}

@router.get("/bgp/peer-routes")
async def get_bgp_peer_routes(request: Request, dn: str, direction: str = "in", session: SessionEntry = Depends(require_auth)):
    aci = _get_aci(session)
    loop = asyncio.get_event_loop()
    routes_raw_orig = await loop.run_in_executor(None, aci.get_bgp_adj_rib, dn, direction)

    if isinstance(routes_raw_orig, list):
        routes_raw = {"imdata": routes_raw_orig}
    elif routes_raw_orig is None:
        routes_raw = {"imdata": []}
    else:
        routes_raw = routes_raw_orig

    processed = []
    cls = "bgpAdjRibIn" if direction == "in" else "bgpAdjRibOut"
    for item in routes_raw.get('imdata', []):
        attr = item.get(cls, {}).get('attributes', {})
        processed.append({
            "prefix": attr.get('prefix'),
            "nextHop": attr.get('nextHop'),
            "asPath": attr.get('asPath'),
            "origin": attr.get('origin'),
            "status": attr.get('status')
        })

    # Get neighbor IP from DN
    peer_ip = dn.split('peer-[')[-1].split(']')[0] if 'peer-[' in dn else "Unknown"

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_peer_routes.html", {
            "peer_ip": peer_ip,
            "direction": "Received" if direction == "in" else "Advertised",
            "routes": processed,
            "raw_json": routes_raw
        })
    return {"peer": peer_ip, "direction": direction, "items": processed, "raw": routes_raw}
