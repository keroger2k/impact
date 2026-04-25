"""
routers/aci.py — Cisco ACI API endpoints.

This module provides access to ACI fabric data including nodes, interfaces,
L3Outs, and BGP operational state. It supports multi-fabric configurations
and handles aggregated views across all fabrics.
"""

import asyncio
import logging
import re
from collections import defaultdict
from typing import Optional, List, Dict, Any, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

import auth as auth_module
import clients.aci as ac
from auth import SessionEntry, require_auth
from cache import cache
from logger_config import run_with_context

router = APIRouter()
logger = logging.getLogger(__name__)

# Distinguished Name validation regex
ACI_DN_RE = re.compile(r'^[\w\-./\[\]:,]+$')

def _validate_dn(dn: str):
    """Ensure the provided DN string is well-formed before sending to APIC."""
    if not dn or not ACI_DN_RE.match(dn):
        raise HTTPException(400, f"Invalid DN format: {dn!r}")

def get_fabric_id(request: Request) -> str:
    """
    Dependency to resolve the target ACI fabric ID from the request.
    Precedence: X-ACI-Fabric header > ?fabric= query param > impact_aci_fabric cookie > default.
    """
    import clients.aci_registry as reg
    fabrics = reg.list_fabrics()
    default_id = fabrics[0].id if fabrics else "default"

    # 1. Header
    fid = request.headers.get("X-ACI-Fabric")

    # 2. Query param
    if not fid:
        fid = request.query_params.get("fabric")

    # 3. Cookie
    if not fid:
        fid = request.cookies.get("impact_aci_fabric")

    # Validation and Fallback
    if not fid or fid == "all":
        return default_id

    return fid

from cache import TTL_ACI_STATUS as ACI_TTL

# Standard keys used for namespacing ACI cache entries
ACI_CACHE_KEYS = [
    "nodes", "l3outs", "bgp_peers", "bgp_peer_cfg",
    "ospf_peers", "epgs", "faults", "subnets",
    "health_overall", "health_tenants", "health_pods",
    "bgp_doms_all", "bgp_adj_rib_out", "bgp_adj_rib_in"
]

def _fkey(fabric_id: str, suffix: str) -> str:
    """Helper to generate a namespaced cache key for a specific fabric."""
    return f"aci_{fabric_id}_{suffix}"

async def _get_aci_async(session: SessionEntry, fabric_id: str) -> ac.ACIClient:
    """Async helper to retrieve the ACI client for a session/fabric, offloading login if needed."""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(
            None, run_with_context(auth_module.get_aci_for_session),
            session, fabric_id
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get ACI client for fabric {fabric_id}: {e}")
        raise HTTPException(503, f"ACI connection failed for fabric {fabric_id}: {e}")

def _cached(key: str, loader, ttl: int = ACI_TTL):
    """
    Generic cached fetch helper.
    Ensures imdata structure and handles legacy list formats from disk cache.
    """
    def wrapped_loader():
        res = loader()
        if isinstance(res, list):
            res = {"imdata": res}
        return res

    data = cache.get_or_set(key, wrapped_loader, ttl)

    # Normalize response to dict with imdata
    if isinstance(data, list):
        data = {"imdata": data}

    return data or {"imdata": []}

# ── Fabrics ───────────────────────────────────────────────────────────────────

@router.get("/fabrics")
async def list_fabrics():
    """Return the list of configured ACI fabrics for the UI picker."""
    import clients.aci_registry as reg
    return [{"id": f.id, "label": f.label, "url": f.url} for f in reg.list_fabrics()]

# ── Cache management ──────────────────────────────────────────────────────────

@router.get("/cache/info")
async def aci_cache_info():
    """Return cache metadata grouped by fabric."""
    import clients.aci_registry as reg
    fabrics = reg.list_fabrics()
    results = {}

    for f in fabrics:
        fabric_keys = [f"aci_{f.id}_{k}" for k in ACI_CACHE_KEYS]
        infos = {k: cache.cache_info(k) for k in fabric_keys}

        # Find the oldest valid timestamp to represent fabric "freshness"
        valid_ts = [v["set_at"] for v in infos.values() if v]

        results[f.id] = {
            "label": f.label,
            "oldest_at": min(valid_ts) if valid_ts else None,
            "keys": infos
        }
    return results

@router.post("/cache/refresh")
async def refresh_aci_cache(fabric: Optional[str] = None):
    """Invalidate ACI cache entries, optionally scoped to a single fabric."""
    if fabric:
        cache.invalidate_prefix(f"aci_{fabric}_")
        return {"status": f"ACI cache for {fabric} cleared"}
    else:
        cache.invalidate_prefix("aci_")
        return {"status": "All ACI caches cleared"}

# ── Fabric Nodes ──────────────────────────────────────────────────────────────

_APIC_FANOUT_SEM: Optional[asyncio.Semaphore] = None

def get_apic_sem() -> asyncio.Semaphore:
    """Lazy initializer for the APIC concurrency semaphore."""
    global _APIC_FANOUT_SEM
    if _APIC_FANOUT_SEM is None:
        _APIC_FANOUT_SEM = asyncio.Semaphore(8)
    return _APIC_FANOUT_SEM

async def _get_processed_nodes(aci: ac.ACIClient, loop: asyncio.AbstractEventLoop, fabric_id: str) -> Tuple[List[Dict], Dict]:
    """Fetch and normalize fabric nodes with aggregated BGP route counts."""
    # 1. Fetch raw nodes
    nodes_raw = await loop.run_in_executor(
        None, run_with_context(_cached),
        _fkey(fabric_id, "nodes"),
        aci.get_fabric_nodes
    )
    nodes_list = nodes_raw.get('imdata', [])

    # 2. Fetch BGP DOMs to calculate route counts per node
    route_counts = {}
    try:
        doms_raw = await loop.run_in_executor(
            None, run_with_context(_cached),
            _fkey(fabric_id, "bgp_doms_all"),
            aci.get_all_bgp_doms
        )

        for item in doms_raw.get('imdata', []):
            obj_name = next(iter(item)) if item else None
            obj = item.get(obj_name)
            if not obj:
                continue

            attr = obj.get('attributes', {})
            dn = attr.get('dn', '')

            # Extract node ID from DN: topology/pod-1/node-101/sys/bgp/inst/dom-default/af-ipv4-ucast
            node_match = re.search(r'node-(\d+)', dn)
            if node_match:
                node_id = node_match.group(1)
                count = int(attr.get('count') or 0)
                route_counts[node_id] = route_counts.get(node_id, 0) + count
    except Exception as e:
        logger.warning(f"Failed to calculate ACI route counts for {fabric_id}: {e}")

    # 3. Process and normalize
    processed = []
    for n in nodes_list:
        attr = n.get('fabricNode', {}).get('attributes', {})
        role = attr.get('role', 'unknown')
        node_id_str = attr.get('id', '0')
        node_id = int(node_id_str) if node_id_str.isdigit() else 0

        # Heuristic for role if missing
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

    return processed, nodes_raw

@router.get("/fabric/nodes")
async def list_fabric_nodes(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """List fabric nodes, supporting 'all' fabrics aggregation."""
    import clients.aci_registry as reg
    loop = asyncio.get_event_loop()

    if request.query_params.get("fabric") == "all":
        fabrics = reg.list_fabrics()

        async def _fetch_single(f):
            try:
                aci = await _get_aci_async(session, f.id)
                p, raw = await _get_processed_nodes(aci, loop, f.id)
                # Inject fabric metadata for aggregated table
                for n in p:
                    n.update({"fabric_id": f.id, "fabric_label": f.label})
                return p, raw
            except Exception as e:
                logger.error(f"Aggregated node fetch failed for {f.id}: {e}")
                return [], {"imdata": []}

        results = await asyncio.gather(*[_fetch_single(f) for f in fabrics])

        # Merge results
        processed = []
        merged_imdata = []
        for p, raw in results:
            processed.extend(p)
            merged_imdata.extend(raw.get("imdata", []))
        nodes_raw = {"imdata": merged_imdata}
    else:
        aci = await _get_aci_async(session, fabric_id)
        processed, nodes_raw = await _get_processed_nodes(aci, loop, fabric_id)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_nodes.html", {
            "nodes": processed,
            "raw_json": nodes_raw
        })

    return {"items": processed, "raw": nodes_raw}

# ── Node Interfaces ───────────────────────────────────────────────────────────

@router.get("/nodes/{node_id}/interfaces")
async def get_node_interfaces(
    request: Request,
    node_id: str,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """
    Detailed interface view for a node.
    Joins physical ports with operational state, Port-Channels, and vPCs.
    """
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    # 1. Resolve Node DN
    nodes_proc, _ = await _get_processed_nodes(aci, loop, fabric_id)
    node = next((n for n in nodes_proc if n["id"] == node_id), None)
    if not node:
        raise HTTPException(404, f"Node {node_id} not found in fabric {fabric_id}")

    # 2. Fetch Subtree Data
    cache_key = _fkey(fabric_id, f"node_{node_id}_interfaces")
    raw = await loop.run_in_executor(
        None, run_with_context(_cached),
        cache_key,
        lambda: aci.get_node_interfaces(node["dn"]),
        300 # 5 min TTL for operational port data
    )
    imdata = raw.get("imdata", [])

    # 3. Join Logic
    phys_ifs = {}     # dn -> attributes
    pc_ifs = {}       # dn -> attributes + members list
    member_to_pc = {}   # phys_dn -> pc_dn
    pc_to_vpc = {}      # pc_dn -> vpc_id
    lacp_states = {}    # phys_dn -> lacp state (from pcAggrMbrIf channelingSt)

    for item in imdata:
        if "l1PhysIf" in item:
            attr = item["l1PhysIf"]["attributes"]
            phys_ifs[attr["dn"]] = {
                **attr,
                "operSt": "unknown",
                "operSpeed": "inherit",
                "operDuplex": "auto",
                "lastChange": "",
                "operVlans": "",
                "allowedVlans": "",
                "cfgAccessVlan": "",
                "bundleIndex": "unspecified",
                "operStQual": ""
            }
        elif "ethpmPhysIf" in item:
            attr = item["ethpmPhysIf"]["attributes"]
            # Deliverable 2d: more robust split for bracketed DNs
            parent_dn = attr["dn"].rsplit("/phys", 1)[0]
            if parent_dn in phys_ifs:
                phys_ifs[parent_dn].update({
                    "operSt": attr.get("operSt"),
                    "operSpeed": attr.get("operSpeed"),
                    "operDuplex": attr.get("operDuplex"),
                    "lastChange": attr.get("lastLinkStChg"),
                    "operVlans": attr.get("operVlans"),
                    "allowedVlans": attr.get("allowedVlans"),
                    "cfgAccessVlan": attr.get("cfgAccessVlan"),
                    "bundleIndex": attr.get("bundleIndex"),
                    "operStQual": attr.get("operStQual")
                })
        elif "pcAggrIf" in item:
            attr = item["pcAggrIf"]["attributes"]
            pc_ifs[attr["dn"]] = {**attr, "vpc": "", "members": []}
        elif "pcRsMbrIfs" in item:
            attr = item["pcRsMbrIfs"]["attributes"]
            # DN: .../aggr-[po10]/rsmbrIfs-[.../phys-[eth1/31]]
            # Parent is PC, tDn is physical port
            pc_dn = attr["dn"].split("/rsmbrIfs-")[0]
            phys_dn = attr.get("tDn")
            if phys_dn:
                member_to_pc[phys_dn] = pc_dn
        elif "pcAggrMbrIf" in item:
            attr = item["pcAggrMbrIf"]["attributes"]
            # DN: topology/pod-1/node-208/sys/phys-[eth1/32]/aggrmbrif
            phys_dn = attr["dn"].rsplit("/aggrmbrif", 1)[0]
            if phys_dn in phys_ifs:
                lacp_states[phys_dn] = attr.get("channelingSt")
        elif "vpcRsVpcConf" in item:
            attr = item["vpcRsVpcConf"]["attributes"]
            # parentSKey is usually the numerical vPC ID
            vpc_id = attr.get("parentSKey")
            if vpc_id:
                vpc_id = f"vPC-{vpc_id}"
            pc_to_vpc[attr["tDn"]] = vpc_id

    # Cross-reference members into PCs
    for phys_dn, pc_dn in member_to_pc.items():
        if pc_dn in pc_ifs:
            pc_id = phys_ifs[phys_dn]["id"] if phys_dn in phys_ifs else "??"
            pc_ifs[pc_dn]["members"].append(pc_id)

    # 4. Final Normalization
    interfaces = []
    for dn, p in phys_ifs.items():
        target_pc_dn = member_to_pc.get(dn)
        pc_obj = pc_ifs.get(target_pc_dn) if target_pc_dn else None

        # For description, fall back to PC name if the physical port descr is empty
        descr = p.get("descr")
        if not descr and pc_obj:
            descr = pc_obj.get("name")

        interfaces.append({
            "id": p.get("id", "??"),
            "descr": descr or "",
            "adminSt": p.get("adminSt", "unknown"),
            "operSt": p.get("operSt", "unknown"),
            "adminSpeed": p.get("speed", "inherit"),
            "operSpeed": p.get("operSpeed", "inherit"),
            "operDuplex": p.get("operDuplex", "auto"),
            "mtu": p.get("mtu", "inherit"),
            "layer": p.get("layer", "Layer2"),
            "mode": p.get("mode", "trunk"),
            "switchingSt": p.get("switchingSt", "disabled"),
            "usage": p.get("usage", "discovery"),
            "portT": p.get("portT", "leaf"),
            "operVlans": p.get("operVlans", ""),
            "allowedVlans": p.get("allowedVlans", "") or p.get("cfgAccessVlan", ""),
            "bundleIndex": p.get("bundleIndex", "unspecified"),
            "operStQual": p.get("operStQual", "none"),
            "channel": pc_obj.get("id", "") if pc_obj else "",
            "lacp": pc_obj.get("pcMode", "") if pc_obj else "",
            "lacp_state": lacp_states.get(dn, ""),
            "vpc": pc_to_vpc.get(target_pc_dn, "") if target_pc_dn else "",
            "last_change": p.get("lastChange", "")
        })

    aggregates = []
    for dn, a in pc_ifs.items():
        aggregates.append({
            "id": a.get("id", "??"),
            "pcMode": a.get("pcMode", ""),
            "members": a.get("members", []),
            "vpc": pc_to_vpc.get(dn, ""),
            "operSt": a.get("operSt", "unknown"),
            "name": a.get("name", "")
        })

    # 5. Build Front Panel structure
    def _parse_port(port_id):
        m = re.match(r"eth(\d+)/(\d+)", port_id or "")
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    modules = defaultdict(lambda: {"access": [], "uplink": []})
    for i in interfaces:
        mod, port = _parse_port(i["id"])
        bucket = "uplink" if i.get("portT") == "fab" else "access"
        modules[mod][bucket].append({**i, "port_num": port})

    panel = []
    for mod in sorted(modules.keys()):
        acc = sorted(modules[mod]["access"], key=lambda p: p["port_num"])
        upl = sorted(modules[mod]["uplink"], key=lambda p: p["port_num"])
        panel.append({
            "module":        mod,
            "access_top":    [p for p in acc if p["port_num"] % 2 == 1],
            "access_bottom": [p for p in acc if p["port_num"] % 2 == 0],
            "uplink_top":    [p for p in upl if p["port_num"] % 2 == 1],
            "uplink_bottom": [p for p in upl if p["port_num"] % 2 == 0],
        })

    node_name = node.get("name") if node else f"Node-{node_id}"

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_node_interfaces.html", {
            "node_id": node_id,
            "node_name": node_name,
            "interfaces": interfaces,
            "aggregates": aggregates,
            "panel": panel,
            "raw_json": raw
        })

    return {
        "node_id": node_id,
        "node_name": node_name,
        "interfaces": interfaces,
        "aggregates": aggregates,
        "panel": panel,
        "raw": raw
    }

# ── L3Outs ────────────────────────────────────────────────────────────────────

@router.get("/l3outs")
async def list_l3outs(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """List L3Out configurations across the fabric."""
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    l3outs_raw = await loop.run_in_executor(
        None, run_with_context(_cached),
        _fkey(fabric_id, "l3outs"),
        aci.get_l3outs
    )

    processed = []
    for item in l3outs_raw.get('imdata', []):
        attr = item.get('l3extOut', {}).get('attributes', {})
        dn = attr.get('dn', '')
        # uni/tn-COMMON/out-INET
        tenant = dn.split('/')[1].replace('tn-', '') if '/' in dn else '?'

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
async def get_l3out_detail(
    request: Request,
    dn: str,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """Drill down into a specific L3Out to see associated nodes and interfaces."""
    _validate_dn(dn)
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    detail_raw = await loop.run_in_executor(None, run_with_context(aci.get_l3out_details), dn)
    if isinstance(detail_raw, list):
        detail_raw = {"imdata": detail_raw}

    # Flatten structure for template
    processed = {
        "name": dn.split('/')[-1].replace('out-', ''),
        "dn": dn,
        "nodes": [],
        "interfaces": []
    }

    imdata = detail_raw.get('imdata', [{}])
    if imdata:
        root = imdata[0].get('l3extOut', {})
        children = root.get('children', [])
        for child in children:
            if 'l3extLNodeP' in child:
                node_p = child['l3extLNodeP']['attributes']
                processed['nodes'].append({
                    "name": node_p.get('name'),
                    "dn": node_p.get('dn')
                })
                # Nested interface profiles
                for sub in child['l3extLNodeP'].get('children', []):
                    if 'l3extLIfP' in sub:
                        if_p = sub['l3extLIfP']['attributes']
                        processed['interfaces'].append({
                            "name": if_p.get('name'),
                            "node_profile": node_p.get('name')
                        })

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_l3out_detail.html", {
            "l": processed,
            "raw_json": detail_raw
        })

    return processed

# ── BGP Troubleshooting ────────────────────────────────────────────────────────

async def _get_processed_bgp_peers(aci: ac.ACIClient, loop: asyncio.AbstractEventLoop, fabric_id: str) -> Tuple[List[Dict], Dict]:
    """Fetch and correlate BGP operational state with policy (L3Out mapping)."""
    peers_raw, subnets_raw, peer_cfg_raw = await asyncio.gather(
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peers"), aci.get_bgp_peers),
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "subnets"), aci.get_l3_subnets),
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peer_cfg"), aci.get_bgp_peer_configs),
    )

    # 1. Map Peer IPs to L3Outs using Policy-space objects (bgpPeerP)
    peer_to_l3out = {}
    for entry in peer_cfg_raw.get('imdata', []):
        attr = entry.get('bgpPeerP', {}).get('attributes', {})
        addr = attr.get('addr', '').split('/')[0]
        # DN: uni/tn-COMMON/out-INET/lnodep-L101/lifp-L101/peerP-[1.1.1.1]
        l3out = next((p.replace('out-', '') for p in attr.get('dn', '').split('/') if p.startswith('out-')), None)
        if addr and l3out:
            peer_to_l3out[addr] = l3out

    # 2. Map Export Subnets to L3Outs
    ads_map = {}
    for entry in subnets_raw.get('imdata', []):
        attr = entry.get('l3extSubnet', {}).get('attributes', {})
        if 'export-rtctrl' in attr.get('scope', ''):
            l3out = next((p.replace('out-', '') for p in attr.get('dn', '').split('/') if p.startswith('out-')), None)
            if l3out:
                ads_map.setdefault(l3out, []).append(attr.get('ip'))

    # 3. Process Operational Peer State
    processed = []
    for entry in peers_raw.get('imdata', []):
        attr = entry.get('bgpPeerEntry', {}).get('attributes', {})
        dn = attr.get('dn', '')
        peer_addr = attr.get('addr', '').split('/')[0]
        l3out = peer_to_l3out.get(peer_addr, 'N/A')

        # Extract basic hierarchy
        dn_parts = dn.split('/')
        node_id = next((p.replace('node-', '') for p in dn_parts if p.startswith('node-')), "N/A")
        vrf = next((p.replace('dom-', '') for p in dn_parts if p.startswith('dom-')), "N/A")

        processed.append({
            "node": node_id,
            "vrf": vrf,
            "l3out": l3out,
            "addr": attr.get('addr'),
            "state": attr.get('operSt', 'unknown').upper(),
            "type": attr.get('type', 'unknown'),
            "nets": ads_map.get(l3out, ["No Export Subnets"]),
            "dn": dn,
            "base_dn": "/".join(dn_parts[:3]) if len(dn_parts) >= 3 else "" # topology/pod-1/node-101
        })

    return processed, peers_raw

@router.get("/bgp/peers")
async def list_bgp_peers(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """List BGP neighbors and their adjacency states."""
    import clients.aci_registry as reg
    loop = asyncio.get_event_loop()

    if request.query_params.get("fabric") == "all":
        async def _fetch_single(f):
            try:
                aci = await _get_aci_async(session, f.id)
                p, raw = await _get_processed_bgp_peers(aci, loop, f.id)
                for x in p:
                    x.update({"fabric_id": f.id, "fabric_label": f.label})
                return p, raw
            except Exception:
                return [], {"imdata": []}

        results = await asyncio.gather(*[_fetch_single(f) for f in reg.list_fabrics()], return_exceptions=True)

        processed = []
        peers_raw = {"imdata": []}
        for res in results:
            if isinstance(res, tuple):
                p, raw = res
                processed.extend(p)
                peers_raw["imdata"].extend(raw.get("imdata", []))
    else:
        aci = await _get_aci_async(session, fabric_id)
        processed, peers_raw = await _get_processed_bgp_peers(aci, loop, fabric_id)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_peers.html", {
            "peers": processed,
            "raw_json": peers_raw
        })

    return {"items": processed, "raw": peers_raw}

@router.get("/bgp/diagnose")
async def bgp_diagnose(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """Diagnostic report for BGP visibility issues in production."""
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    async def _run_diagnostics():
        # 1. Tenants, Version, RIB-In Class, and Peer Count
        tenants_raw, version_raw, rib_in_raw, peer_data_raw = await asyncio.gather(
            loop.run_in_executor(None, run_with_context(aci.get), "api/node/class/fvTenant.json"),
            loop.run_in_executor(None, run_with_context(aci.get), "api/node/class/firmwareCtrlrRunning.json"),
            loop.run_in_executor(None, run_with_context(aci.get), "api/node/class/bgpAdjRibIn.json?rsp-subtree-include=count"),
            loop.run_in_executor(None, run_with_context(aci.get_bgp_peers))
        )

        # 2. Per-leaf count
        nodes_proc, _ = await _get_processed_nodes(aci, loop, fabric_id)
        leaves = [n for n in nodes_proc if n["role"] == "leaf"]

        async def _get_count(n):
            async with get_apic_sem():
                # Corrected: api/node/mo/... instead of api/node/class/...
                res = await loop.run_in_executor(
                    None, run_with_context(aci.get),
                    f"api/node/mo/topology/pod-1/node-{n['id']}/sys/bgp.json?query-target=subtree&target-subtree-class=bgpAdjRibIn&rsp-subtree-include=count"
                )
                count = res.get("imdata", [{}])[0].get("moCount", {}).get("attributes", {}).get("count", 0)
                return n["id"], int(count)

        counts = await asyncio.gather(*[_get_count(l) for l in leaves])

        # 3. Soft-reconfig check
        peer_pfx_pols = await loop.run_in_executor(None, run_with_context(aci.get), "api/node/class/bgpPeerPfxPol.json")
        soft_reconfig_map = {
            p.get("bgpPeerPfxPol", {}).get("attributes", {}).get("dn"): p.get("bgpPeerPfxPol", {}).get("attributes", {}).get("action") == "permit"
            for p in peer_pfx_pols.get("imdata", [])
        }

        return {
            "user_readable_tenants": [t.get("fvTenant", {}).get("attributes", {}).get("name") for t in tenants_raw.get("imdata", [])],
            "apic_version": version_raw.get("imdata", [{}])[0].get("firmwareCtrlrRunning", {}).get("attributes", {}).get("version"),
            "bgp_peer_count": len(peer_data_raw.get("imdata", [])),
            "class_query_adj_rib_in": int(rib_in_raw.get("imdata", [{}])[0].get("moCount", {}).get("attributes", {}).get("count", 0)),
            "per_node_adj_rib_in": dict(counts)
        }

    try:
        return await asyncio.wait_for(_run_diagnostics(), timeout=60.0)
    except asyncio.TimeoutError:
        raise HTTPException(504, f"ACI diagnostics timed out for fabric {fabric_id} after 60s")

# ── BGP Route Aggregation Helpers ───────────────────────────────────────────

def _parse_adj_rib_dn(dn: str) -> Tuple[str, str, str]:
    """Extract node, vrf, and peer_ip from an Adj-RIB-In/Out DN."""
    parts = dn.split('/')
    node_id = next((p.replace('node-', '') for p in parts if p.startswith('node-')), 'N/A')
    vrf = next((p.replace('dom-', '') for p in parts if p.startswith('dom-')), 'N/A')
    # peer-[1.1.1.1] or peer-[1.1.1.1/32]
    peer_seg = next((p for p in parts if p.startswith('peer-[')), '')
    peer_ip = peer_seg[6:].rstrip(']').split('/')[0] if peer_seg else 'N/A'
    return node_id, vrf, peer_ip

def _build_adj_rib_rows(raw: Dict, cls: str, peer_to_l3out: Dict) -> List[Dict]:
    """Transform raw Adj-RIB-In/Out objects into flat table rows."""
    rows = []
    if not raw or not isinstance(raw, dict):
        return rows
    for item in raw.get('imdata', []):
        attr = item.get(cls, {}).get('attributes', {})
        if not attr:
            continue

        dn = attr.get('dn', '')
        if 'overlay-1' in dn:
            continue

        node_id, vrf, peer_ip = _parse_adj_rib_dn(dn)
        rows.append({
            "node": node_id,
            "vrf": vrf,
            "peer": peer_ip,
            "l3out": peer_to_l3out.get(peer_ip, 'N/A'),
            "prefix": attr.get('prefix') or attr.get('pfx', ''),
            "nextHop": attr.get('nextHop') or attr.get('nh', ''),
            "asPath": attr.get('asPath', ''),
            "origin": attr.get('origin', ''),
            "flags": attr.get('flags') or attr.get('status', ''),
            "localPref": attr.get('localPref', ''),
            "med": attr.get('med', ''),
            "community": attr.get('community', '')
        })
    return rows

async def _fetch_bgp_rib_aggregated(
    aci: ac.ACIClient,
    loop: asyncio.AbstractEventLoop,
    fabric_id: str,
    direction: str
) -> Tuple[List[Dict], Dict]:
    """Fetch BGP RIB using a parallel per-leaf strategy with class-level fallback."""
    cls = "bgpAdjRibIn" if direction == "in" else "bgpAdjRibOut"

    # 1. Prepare Leaf List and L3Out Mapping
    nodes_proc, _ = await _get_processed_nodes(aci, loop, fabric_id)
    leaves = [n for n in nodes_proc if n["role"] == "leaf"]

    _, _, peer_cfg_raw = await asyncio.gather(
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peers"), aci.get_bgp_peers),
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "subnets"), aci.get_l3_subnets),
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peer_cfg"), aci.get_bgp_peer_configs),
    )

    peer_to_l3out = {}
    for entry in peer_cfg_raw.get('imdata', []):
        attr = entry.get('bgpPeerP', {}).get('attributes', {})
        addr = attr.get('addr', '').split('/')[0]
        l3out = next((p.replace('out-', '') for p in attr.get('dn', '').split('/') if p.startswith('out-')), None)
        if addr and l3out:
            peer_to_l3out[addr] = l3out

    # 2. Parallel Fetch per Leaf
    async def _fetch_node(n):
        try:
            async with get_apic_sem():
                return await loop.run_in_executor(
                    None, run_with_context(aci.get_bgp_rib_for_node),
                    n["dn"], direction
                )
        except Exception as e:
            logger.warning(f"Failed to fetch BGP RIB for node {n['id']} in {fabric_id}: {e}")
            return {"imdata": []}

    results = await asyncio.gather(*[_fetch_node(l) for l in leaves])
    all_raw = {"imdata": [item for res in results if res and "imdata" in res for item in res["imdata"]]}
    rows = _build_adj_rib_rows(all_raw, cls, peer_to_l3out)

    # 3. Fallback to Class-level if leaf-fetch returned nothing
    if not rows:
        logger.info(f"Per-leaf BGP RIB fetch for {fabric_id} returned 0 rows, falling back to class-level.")
        class_raw = await loop.run_in_executor(
            None, run_with_context(aci.get),
            f"api/node/class/{cls}.json?page-size=1000"
        )
        if not class_raw or not isinstance(class_raw, dict):
            logger.warning(
                f"BGP RIB class-level fallback returned {type(class_raw).__name__} for {fabric_id} — "
                f"likely auth or upstream error. Run /api/aci/bgp/diagnose?fabric={fabric_id} to investigate."
            )
            class_raw = {"imdata": []}
        rows = _build_adj_rib_rows(class_raw, cls, peer_to_l3out)
        all_raw = class_raw

    return rows, all_raw

@router.get("/bgp/advertised")
async def get_bgp_advertised(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """Aggregate fabric-wide BGP Advertised Routes (TX)."""
    import clients.aci_registry as reg
    loop = asyncio.get_event_loop()

    if request.query_params.get("fabric") == "all":
        fabrics = reg.list_fabrics()
        clients = await asyncio.gather(
            *[_get_aci_async(session, f.id) for f in fabrics],
            return_exceptions=True,
        )

        async def _safe_fetch(client, fabric):
            if isinstance(client, Exception):
                logger.warning(f"Fabric {fabric.id} client init failed: {client}")
                return ([], {"imdata": []})
            try:
                return await _fetch_bgp_rib_aggregated(client, loop, fabric.id, "out")
            except Exception as e:
                logger.warning(f"Fabric {fabric.id} BGP advertised fetch failed: {e}")
                return ([], {"imdata": []})

        results = await asyncio.gather(*[_safe_fetch(c, f) for c, f in zip(clients, fabrics)])

        processed = []
        for (p, _), fabric in zip(results, fabrics):
            for x in p:
                x.update({"fabric_id": fabric.id, "fabric_label": fabric.label})
            processed.extend(p)
        rib_raw = {"imdata": [item for _, raw in results for item in (raw or {}).get("imdata", [])]}
    else:
        aci = await _get_aci_async(session, fabric_id)
        processed, rib_raw = await _fetch_bgp_rib_aggregated(aci, loop, fabric_id, "out")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_advertised.html", {
            "routes": processed,
            "raw_json": rib_raw
        })

    return {"items": processed, "raw": rib_raw}

@router.get("/bgp/received")
async def get_bgp_received(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """Aggregate fabric-wide BGP Received Routes (RX)."""
    import clients.aci_registry as reg
    loop = asyncio.get_event_loop()

    if request.query_params.get("fabric") == "all":
        fabrics = reg.list_fabrics()
        clients = await asyncio.gather(
            *[_get_aci_async(session, f.id) for f in fabrics],
            return_exceptions=True,
        )

        async def _safe_fetch(client, fabric):
            if isinstance(client, Exception):
                logger.warning(f"Fabric {fabric.id} client init failed: {client}")
                return ([], {"imdata": []})
            try:
                return await _fetch_bgp_rib_aggregated(client, loop, fabric.id, "in")
            except Exception as e:
                logger.warning(f"Fabric {fabric.id} BGP received fetch failed: {e}")
                return ([], {"imdata": []})

        results = await asyncio.gather(*[_safe_fetch(c, f) for c, f in zip(clients, fabrics)])

        processed = []
        for (p, _), fabric in zip(results, fabrics):
            for x in p:
                x.update({"fabric_id": fabric.id, "fabric_label": fabric.label})
            processed.extend(p)
        rib_raw = {"imdata": [item for _, raw in results for item in (raw or {}).get("imdata", [])]}
    else:
        aci = await _get_aci_async(session, fabric_id)
        processed, rib_raw = await _fetch_bgp_rib_aggregated(aci, loop, fabric_id, "in")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_received.html", {
            "routes": processed,
            "raw_json": rib_raw
        })

    return {"items": processed, "raw": rib_raw}

# ── L3Out Routes ──────────────────────────────────────────────────────────────

@router.get("/l3outs/routes")
async def get_l3out_routes(
    request: Request,
    dn: str,
    direction: str = "in",
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """
    Focused view of routes received/advertised for a specific L3Out.
    Groups results by BGP peer.
    """
    _validate_dn(dn)
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    # 1. Identify peers for this L3Out from config (bgpPeerP)
    peer_cfg_raw = await loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peer_cfg"), aci.get_bgp_peer_configs)
    peers = []
    for entry in peer_cfg_raw.get('imdata', []):
        attr = entry.get('bgpPeerP', {}).get('attributes', {})
        if attr.get('dn', '').startswith(dn):
            peers.append({
                "addr": attr.get("addr", "").split("/")[0],
                "dn": attr.get("dn")
            })

    # 2. Correlate with operational peers to get Node and VRF
    all_peers_raw = await loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peers"), aci.get_bgp_peers)
    peer_data = []
    for p in peers:
        for op in all_peers_raw.get("imdata", []):
            attr = op.get("bgpPeerEntry", {}).get("attributes", {})
            # Match on IP address
            op_addr = attr.get("addr", "").split("/")[0]
            if op_addr == p["addr"]:
                dn_p = attr.get("dn").split("/")
                peer_data.append({
                    **p,
                    "node": next((x.replace("node-", "") for x in dn_p if x.startswith("node-")), "?"),
                    "vrf": next((x.replace("dom-", "") for x in dn_p if x.startswith("dom-")), "?")
                })
                break

    # 3. Parallel Fetch Routes per Peer
    cls = "bgpAdjRibIn" if direction == "in" else "bgpAdjRibOut"
    async def _fetch_peer_routes(p):
        # Specific peer MO path for Adj-RIB
        path = (
            f"api/node/mo/topology/pod-1/node-{p['node']}/sys/bgp/inst/"
            f"dom-{p['vrf']}/peer-[{p['addr']}]/ent-[{p['addr']}].json"
            f"?query-target=subtree&target-subtree-class={cls}"
        )
        raw = await loop.run_in_executor(None, run_with_context(aci.get), path)

        routes = []
        for item in raw.get("imdata", []):
            attr = item.get(cls, {}).get("attributes", {})
            if attr:
                routes.append({
                    "prefix": attr.get('prefix') or attr.get('pfx', ''),
                    "nextHop": attr.get('nextHop') or attr.get('nh', ''),
                    "asPath": attr.get('asPath', ''),
                    "origin": attr.get('origin', ''),
                    "flags": attr.get('flags') or attr.get('status', ''),
                    "localPref": attr.get('localPref', ''),
                    "med": attr.get('med', ''),
                    "community": attr.get('community', '')
                })
        return {**p, "routes": routes, "raw": raw}

    results = await asyncio.gather(*[_fetch_peer_routes(p) for p in peer_data])

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_l3out_routes.html", {
            "l3out_dn": dn,
            "direction": direction,
            "peer_results": results
        })

    return {"l3out": dn, "direction": direction, "peers": results}

# ── Miscellany (Health, Faults, EPGs) ───────────────────────────────────────────

@router.get("/bgp/routes")
async def get_bgp_routes(
    request: Request,
    node_id: str = None,
    dn: str = None,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """General node-wide BGP route table (RIB)."""
    if dn:
        _validate_dn(dn)
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    target = dn or node_id
    raw = await loop.run_in_executor(None, run_with_context(aci.get_bgp_routes), target)
    if isinstance(raw, list):
        raw = {"imdata": raw}
    if not raw or not isinstance(raw, dict):
        logger.warning(
            f"BGP routes query for {target} on fabric {fabric_id} returned no data "
            f"(likely 400 from APIC — class query unsupported on this version, or RBAC). "
            f"Run /api/aci/bgp/diagnose?fabric={fabric_id} to investigate."
        )
        raw = {"imdata": []}

    processed = []
    for item in raw.get('imdata', []):
        cls = next(iter(item)) if item else None
        if cls in {'bgpRoute', 'bgpBdpRoute', 'bgpEvpnRoute'}:
            attr = item[cls]['attributes']
            vrf = attr.get('dn', '').split('dom-')[-1].split('/')[0] if 'dom-' in attr.get('dn','') else '?'
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
            "node_id": node_id or target,
            "routes": processed,
            "raw_json": raw
        })
    return {"items": processed, "raw": raw}

@router.get("/traffic/epgs")
async def list_epgs(
    request: Request,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """List endpoint groups (EPGs) with real-time health scores."""
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    raw = await loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "epgs"), aci.get_epgs)

    processed = []
    for item in raw.get('imdata', []):
        attr = item.get('fvAEPg', {}).get('attributes', {})
        dn = attr.get('dn', '')
        # uni/tn-PROD/ap-APP1/epg-WEB
        parts = dn.split('/')
        tenant = parts[1].replace('tn-', '') if len(parts) > 1 else '?'
        app_prof = parts[2].replace('ap-', '') if len(parts) > 2 else '?'

        health = next((c['healthInst']['attributes']['cur'] for c in item.get('fvAEPg', {}).get('children', []) if 'healthInst' in c), "0")

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
            "raw_json": raw
        })
    return {"items": processed, "raw": raw}

@router.get("/health/summary")
async def get_health_summary(
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """Return a summary of overall, tenant, and pod health scores."""
    return await get_health_summary_logic(session, fabric_id)

async def get_health_summary_logic(session: SessionEntry, fabric_id: str):
    """Business logic for health summary, callable from other routers."""
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    overall, tenants, pods = await asyncio.gather(
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "health_overall"), aci.get_overall_health),
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "health_tenants"), aci.get_tenant_health),
        loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "health_pods"), aci.get_pod_health)
    )

    def extract_h(item, key):
        for c in item.get(key, {}).get('children', []):
            if 'healthInst' in c: return c['healthInst']['attributes'].get('cur', '0')
        return '0'

    return {
        "overall": extract_h(overall.get('imdata', [{}])[0], 'fabricHealthTotal') if overall.get('imdata') else '0',
        "tenants": [
            {
                "name": x.get('fvTenant', {}).get('attributes', {}).get('name'),
                "health": extract_h(x, 'fvTenant')
            } for x in tenants.get('imdata', [])
        ],
        "pods": [
            {
                "id": x.get('fabricPod', {}).get('attributes', {}).get('id'),
                "health": extract_h(x, 'fabricPod')
            } for x in pods.get('imdata', [])
        ]
    }

@router.get("/traffic/faults")
async def list_faults(
    request: Request,
    severity: Optional[str] = None,
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """List operational faults, optionally filtered by severity."""
    processed, raw = await list_faults_logic(session, fabric_id, severity)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_faults.html", {
            "faults": processed,
            "raw_json": raw
        })
    return {"items": processed, "raw": raw}

async def list_faults_logic(session: SessionEntry, fabric_id: str, severity: Optional[str] = None):
    """Business logic for faults, callable from other routers."""
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    raw = await loop.run_in_executor(None, run_with_context(aci.get_faults), severity)

    processed = []
    for f in raw.get('imdata', []):
        attr = f.get('faultInst', {}).get('attributes', {})
        processed.append({
            "code": attr.get('code'),
            "severity": attr.get('severity'),
            "descr": attr.get('descr'),
            "dn": attr.get('dn'),
            "created": attr.get('created')
        })
    return processed, raw

@router.get("/bgp/peer-routes")
async def get_bgp_peer_routes(
    request: Request,
    dn: str,
    direction: str = "in",
    session: SessionEntry = Depends(require_auth),
    fabric_id: str = Depends(get_fabric_id)
):
    """Direct fetch of Adj-RIB (RX/TX) for a specific BGP peer DN."""
    _validate_dn(dn)
    aci = await _get_aci_async(session, fabric_id)
    loop = asyncio.get_event_loop()

    raw = await loop.run_in_executor(None, run_with_context(aci.get_bgp_adj_rib), dn, direction)
    if isinstance(raw, list):
        raw = {"imdata": raw}
    if not raw:
        logger.warning(
            f"BGP peer routes fetch returned NoneType for fabric={fabric_id} dn={dn} dir={direction} — "
            f"likely 400/auth/upstream error. Run /api/aci/bgp/diagnose?fabric={fabric_id} to investigate."
        )
        raw = {"imdata": []}

    cls = "bgpAdjRibIn" if direction == "in" else "bgpAdjRibOut"
    processed = []
    for item in raw.get('imdata', []):
        attr = item.get(cls, {}).get('attributes', {})
        if attr:
            processed.append({
                "prefix": attr.get('prefix') or attr.get('pfx', ''),
                "nextHop": attr.get('nextHop') or attr.get('nh', ''),
                "asPath": attr.get('asPath', ''),
                "origin": attr.get('origin', ''),
                "flags": attr.get('flags') or attr.get('status', ''),
                "localPref": attr.get('localPref', ''),
                "med": attr.get('med', ''),
                "community": attr.get('community', '')
            })

    # Neighbor IP from DN: .../peer-[1.1.1.1]/...
    peer_ip = dn.split('peer-[')[-1].split(']')[0] if 'peer-[' in dn else "?"

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_bgp_peer_routes.html", {
            "peer_ip": peer_ip,
            "direction": "Received" if direction == "in" else "Advertised",
            "routes": processed,
            "raw_json": raw
        })

    return {"peer": peer_ip, "direction": direction, "items": processed, "raw": raw}
