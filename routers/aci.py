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
    "bgp_doms_all"
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

    # Dedupe: in vPC pairs the same peer IP shows up on multiple nodes. When at least
    # one row in (addr, vrf, l3out) is ESTABLISHED, drop the non-established siblings.
    groups: Dict[Tuple[str, str, str], List[Dict]] = {}
    for row in processed:
        groups.setdefault((row["addr"], row["vrf"], row["l3out"]), []).append(row)

    deduped: List[Dict] = []
    for rows in groups.values():
        established = [r for r in rows if r["state"] == "ESTABLISHED"]
        deduped.extend(established if established else rows)

    return deduped, peers_raw

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
        # 1. Tenants, Version, Peer Count
        tenants_raw, version_raw, peer_data_raw = await asyncio.gather(
            loop.run_in_executor(None, run_with_context(aci.get), "api/node/class/fvTenant.json"),
            loop.run_in_executor(None, run_with_context(aci.get), "api/node/class/firmwareCtrlrRunning.json"),
            loop.run_in_executor(None, run_with_context(aci.get_bgp_peers))
        )

        # 2. Probe BGP-related class queries to find what this APIC version supports.
        # Each entry: ok (200 + dict), count (if available), error string (if 4xx/5xx).
        candidate_classes = [
            "bgpRoute", "bgpAdjRibIn", "bgpAdjRibOut",
            "bgpPeerEntry", "bgpPeerAfEntry", "bgpDom", "bgpDomAf",
            "bgpPathAttr", "bgpRtPfxEntry", "bgpRouteEntry",
            "uribv4Route", "uribv6Route",
        ]

        def _probe_class(cls: str):
            res = aci.get(
                f"api/node/class/{cls}.json?rsp-subtree-include=count",
                action=f"PROBE_{cls}", quiet=True,
            )
            if not isinstance(res, dict):
                return cls, {"ok": False, "count": None}
            count = (
                res.get("imdata", [{}])[0]
                .get("moCount", {}).get("attributes", {}).get("count")
            )
            try:
                count = int(count) if count is not None else 0
            except (TypeError, ValueError):
                count = 0
            return cls, {"ok": True, "count": count}

        probe_results = await asyncio.gather(*[
            loop.run_in_executor(None, run_with_context(_probe_class), cls)
            for cls in candidate_classes
        ])
        class_probes = dict(probe_results)

        # 3. Per-leaf count of bgpRoute (most reliable across versions)
        nodes_proc, _ = await _get_processed_nodes(aci, loop, fabric_id)
        leaves = [n for n in nodes_proc if n["role"] == "leaf"]

        async def _get_count(n):
            async with get_apic_sem():
                res = await loop.run_in_executor(
                    None, run_with_context(aci.get),
                    f"api/node/mo/topology/pod-1/node-{n['id']}/sys/bgp.json?query-target=subtree&target-subtree-class=bgpRoute&rsp-subtree-include=count",
                    "PROBE_NODE_BGPROUTE", True,
                )
                if not isinstance(res, dict):
                    return n["id"], None
                count = res.get("imdata", [{}])[0].get("moCount", {}).get("attributes", {}).get("count", 0)
                try:
                    return n["id"], int(count)
                except (TypeError, ValueError):
                    return n["id"], 0

        counts = await asyncio.gather(*[_get_count(l) for l in leaves])

        # 4. Sample subtree under one peer (if any), to reveal actual child classes.
        sample_subtree = None
        for entry in peer_data_raw.get("imdata", []):
            peer_dn = entry.get("bgpPeerEntry", {}).get("attributes", {}).get("dn", "")
            # Step up from .../ent-[ip] to .../peer-[ip] for the parent peer container
            if "/ent-" in peer_dn:
                peer_parent = peer_dn.rsplit("/ent-", 1)[0]
                res = await loop.run_in_executor(
                    None, run_with_context(aci.get),
                    f"api/node/mo/{peer_parent}.json?query-target=children",
                    "PROBE_PEER_CHILDREN", True,
                )
                if isinstance(res, dict):
                    sample_subtree = {
                        "peer_dn": peer_parent,
                        "child_classes": sorted({
                            next(iter(item)) for item in res.get("imdata", []) if item
                        }),
                    }
                break

        return {
            "apic_version": version_raw.get("imdata", [{}])[0].get("firmwareCtrlrRunning", {}).get("attributes", {}).get("version"),
            "tenants": [t.get("fvTenant", {}).get("attributes", {}).get("name") for t in tenants_raw.get("imdata", [])],
            "bgp_peer_count": len(peer_data_raw.get("imdata", [])),
            "class_probes": class_probes,
            "per_node_bgproute_count": dict(counts),
            "sample_peer_subtree": sample_subtree,
        }

    try:
        return await asyncio.wait_for(_run_diagnostics(), timeout=60.0)
    except asyncio.TimeoutError:
        raise HTTPException(504, f"ACI diagnostics timed out for fabric {fabric_id} after 60s")

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
    BGP route view for an L3Out's VRF.

    APIC versions before ~6.x do not expose per-peer adj-RIB-in/out as MOs
    (`bgpAdjRibIn`/`bgpAdjRibOut` returns "Unknown class"). We instead read the
    URIB on each leaf node carrying L3Out peers and surface the BGP-installed
    routes for the L3Out's VRF, grouped by peer where the route's next-hop
    matches a configured peer. Adj-RIB-out is not derivable from URIB.
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

    # 2. Correlate with operational peers to get Node, VRF, and the operational DN
    all_peers_raw = await loop.run_in_executor(None, run_with_context(_cached), _fkey(fabric_id, "bgp_peers"), aci.get_bgp_peers)
    peer_data = []
    for p in peers:
        for op in all_peers_raw.get("imdata", []):
            attr = op.get("bgpPeerEntry", {}).get("attributes", {})
            op_addr = attr.get("addr", "").split("/")[0]
            if op_addr == p["addr"]:
                op_dn = attr.get("dn") or ""
                dn_p = op_dn.split("/")
                peer_data.append({
                    **p,
                    "op_dn": op_dn,
                    "state": attr.get("operSt"),
                    "node": next((x.replace("node-", "") for x in dn_p if x.startswith("node-")), "?"),
                    "vrf": next((x.replace("dom-", "") for x in dn_p if x.startswith("dom-")), "?")
                })
                break

    note = (
        "APIC %s does not expose per-peer adj-RIB MOs. RX shows the BGP-installed "
        "routes from the URIB on each leaf, grouped by peer when the next-hop matches. "
        "TX (advertised-routes) is not queryable through the APIC API on this version."
    )

    # If TX requested, return early with the explanatory note (no fetch).
    if direction == "out":
        results = [{**p, "routes": [], "raw": None, "note": "adj-rib-out not available"} for p in peer_data]
        if request.headers.get("HX-Request"):
            from templates_module import templates
            return templates.TemplateResponse(request, "partials/aci_l3out_routes.html", {
                "l3out_dn": dn, "direction": direction, "peer_results": results, "note": note,
            })
        return {"l3out": dn, "direction": direction, "peers": results, "note": note,
                "vrf_other_routes": []}

    # 3. Fetch URIB v4 routes (with their nexthop children) per (node, vrf)
    # `dom-<tenant>:<vrf>` is the same in URIB as in BGP. Use rsp-subtree=children
    # so we get uribv4Nexthop entries embedded under each uribv4Route.
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for p in peer_data:
        if p["node"] != "?" and p["vrf"] != "?":
            groups[(p["node"], p["vrf"])].append(p)

    async def _fetch_uribv4(node: str, vrf: str):
        vrf_dn = f"topology/pod-1/node-{node}/sys/uribv4/dom-{vrf}"
        path = (
            f"api/node/mo/{ac._quote_dn(vrf_dn)}.json"
            f"?query-target=subtree&target-subtree-class=uribv4Route"
            f"&rsp-subtree=children&rsp-subtree-class=uribv4Nexthop"
        )
        meta = await loop.run_in_executor(None, run_with_context(aci.get_with_meta), path)
        return (node, vrf), meta

    fetched = await asyncio.gather(*[_fetch_uribv4(n, v) for (n, v) in groups.keys()])
    meta_by_group: Dict[Tuple[str, str], Dict[str, Any]] = dict(fetched)

    def _is_bgp_nh(nh_attr: Dict[str, Any]) -> bool:
        # Try a few common attribute names; fall back to DN substring.
        for k in ("routeType", "srcType", "protocol", "nhType"):
            v = nh_attr.get(k, "")
            if isinstance(v, str) and "bgp" in v.lower():
                return True
        return "-bgp-" in nh_attr.get("dn", "")

    def _summarize_nh(nh_attr: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "addr": nh_attr.get("addr", "") or nh_attr.get("nhAddr", ""),
            "vrf": nh_attr.get("nhVrf", ""),
            "pref": nh_attr.get("pref", ""),
            "metric": nh_attr.get("metric", ""),
            "type": nh_attr.get("routeType") or nh_attr.get("srcType") or nh_attr.get("protocol") or "",
            "dn": nh_attr.get("dn", ""),
        }

    # 4. Walk routes per group; assign each BGP-sourced route to its peer when next-hop matches.
    routes_by_peer: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    vrf_other_routes: List[Dict[str, Any]] = []
    fetch_errors: List[Dict[str, Any]] = []

    for (node, vrf), peers_in_group in groups.items():
        meta = meta_by_group.get((node, vrf)) or {}
        raw = meta.get("data")
        if not isinstance(raw, dict):
            fetch_errors.append({
                "node": node, "vrf": vrf,
                "status": meta.get("status"), "error": meta.get("error"),
                "body": meta.get("body"), "url": meta.get("url"),
            })
            continue

        peer_addrs = {p["addr"] for p in peers_in_group}
        for item in raw.get("imdata", []):
            rt_obj = item.get("uribv4Route", {})
            rt_attr = rt_obj.get("attributes", {})
            children = rt_obj.get("children", []) or []

            bgp_nhs = []
            for child in children:
                nh_attr = child.get("uribv4Nexthop", {}).get("attributes", {})
                if not nh_attr:
                    continue
                if _is_bgp_nh(nh_attr):
                    bgp_nhs.append(nh_attr)

            if not bgp_nhs:
                continue  # not a BGP-installed route

            entry = {
                "prefix": rt_attr.get("prefix") or rt_attr.get("pfx", ""),
                "nextHops": [_summarize_nh(nh) for nh in bgp_nhs],
                "node": node,
                "vrf": vrf,
                # URIB doesn't carry these BGP attrs; left blank for UI compat.
                "asPath": "", "origin": "", "flags": "", "localPref": "", "med": "", "community": "",
            }

            matched = False
            for nh in bgp_nhs:
                nh_addr = (nh.get("addr") or nh.get("nhAddr") or "").split("/")[0]
                if nh_addr in peer_addrs:
                    routes_by_peer[f"{node}|{nh_addr}"].append({**entry, "nextHop": nh_addr})
                    matched = True
                    break
            if not matched:
                vrf_other_routes.append(entry)

    # 5. Assemble per-peer results in the original shape so the template still works.
    results = []
    for p in peer_data:
        key = f"{p['node']}|{p['addr']}"
        results.append({**p, "routes": routes_by_peer.get(key, []), "raw": None})

    response = {
        "l3out": dn,
        "direction": direction,
        "peers": results,
        "vrf_other_routes": vrf_other_routes,
        "note": note,
        "fetch_errors": fetch_errors,
    }

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/aci_l3out_routes.html", {
            "l3out_dn": dn,
            "direction": direction,
            "peer_results": results,
            "vrf_other_routes": vrf_other_routes,
            "note": note,
        })

    return response

# ── Miscellany (Health, Faults, EPGs) ───────────────────────────────────────────

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
