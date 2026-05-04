import logging
import asyncio
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import JSONResponse, Response, StreamingResponse
from auth import SessionEntry, require_auth
from utils.ipam_engine import IPAMEngine
from utils.ipam_export import generate_solarwinds_csv
from cache import cache, IPAM_TREE_CACHE_KEY

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/refresh")
async def refresh_ipam(
    request: Request,
    sources: Optional[List[str]] = Query(None),
    session: SessionEntry = Depends(require_auth)
):
    # Ensure sources is a list if it's a Query object
    actual_sources = sources.default if hasattr(sources, "default") else sources

    async def generate():
        def emit(msg: str, type: str = "log"):
            return f"data: {json.dumps({'type': type, 'message': msg})}\n\n"

        engine = IPAMEngine()
        loop = asyncio.get_event_loop()

        yield emit(f"Starting discovery for sources: {actual_sources or 'ALL'}")

        # Load existing subnets if we are doing a partial refresh
        existing_tree = cache.get(IPAM_TREE_CACHE_KEY)
        if sources and existing_tree:
             # This is a bit complex since we store the tree, not flat subnets.
             # For now, if partial refresh is requested, we still rebuild the whole tree
             # but only 'refresh' discovery for requested sources.
             # Better: IPAMEngine should probably support additive discovery or we store flat subnets.
             # For simplicity in this step, we just do selective discovery but result replaces all.
             pass

        # We redefine yield_progress to be usable
        progress_queue = asyncio.Queue()
        async def progress_callback(msg):
            await progress_queue.put(msg)

        # Run discovery in background
        discovery_task = asyncio.create_task(engine.discover_all(session, loop, sources=actual_sources, yield_progress=progress_callback))

        while not discovery_task.done() or not progress_queue.empty():
            try:
                msg = await asyncio.wait_for(progress_queue.get(), timeout=0.1)
                yield emit(msg)
            except asyncio.TimeoutError:
                continue

        await discovery_task

        yield emit("Building hierarchy tree...")
        engine.build_tree()

        tree_data = engine.get_tree()
        cache.set(IPAM_TREE_CACHE_KEY, tree_data, ttl=3600*24)

        yield emit("Discovery complete!", type="complete")

    return StreamingResponse(generate(), media_type="text/event-stream")

@router.get("/stats")
async def get_ipam_stats(session: SessionEntry = Depends(require_auth)):
    """Return summary statistics about the current IPAM tree."""
    tree = cache.get(IPAM_TREE_CACHE_KEY)
    info = cache.cache_info(IPAM_TREE_CACHE_KEY)

    if not tree:
        return {"ipv4_node_count": 0, "ipv6_node_count": 0, "last_refresh_at": None, "source_counts": {}}

    v4_count = 0
    v6_count = 0
    source_counts = {}

    def _walk(nodes, is_v6=False):
        nonlocal v4_count, v6_count
        for n in nodes:
            if is_v6: v6_count += 1
            else: v4_count += 1

            src = n.get("source", "Unknown")
            source_counts[src] = source_counts.get(src, 0) + 1
            _walk(n.get("children", []), is_v6)

    _walk(tree.get("ipv4", []))
    _walk(tree.get("ipv6", []), is_v6=True)

    return {
        "ipv4_node_count": v4_count,
        "ipv6_node_count": v6_count,
        "last_refresh_at": info["set_at"] if info else None,
        "source_counts": source_counts
    }

@router.get("/tree")
async def get_ipam_tree(session: SessionEntry = Depends(require_auth)):
    tree_data = cache.get(IPAM_TREE_CACHE_KEY)
    if not tree_data:
        return JSONResponse(status_code=404, content={"message": "No IPAM data found. Please run refresh."})
    return tree_data

@router.get("/debug")
async def debug_ipam_sources(session: SessionEntry = Depends(require_auth)):
    """Inspect raw cache data for IPAM sources — no network calls."""
    from cache import cache

    # ── Panorama ──────────────────────────────────────────────────────────────
    pan_ifaces = cache.get("pan_interfaces") or []
    pan_sample, pan_with_prefix, pan_without_prefix = [], 0, 0
    for dev in pan_ifaces:
        for iface in dev.get("interfaces", []):
            ipv4 = iface.get("ipv4") or ""
            has_prefix = "/" in ipv4
            if has_prefix:
                pan_with_prefix += 1
            else:
                pan_without_prefix += 1
            if len(pan_sample) < 15:
                pan_sample.append({
                    "hostname": dev.get("hostname"),
                    "iface": iface.get("name"),
                    "ipv4": ipv4 or "none",
                    "has_prefix": has_prefix,
                })

    # ── Nexus ─────────────────────────────────────────────────────────────────
    nex_ifaces = cache.get("nexus_interfaces") or []
    nex_sample, nex_with_ip, nex_na = [], 0, 0
    for iface in nex_ifaces:
        ipv4 = iface.get("ipv4_address") or "N/A"
        if ipv4 and ipv4 != "N/A":
            nex_with_ip += 1
        else:
            nex_na += 1
        if len(nex_sample) < 15:
            nex_sample.append({
                "hostname": iface.get("hostname"),
                "iface": iface.get("interface_name"),
                "ipv4": ipv4,
            })

    # ── DNAC ──────────────────────────────────────────────────────────────────
    devices = cache.get("devices") or []
    sites   = cache.get("sites") or []
    sitemap = cache.get("device_site_map") or {}
    dnac_ifaces = cache.get("dnac_interfaces") or []
    dnac_global_pools = cache.get("dnac_global_pools") or []
    dnac_subpools = cache.get("dnac_reserve_subpools") or []

    # Count v4 vs v6 pools so the user can immediately see whether IPv6 pools exist.
    pool_v4 = pool_v6 = 0
    pool_samples: list = []
    for p in dnac_global_pools:
        cidr = p.get("ipPoolCidr") or p.get("cidr") or ""
        if ":" in cidr: pool_v6 += 1
        elif "." in cidr: pool_v4 += 1
        if len(pool_samples) < 5:
            pool_samples.append({"site": "GLOBAL", "name": p.get("ipPoolName"), "cidr": cidr, "v6": ":" in cidr})
    for sp in dnac_subpools:
        site = sp.get("siteName") or sp.get("groupName") or "?"
        for ip in (sp.get("ipPools") or []):
            cidr = ip.get("ipPoolCidr") or ip.get("cidr") or ""
            if ":" in cidr: pool_v6 += 1
            elif "." in cidr: pool_v4 += 1
            if len(pool_samples) < 10:
                pool_samples.append({"site": site, "name": ip.get("ipPoolName"), "cidr": cidr, "v6": ":" in cidr})

    # Inventory IPv4/IPv6 coverage on the DNAC interfaces and dump a few raw
    # samples that have IPv6-shaped fields so we can see exactly what schema
    # DNAC returned (the SDK validator is loose; field names vary by version).
    dnac_v4_count = 0
    dnac_v6_count = 0
    dnac_v6_field_names: dict = {}
    dnac_v6_samples: list = []
    for iface in dnac_ifaces:
        if iface.get("ipv4Address") and iface.get("ipv4Mask"):
            dnac_v4_count += 1
        # Any field whose name contains "v6" (case-insensitive) and has a non-empty value.
        v6_hits = {k: v for k, v in iface.items() if "v6" in k.lower() and v not in (None, "", [], {})}
        if v6_hits:
            dnac_v6_count += 1
            for k in v6_hits:
                dnac_v6_field_names[k] = dnac_v6_field_names.get(k, 0) + 1
            if len(dnac_v6_samples) < 5:
                dnac_v6_samples.append({
                    "device": iface.get("deviceName") or iface.get("deviceId"),
                    "port": iface.get("portName"),
                    "v6_fields": v6_hits,
                })

    # ── ACI ───────────────────────────────────────────────────────────────────
    # Real keys are aci_{fabric_id}_nodes; aggregate across fabrics for the count.
    import clients.aci_registry as reg
    aci_imdata = []
    for f in reg.list_fabrics():
        fabric_nodes = cache.get(f"aci_{f.id}_nodes") or {"imdata": []}
        aci_imdata.extend(fabric_nodes.get("imdata", []))
    aci_nodes = {"imdata": aci_imdata}

    # ── ipam_tree ────────────────────────────────────────────────────────────
    tree = cache.get(IPAM_TREE_CACHE_KEY)
    tree_v4 = len(tree.get("ipv4", [])) if tree else 0
    tree_v6 = len(tree.get("ipv6", [])) if tree else 0

    # Count sources in the existing tree
    source_counts: dict = {}
    if tree:
        def _count_sources(nodes: list):
            for n in nodes:
                src = n.get("source", "Unknown")
                source_counts[src] = source_counts.get(src, 0) + 1
                _count_sources(n.get("children", []))
        _count_sources(tree.get("ipv4", []))
        _count_sources(tree.get("ipv6", []))

    return {
        "ipam_tree": {
            "cached": tree is not None,
            "v4_roots": tree_v4,
            "v6_roots": tree_v6,
            "source_counts": source_counts,
        },
        "dnac": {
            "devices_cached": len(devices),
            "sites_cached": len(sites),
            "sitemap_entries": len(sitemap),
            "interfaces_cached": len(dnac_ifaces),
            "interfaces_with_ipv4": dnac_v4_count,
            "interfaces_with_ipv6_field": dnac_v6_count,
            "ipv6_field_names": dnac_v6_field_names,
            "ipv6_samples": dnac_v6_samples,
            "global_pools_cached": len(dnac_global_pools),
            "reserve_subpools_cached": len(dnac_subpools),
            "pool_v4_count": pool_v4,
            "pool_v6_count": pool_v6,
            "pool_samples": pool_samples,
            "last_errors": {
                k: cache.last_error(k)
                for k in (
                    "dnac_global_pools",
                    "dnac_reserve_subpools",
                    "dnac_device_configs",
                    "dnac_interfaces",
                    "devices",
                )
                if cache.last_error(k)
            },
        },
        "aci_nodes_cached": len(aci_nodes.get("imdata", [])),
        "panorama": {
            "devices_in_cache": len(pan_ifaces),
            "interfaces_with_prefix": pan_with_prefix,
            "interfaces_without_prefix": pan_without_prefix,
            "sample": pan_sample,
        },
        "nexus": {
            "interfaces_in_cache": len(nex_ifaces),
            "interfaces_with_ip": nex_with_ip,
            "interfaces_na": nex_na,
            "sample": nex_sample,
        },
    }


@router.get("/export")
async def export_ipam_csv(session: SessionEntry = Depends(require_auth)):
    tree_data = cache.get(IPAM_TREE_CACHE_KEY)
    if not tree_data:
        return JSONResponse(status_code=404, content={"message": "No IPAM data found. Please run refresh."})

    # Flatten tree for CSV
    all_nodes = tree_data["ipv4"] + tree_data["ipv6"]
    csv_content = generate_solarwinds_csv(all_nodes)

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=solarwinds_ipam_import.csv"}
    )
