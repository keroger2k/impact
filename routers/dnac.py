import ipaddress
import json
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, Depends, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

import clients.dnac as dc
import clients.panorama as pc
import auth as auth_module
from auth import SessionEntry, require_auth
from cache import cache, TTL_DEVICES, TTL_SITES
from logger_config import run_with_context

DEVICE_PAGE_LIMIT = 500
DEVICE_PAGE_MAX = 5000
CONFIG_SEARCH_WORKERS = 20

router = APIRouter()
logger = logging.getLogger(__name__)


def _get_dnac(session: SessionEntry):
    try:
        return auth_module.get_dnac_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"DNAC connection failed: {e}")


def _fmt_ts(ts) -> str:
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts) / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)[:16]


def _enrich(d: dict) -> dict:
    """Add computed fields to a device dict."""
    d = dict(d)
    d["lastContactFormatted"] = _fmt_ts(d.get("lastUpdateTime"))
    return d


# ── Devices ────────────────────────────────────────────────────────────────────

async def get_devices_data(
    session:      SessionEntry,
    hostname:     Optional[str] = None,
    ip:           Optional[str] = None,
    platform:     Optional[str] = None,
    role:         Optional[str] = None,
    reachability: Optional[str] = None,
    site:         Optional[str] = None,
    limit:        int = DEVICE_PAGE_LIMIT,
    offset:       int = 0,
):
    """Core logic to fetch and filter devices from cache."""
    loop = asyncio.get_event_loop()
    dnac = _get_dnac(session)

    devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "devices", lambda: dc.get_all_devices(dnac), TTL_DEVICES)
    devices = devices or []

    filtered = devices
    if hostname:
        filtered = [d for d in filtered if hostname.lower() in (d.get("hostname") or "").lower()]
    if ip:
        filtered = [d for d in filtered if ip in (d.get("managementIpAddress") or "")]
    if platform:
        filtered = [d for d in filtered if platform.lower() in (d.get("platformId") or "").lower()]
    if role:
        filtered = [d for d in filtered if role.lower() in (d.get("role") or "").lower()]
    if reachability:
        if reachability.lower() == "reachable":
            filtered = [d for d in filtered if d.get("reachabilityStatus") == "Reachable"]
        elif reachability.lower() == "unreachable":
            filtered = [d for d in filtered if d.get("reachabilityStatus") != "Reachable"]

    sites = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "sites", lambda: dc.get_site_cache(dnac), TTL_SITES)
    sites = sites or []
    dev_site_map = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "device_site_map", lambda: dc.build_device_site_map(dnac, sites), TTL_SITES)
    dev_site_map = dev_site_map or {}

    if site:
        filtered = [d for d in filtered if site.lower() in (dev_site_map.get(d.get("id")) or "").lower()]

    # Merge Nexus devices
    from routers.nexus import get_cached_nexus_inventory
    nexus_devices = get_cached_nexus_inventory()

    # Apply filters to Nexus devices too if relevant
    if hostname:
        nexus_devices = [d for d in nexus_devices if hostname.lower() in (d.get("hostname") or "").lower()]
    if ip:
        nexus_devices = [d for d in nexus_devices if ip in (d.get("managementIpAddress") or "")]
    if platform:
        nexus_devices = [d for d in nexus_devices if platform.lower() in (d.get("platformId") or "").lower()]
    if reachability:
        if reachability.lower() == "reachable":
            nexus_devices = [d for d in nexus_devices if d.get("reachabilityStatus") == "Reachable"]
        elif reachability.lower() == "unreachable":
            nexus_devices = [d for d in nexus_devices if d.get("reachabilityStatus") != "Reachable"]

    # Combine
    combined = []
    for d in filtered:
        d_copy = dict(d)
        d_copy["source"] = "DNAC"
        combined.append(d_copy)

    combined.extend(nexus_devices)

    filtered = combined
    total = len(filtered)
    paged = []
    for d in filtered[offset: offset + limit]:
        if d.get("source") == "Nexus":
            paged.append(d)
        else:
            enriched = _enrich(d)
            enriched["siteName"] = dev_site_map.get(d.get("id"))
            paged.append(enriched)

    return {"total": total, "offset": offset, "limit": limit, "items": paged}


@router.get("/devices")
async def list_devices(
    request:      Request,
    hostname:     Optional[str] = None,
    ip:           Optional[str] = None,
    platform:     Optional[str] = None,
    role:         Optional[str] = None,
    reachability: Optional[str] = None,
    site:         Optional[str] = None,
    limit:        int = Query(DEVICE_PAGE_LIMIT, le=DEVICE_PAGE_MAX),
    offset:       int = Query(0, ge=0),
    session:      SessionEntry = Depends(require_auth),
):
    """Return filtered device list from cache."""
    # Convert Query objects to actual values if called manually
    q_limit = limit.default if hasattr(limit, "default") else limit
    q_offset = offset.default if hasattr(offset, "default") else offset

    data = await get_devices_data(
        session=session,
        hostname=hostname,
        ip=ip,
        platform=platform,
        role=role,
        reachability=reachability,
        site=site,
        limit=q_limit,
        offset=q_offset
    )
    
    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/devices_list.html", data)

    return data


@router.get("/devices/stats")
async def device_stats(session: SessionEntry = Depends(require_auth)):
    """Summary statistics for the dashboard."""
    loop    = asyncio.get_event_loop()
    dnac    = _get_dnac(session)
    devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "devices", lambda: dc.get_all_devices(dnac), TTL_DEVICES)
    devices = devices or []

    from routers.nexus import get_cached_nexus_inventory
    nexus_devices = get_cached_nexus_inventory()

    all_devices = list(devices) + nexus_devices

    from collections import Counter
    reachable   = sum(1 for d in all_devices if isinstance(d, dict) and d.get("reachabilityStatus") == "Reachable")
    unreachable = len(all_devices) - reachable
    platforms   = Counter(d.get("platformId", "Unknown") or "Unknown" for d in all_devices if isinstance(d, dict))
    versions    = Counter(d.get("softwareVersion", "Unknown") or "Unknown" for d in all_devices if isinstance(d, dict))
    roles       = Counter(d.get("role", "UNKNOWN") or "UNKNOWN" for d in all_devices if isinstance(d, dict))

    return {
        "total":        len(all_devices),
        "reachable":    reachable,
        "unreachable":  unreachable,
        "pct_reachable": round(reachable / len(all_devices) * 100, 1) if all_devices else 0,
        "platforms":    platforms.most_common(15),
        "versions":     versions.most_common(12),
        "roles":        roles.most_common(),
    }


@router.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Device detail by ID."""
    if device_id.startswith("nexus_"):
        from routers.nexus import get_cached_nexus_inventory
        devices = get_cached_nexus_inventory()
    else:
        devices = cache.get("devices") or []

    device  = next((d for d in devices if d.get("id") == device_id), None)
    if not device:
        raise HTTPException(404, "Device not found")
    return _enrich(device) if device.get("source") != "Nexus" else device


@router.get("/devices/{device_id}/detail")
async def get_device_detail_partial(
    request:     Request,
    device_id:   str,
    session:     SessionEntry = Depends(require_auth)
):
    """Return a detailed HTML partial for a device."""
    if device_id.startswith("nexus_"):
        from routers.nexus import get_cached_nexus_inventory
        devices = get_cached_nexus_inventory()
        device  = next((d for d in devices if d.get("id") == device_id), None)
        if not device:
             raise HTTPException(404, "Device not found")

        from templates_module import templates
        return templates.TemplateResponse(request, "partials/device_detail.html", {
            "d": device,
            "site_name": device.get("siteName")
        })

    devices = cache.get("devices") or []
    device  = next((d for d in devices if d.get("id") == device_id), None)
    if not device:
        loop = asyncio.get_event_loop()
        dnac = _get_dnac(session)
        try:
            device = await loop.run_in_executor(None, run_with_context(dc.get_device_detail), dnac, device_id)
        except Exception as e:
            logger.error(f"Device detail lookup failed for {device_id}: {e}")
            raise HTTPException(404, "Device not found")

    if not device:
        raise HTTPException(404, "Device not found")

    enriched = _enrich(device)
    dev_site_map = cache.get("device_site_map") or {}
    site_name = dev_site_map.get(device_id, "Unknown Site")

    from templates_module import templates
    return templates.TemplateResponse(request, "partials/device_detail.html", {
        "d": enriched,
        "site_name": site_name
    })


@router.get("/devices/{device_id}/config")
async def get_device_config(
    request:     Request,
    device_id: str,
    session: SessionEntry = Depends(require_auth)
):
    """Running configuration for a device."""
    if device_id.startswith("nexus_"):
        from dev import DEV_MODE
        config = None
        if DEV_MODE:
            from dev import get_mock_config
            config = get_mock_config(device_id)
        else:
            hostname = device_id.replace("nexus_", "")
            config = cache.get(f"config:nexus:{hostname}")

        if config:
            if request.headers.get("HX-Request"):
                from templates_module import templates
                return templates.TemplateResponse(request, "partials/device_config.html", {
                    "config": config,
                    "cached": True
                })
            return {"config": config, "cached": True}
        else:
             raise HTTPException(404, "Nexus config not found in cache. Please refresh Nexus data.")

    cache_key = f"config_{device_id}"
    loop      = asyncio.get_event_loop()
    dnac      = _get_dnac(session)

    config = await loop.run_in_executor(None, run_with_context(cache.get_or_set), cache_key, lambda: dc.get_device_config(dnac, device_id), 600)

    if not config:
        raise HTTPException(404, "Config not available for this device")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/device_config.html", {
            "config": config,
            "cached": True # With get_or_set, it's effectively always potentially from cache
        })
    return {"config": config, "cached": True}


# ── IP Lookup ─────────────────────────────────────────────────────────────────

@router.get("/ip-lookup")
async def ip_lookup_handler(ip: str, session: SessionEntry = Depends(require_auth)):
    """
    Find what interface and device owns an IP address.
    Searches both Catalyst Center (DNAC) and the Palo Alto interface inventory.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"'{ip}' is not a valid IP address")

    loop = asyncio.get_event_loop()
    dnac = _get_dnac(session)

    # ── DNAC lookup ───────────────────────────────────────────────────────────
    ifaces = await loop.run_in_executor(None, run_with_context(dc.get_interface_by_ip), dnac, ip)

    enriched = []
    if ifaces:
        devices   = cache.get("devices") or []
        id_to_dev = {d.get("id"): d for d in devices if d.get("id")}

        dev_site_map = cache.get("device_site_map") or {}

        for iface in ifaces:
            dev_id = iface.get("deviceId")
            device = id_to_dev.get(dev_id, {})

            subnet = None
            addr   = iface.get("ipv4Address")
            mask   = iface.get("ipv4Mask")
            if addr and mask:
                try:
                    net    = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
                    subnet = f"{net}  (/{net.prefixlen})"
                except ValueError:
                    subnet = mask

            enriched.append({
                "interface": {
                    "portName":    iface.get("portName"),
                    "ipAddress":   ip,
                    "subnet":      subnet,
                    "macAddress":  iface.get("macAddress"),
                    "vlanId":      iface.get("vlanId"),
                    "description": iface.get("description"),
                    "adminStatus": iface.get("adminStatus"),
                    "operStatus":  iface.get("status"),
                    "speed":       iface.get("speed"),
                },
                "device":   _enrich(device) if device else None,
                "siteName": dev_site_map.get(dev_id) if dev_id else None,
            })

    # ── Palo Alto interface lookup ──
    pan_devices    = cache.get("pan_interfaces") or []
    pan_matches    = pc.search_firewall_interfaces(ip, pan_devices)
    firewall_hits  = []
    for m in pan_matches:
        dev   = m["device"]
        iface = m["interface"]
        firewall_hits.append({
            "hostname":     dev.get("hostname"),
            "serial":       dev.get("serial"),
            "model":        dev.get("model"),
            "management_ip": dev.get("management_ip"),
            "device_group": dev.get("device_group"),
            "os_version":   dev.get("os_version"),
            "ha_state":     dev.get("ha_state"),
            "interface":    iface.get("name"),
            "ipv4":         iface.get("ipv4"),
        })

    # ── Nexus interface lookup ──
    from routers.nexus import get_cached_nexus_interfaces
    nexus_ifaces = get_cached_nexus_interfaces()
    nexus_hits = []
    for iface in nexus_ifaces:
        iface_ip_raw = iface.get("ipv4_address")
        if iface_ip_raw and iface_ip_raw != "N/A":
            try:
                iface_ip = iface_ip_raw.split('/')[0]
                if ip == iface_ip:
                     nexus_hits.append({
                         "hostname": iface.get("hostname"),
                         "device_ip": iface.get("device_ip"),
                         "interface": iface.get("interface_name"),
                         "ipv4": iface.get("ipv4_address"),
                         "mac": iface.get("mac_address"),
                         "platform": "Nexus"
                     })
            except Exception:
                continue

    found = bool(enriched or firewall_hits or nexus_hits)
    return {
        "ip":                ip,
        "found":             found,
        "interfaces":        enriched,
        "firewall_interfaces": firewall_hits,
        "nexus_interfaces": nexus_hits,
    }

@router.get("/ip-lookup/ui", response_class=HTMLResponse)
async def ip_lookup_ui(request: Request, ip: str, session: SessionEntry = Depends(require_auth)):
    results = await ip_lookup_handler(ip, session)
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/ip_lookup_results.html", {"r": results})


# ── Sites ─────────────────────────────────────────────────────────────────────

@router.get("/sites")
async def list_sites(filter: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    loop  = asyncio.get_event_loop()
    dnac  = _get_dnac(session)
    sites = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "sites", lambda: dc.get_site_cache(dnac), TTL_SITES)

    if filter:
        sites = [s for s in sites if filter.lower() in s["name"].lower()]

    return {"total": len(sites), "items": sites}


# ── Cache management ──────────────────────────────────────────────────────────

@router.get("/cache/info")
async def dnac_cache_info():
    return {
        "devices": cache.cache_info("devices"),
        "sites":   cache.cache_info("sites"),
    }


@router.post("/cache/refresh")
async def refresh_cache():
    # Legacy endpoint — use /api/cache/refresh/devices or similar
    # Scoped to DNAC only
    cache.invalidate_prefix("devices")
    cache.invalidate_prefix("sites")
    cache.invalidate_prefix("device_site_map")
    return {"status": "DNAC Cache invalidated"}


# ── Tag devices ───────────────────────────────────────────────────────────────

class TagDevicesRequest(BaseModel):
    tag_name: str
    ips:      list[str]


@router.post("/tag-devices")
async def tag_devices(req: TagDevicesRequest, session: SessionEntry = Depends(require_auth)):
    """Look up or create a tag and apply it to devices by management IP. Streams SSE progress."""
    from dev import DEV_MODE

    async def generate():
        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        loop = asyncio.get_event_loop()

        if DEV_MODE:
            yield emit({"type": "log", "level": "info", "message": f"[MOCK] Resolved tag '{req.tag_name}' (id: mock-tag-id)"})
            for ip in req.ips:
                yield emit({"type": "log", "level": "success", "message": f"{ip}: tagged ✓"})
            yield emit({"type": "complete", "tagged": len(req.ips), "skipped": 0, "tag_name": req.tag_name})
            return

        dnac = _get_dnac(session)

        # Resolve IPs → device IDs using the device cache
        devices   = cache.get("devices") or []
        ip_to_id  = {d.get("managementIpAddress"): d.get("id") for d in devices if d.get("managementIpAddress")}
        ip_to_host = {d.get("managementIpAddress"): d.get("hostname") for d in devices if d.get("managementIpAddress")}

        found, not_found = [], []
        for ip in req.ips:
            dev_id = ip_to_id.get(ip)
            if dev_id:
                found.append({"ip": ip, "id": dev_id, "hostname": ip_to_host.get(ip, ip)})
            else:
                not_found.append(ip)

        yield emit({"type": "log", "level": "info",
                    "message": f"{len(found)} device(s) found in inventory, {len(not_found)} not found"})
        for ip in not_found:
            yield emit({"type": "log", "level": "warn", "message": f"{ip}: not found in DNAC inventory — skipped"})

        if not found:
            yield emit({"type": "complete", "tagged": 0, "skipped": len(not_found), "tag_name": req.tag_name})
            return

        # Get or create the tag
        try:
            yield emit({"type": "log", "level": "info", "message": f"Resolving tag '{req.tag_name}'…"})
            tag_id = await loop.run_in_executor(None, run_with_context(dc.get_or_create_tag), dnac, req.tag_name)
            yield emit({"type": "log", "level": "info", "message": f"Tag ID: {tag_id}"})
        except Exception as e:
            yield emit({"type": "log", "level": "error", "message": f"Tag lookup/create failed: {e}"})
            yield emit({"type": "complete", "tagged": 0, "skipped": len(not_found), "tag_name": req.tag_name})
            return

        # Apply tag to all found devices in one call
        device_ids = [d["id"] for d in found]
        try:
            await loop.run_in_executor(None, run_with_context(dc.tag_network_devices), dnac, tag_id, device_ids)
            for d in found:
                yield emit({"type": "log", "level": "success",
                            "message": f"{d['hostname']} ({d['ip']}): tagged ✓"})
        except Exception as e:
            yield emit({"type": "log", "level": "error", "message": f"Tagging failed: {e}"})
            yield emit({"type": "complete", "tagged": 0, "skipped": len(not_found), "tag_name": req.tag_name})
            return

        yield emit({"type": "complete",
                    "tagged":   len(found),
                    "skipped":  len(not_found),
                    "tag_name": req.tag_name,
                    "results":  found})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Config search ─────────────────────────────────────────────────────────────

class ConfigSearchRequest(BaseModel):
    search_string: str
    hostname:      Optional[str] = None
    ip:            Optional[str] = None
    platform:      Optional[str] = None
    role:          Optional[str] = None
    device_family: Optional[str] = None
    reachability:  str = "Reachable"
    tag:           Optional[str] = None
    max_devices:   Optional[int] = None
    context_lines: int = 5


@router.post("/config-search")
async def config_search(req: ConfigSearchRequest, session: SessionEntry = Depends(require_auth)):
    if not req.search_string or len(req.search_string.strip()) < 2:
        raise HTTPException(400, "search_string must be at least 2 characters")

    loop    = asyncio.get_event_loop()
    dnac    = _get_dnac(session)
    devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "devices", lambda: dc.get_all_devices(dnac), TTL_DEVICES)
    devices = devices or []

    filtered = devices
    q = lambda field, val: val and val.lower() in ((field or "").lower())

    if req.hostname:
        filtered = [d for d in filtered if q(d.get("hostname"), req.hostname)]
    if req.ip:
        filtered = [d for d in filtered if req.ip in (d.get("managementIpAddress") or "")]
    if req.platform:
        filtered = [d for d in filtered if q(d.get("platformId"), req.platform)]
    if req.role:
        filtered = [d for d in filtered if q(d.get("role"), req.role)]
    if req.device_family:
        filtered = [d for d in filtered if q(d.get("family"), req.device_family)
                    or q(d.get("deviceFamily"), req.device_family)]
    if req.reachability:
        if req.reachability.lower() == "reachable":
            filtered = [d for d in filtered if d.get("reachabilityStatus") == "Reachable"]
        elif req.reachability.lower() == "unreachable":
            filtered = [d for d in filtered if d.get("reachabilityStatus") != "Reachable"]

    if req.tag:
        filtered = [
            d for d in filtered
            if req.tag.lower() in " ".join(str(t) for t in (d.get("tags") or d.get("tag") or [])).lower()
            or req.tag.lower() in (d.get("tagName") or "").lower()
        ]

    # Include Nexus devices in search
    from routers.nexus import get_cached_nexus_inventory
    nexus_devices = get_cached_nexus_inventory()

    # Filter Nexus devices
    if req.hostname:
        nexus_devices = [d for d in nexus_devices if q(d.get("hostname"), req.hostname)]
    if req.ip:
        nexus_devices = [d for d in nexus_devices if req.ip in (d.get("managementIpAddress") or "")]
    if req.platform:
        nexus_devices = [d for d in nexus_devices if q(d.get("platformId"), req.platform)]
    if req.role:
        nexus_devices = [d for d in nexus_devices if q(d.get("role"), req.role)]
    if req.reachability:
        if req.reachability.lower() == "reachable":
            nexus_devices = [d for d in nexus_devices if d.get("reachabilityStatus") == "Reachable"]
        elif req.reachability.lower() == "unreachable":
            nexus_devices = [d for d in nexus_devices if d.get("reachabilityStatus") != "Reachable"]

    # Combine
    all_filtered = list(filtered) + nexus_devices

    if not all_filtered:
        return {"total_matches": 0, "results": [], "search_string": req.search_string}

    if req.max_devices and len(all_filtered) > req.max_devices:
        all_filtered = all_filtered[:req.max_devices]

    dnac     = _get_dnac(session)
    search   = req.search_string.lower()

    def fetch_and_search(device: dict) -> dict | None:
        dev_id   = device.get("id", "")

        if device.get("source") == "Nexus":
            from dev import DEV_MODE
            if DEV_MODE:
                from dev import get_mock_config
                config = get_mock_config(dev_id)
            else:
                hostname = dev_id.replace("nexus_", "")
                config = cache.get(f"config:nexus:{hostname}")
        else:
            cfg_key = f"config_{dev_id}"
            config  = cache.get_or_set(cfg_key, lambda: dc.get_device_config(dnac, dev_id), 600)
        if not config: return None

        lines = config.splitlines()
        match_indices = [i for i, line in enumerate(lines) if search in line.lower()]
        if not match_indices: return None

        context = req.context_lines
        blocks = []
        include_indices = set()
        for idx in match_indices:
            for i in range(max(0, idx - context), min(len(lines), idx + context + 1)):
                include_indices.add(i)

        sorted_indices = sorted(list(include_indices))
        if sorted_indices:
            temp_block = []
            for i, idx in enumerate(sorted_indices):
                if i > 0 and idx != sorted_indices[i-1] + 1:
                    blocks.append(temp_block)
                    temp_block = []

                temp_block.append({
                    "line_num": idx + 1,
                    "text": lines[idx],
                    "is_match": idx in match_indices
                })
            blocks.append(temp_block)

        return {
            "hostname": device.get("hostname"), "ip": device.get("managementIpAddress"),
            "platform": device.get("platformId"), "device_id": dev_id,
            "match_count": len(match_indices),
            "lines": [lines[i] for i in match_indices], # Keep for backward compatibility
            "blocks": blocks[:50],
        }

    import time
    search_start = time.time()
    with ThreadPoolExecutor(max_workers=CONFIG_SEARCH_WORKERS) as executor:
        futures_done = list(executor.map(fetch_and_search, all_filtered))

    results = [r for r in futures_done if r is not None]
    results.sort(key=lambda r: (-r["match_count"], r["hostname"]))

    duration_ms = int((time.time() - search_start) * 1000)
    logger.info(
        f"Config search '{req.search_string}': {len(results)}/{len(all_filtered)} devices matched in {duration_ms}ms",
        extra={"target": "DNAC", "action": "CONFIG_SEARCH", "duration_ms": duration_ms},
    )

    return {
        "search_string": req.search_string,
        "total_matches": len(results),
        "results": results,
    }

@router.post("/config-search/ui", response_class=HTMLResponse)
async def config_search_ui(
    request: Request,
    search_string: str = Form(...),
    hostname: Optional[str] = Form(None),
    platform: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    device_family: Optional[str] = Form(None),
    reachability: str = Form("Reachable"),
    tag: Optional[str] = Form(None),
    context_lines: int = Form(5),
    session: SessionEntry = Depends(require_auth)
):
    req = ConfigSearchRequest(
        search_string=search_string,
        hostname=hostname,
        platform=platform,
        role=role,
        device_family=device_family,
        reachability=reachability,
        tag=tag,
        context_lines=context_lines
    )
    results = await config_search(req, session)
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/config_search_results.html", {
        "results": results, "search_string": search_string
    })


# ── Path Trace ──

@router.post("/path-trace/ui", response_class=HTMLResponse)
async def path_trace_ui(
    request: Request,
    source_ip: str = Form(...),
    dest_ip: str = Form(...),
    protocol: str = Form("TCP"),
    dest_port: int = Form(80),
    session: SessionEntry = Depends(require_auth)
):
    loop = asyncio.get_event_loop()
    dnac = _get_dnac(session)
    try:
        task = await loop.run_in_executor(None, run_with_context(dc.initiate_path_trace), dnac, source_ip, dest_ip, protocol, dest_port)
        flow_id = task.get("response", {}).get("flowAnalysisId")
        return HTMLResponse(f"""
            <div class="card shadow-sm animate-fade-in" hx-get="/api/dnac/path-trace/result/{flow_id}" hx-trigger="load delay:3s" hx-swap="outerHTML">
                <div class="card-body p-5 text-center">
                    <div class="spinner spinner-lg mb-3"></div>
                    <h5 class="fw-bold">Path Trace Initiated</h5>
                    <p class="text-muted">Analysis ID: {flow_id}</p>
                </div>
            </div>
        """)
    except Exception as e:
        return HTMLResponse(f"<div class='alert alert-danger'>Path Trace Failed: {str(e)}</div>")

@router.get("/path-trace/result/{flow_id}", response_class=HTMLResponse)
async def path_trace_result_ui(request: Request, flow_id: str, session: SessionEntry = Depends(require_auth)):
    loop = asyncio.get_event_loop()
    dnac = _get_dnac(session)
    result = await loop.run_in_executor(None, run_with_context(dc.get_path_trace_result), dnac, flow_id)
    status = result.get("response", {}).get("request", {}).get("status", "")
    if status in ("INPROGRESS", "PENDING"):
         return HTMLResponse(f"""
            <div class="card shadow-sm animate-fade-in" hx-get="/api/dnac/path-trace/result/{flow_id}" hx-trigger="load delay:3s" hx-swap="outerHTML">
                <div class="card-body p-5 text-center">
                    <div class="spinner spinner-lg mb-3"></div>
                    <h5 class="fw-bold">Analysis in Progress... ({status})</h5>
                </div>
            </div>
        """)
    hops = result.get("response", {}).get("networkElementsInfo", [])
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/path_trace_result.html", {
        "hops": hops,
        "source": result.get("response", {}).get("request", {}).get("sourceIP"),
        "dest": result.get("response", {}).get("request", {}).get("destIP")
    })

@router.get("/devices-select", response_class=HTMLResponse)
async def device_select_partial(request: Request, session: SessionEntry = Depends(require_auth)):
    loop = asyncio.get_event_loop()
    dnac = _get_dnac(session)
    devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "devices", lambda: dc.get_all_devices(dnac), TTL_DEVICES)
    devices = devices or []
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/device_select.html", {"devices": devices})
