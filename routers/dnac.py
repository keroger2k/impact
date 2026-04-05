"""routers/dnac.py — Catalyst Center API endpoints."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

import clients.dnac as dc
from cache import cache, TTL_DEVICES, TTL_SITES

router = APIRouter()
logger = logging.getLogger(__name__)


def _get_dnac():
    try:
        return dc.get_client()
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

@router.get("/devices")
async def list_devices(
    hostname:     Optional[str] = None,
    ip:           Optional[str] = None,
    platform:     Optional[str] = None,
    role:         Optional[str] = None,
    reachability: Optional[str] = None,
    limit:        int = Query(500, le=2000),
    offset:       int = Query(0, ge=0),
):
    """Return filtered device list from cache."""
    devices = cache.get("devices")
    if devices is None:
        loop = asyncio.get_event_loop()
        dnac    = _get_dnac()
        devices = await loop.run_in_executor(None, dc.get_all_devices, dnac)
        cache.set("devices", devices, TTL_DEVICES)

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

    total  = len(filtered)
    paged  = [_enrich(d) for d in filtered[offset: offset + limit]]
    return {"total": total, "offset": offset, "limit": limit, "items": paged}


@router.get("/devices/stats")
async def device_stats():
    """Summary statistics for the dashboard."""
    devices = cache.get("devices")
    if devices is None:
        loop    = asyncio.get_event_loop()
        dnac    = _get_dnac()
        devices = await loop.run_in_executor(None, dc.get_all_devices, dnac)
        cache.set("devices", devices, TTL_DEVICES)

    from collections import Counter
    reachable   = sum(1 for d in devices if d.get("reachabilityStatus") == "Reachable")
    unreachable = len(devices) - reachable
    platforms   = Counter(d.get("platformId", "Unknown") or "Unknown" for d in devices)
    versions    = Counter(d.get("softwareVersion", "Unknown") or "Unknown" for d in devices)
    roles       = Counter(d.get("role", "UNKNOWN") or "UNKNOWN" for d in devices)

    return {
        "total":        len(devices),
        "reachable":    reachable,
        "unreachable":  unreachable,
        "pct_reachable": round(reachable / len(devices) * 100, 1) if devices else 0,
        "platforms":    platforms.most_common(15),
        "versions":     versions.most_common(12),
        "roles":        roles.most_common(),
    }


@router.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Device detail by ID."""
    devices = cache.get("devices") or []
    device  = next((d for d in devices if d.get("id") == device_id), None)
    if not device:
        raise HTTPException(404, "Device not found")
    return _enrich(device)


@router.get("/devices/{device_id}/config")
async def get_device_config(device_id: str):
    """Running configuration for a device."""
    cache_key = f"config_{device_id}"
    cached    = cache.get(cache_key)
    if cached is not None:
        return {"config": cached, "cached": True}

    loop   = asyncio.get_event_loop()
    dnac   = _get_dnac()
    config = await loop.run_in_executor(None, dc.get_device_config, dnac, device_id)
    if not config:
        raise HTTPException(404, "Config not available for this device")

    cache.set(cache_key, config, 600)   # cache configs for 10 min
    return {"config": config, "cached": False}


# ── IP Lookup ─────────────────────────────────────────────────────────────────

@router.get("/ip-lookup/{ip}")
async def ip_lookup(ip: str):
    """Find what interface and device owns an IP address."""
    import ipaddress as _ip
    try:
        _ip.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"'{ip}' is not a valid IP address")

    loop   = asyncio.get_event_loop()
    dnac   = _get_dnac()
    ifaces = await loop.run_in_executor(None, dc.get_interface_by_ip, dnac, ip)

    if not ifaces:
        return {"ip": ip, "found": False, "interfaces": []}

    devices    = cache.get("devices") or []
    id_to_dev  = {d.get("id"): d for d in devices if d.get("id")}

    enriched = []
    for iface in ifaces:
        dev_id = iface.get("deviceId")
        device = id_to_dev.get(dev_id, {})

        # Build subnet string
        subnet = None
        addr   = iface.get("ipv4Address")
        mask   = iface.get("ipv4Mask")
        if addr and mask:
            try:
                import ipaddress as _ip2
                net    = _ip2.ip_network(f"{addr}/{mask}", strict=False)
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
            "device": _enrich(device) if device else None,
        })

    return {"ip": ip, "found": True, "interfaces": enriched}


# ── Sites ─────────────────────────────────────────────────────────────────────

@router.get("/sites")
async def list_sites(filter: Optional[str] = None):
    sites = cache.get("sites")
    if sites is None:
        loop  = asyncio.get_event_loop()
        dnac  = _get_dnac()
        sites = await loop.run_in_executor(None, dc.get_site_cache, dnac)
        cache.set("sites", sites, TTL_SITES)

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
    """Force full cache refresh."""
    cache.clear()
    await cache.warm()
    return {"status": "refreshed"}


# ── Config search ─────────────────────────────────────────────────────────────

class ConfigSearchRequest(BaseModel):
    search_string: str
    hostname:      Optional[str] = None
    ip:            Optional[str] = None
    platform:      Optional[str] = None
    role:          Optional[str] = None
    device_family: Optional[str] = None
    reachability:  str = "Reachable"   # only Reachable by default; "" = all
    tag:           Optional[str] = None
    max_devices:   int = 500           # safety cap; 0 = no limit


@router.post("/config-search")
async def config_search(req: ConfigSearchRequest):
    """
    Pull device configs from DNAC (cached per device, 10 min TTL) and
    search for a string. Returns matching devices with the lines that matched.

    Supports partial matching on all filter fields.
    Configs are fetched in parallel across matching devices.
    """
    if not req.search_string or len(req.search_string.strip()) < 2:
        raise HTTPException(400, "search_string must be at least 2 characters")

    # ── 1. Get device list from cache ──────────────────────────────────────────
    devices = cache.get("devices")
    if devices is None:
        loop    = asyncio.get_event_loop()
        dnac    = _get_dnac()
        devices = await loop.run_in_executor(None, dc.get_all_devices, dnac)
        cache.set("devices", devices, TTL_DEVICES)

    # ── 2. Apply device filters (all partial-match) ────────────────────────────
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

    # Tag filtering — DNAC tags live on a separate endpoint; check tagName if present
    if req.tag:
        # Some responses include a 'tags' list or 'tagName' field
        filtered = [
            d for d in filtered
            if req.tag.lower() in " ".join(
                str(t) for t in (d.get("tags") or d.get("tag") or [])
            ).lower()
            or req.tag.lower() in (d.get("tagName") or "").lower()
        ]

    if not filtered:
        return {"devices_matched_filter": 0, "devices_searched": 0,
                "total_matches": 0, "results": [],
                "search_string": req.search_string}

    # Apply safety cap
    if req.max_devices and len(filtered) > req.max_devices:
        filtered = filtered[:req.max_devices]

    # ── 3. Fetch configs in parallel from DNAC cache ───────────────────────────
    dnac     = _get_dnac()
    loop     = asyncio.get_event_loop()
    search   = req.search_string.lower()
    results  = []

    def fetch_and_search(device: dict) -> dict | None:
        dev_id   = device.get("id", "")
        hostname = device.get("hostname", dev_id)

        # Per-device config cache (10 min TTL)
        cfg_key = f"config_{dev_id}"
        config  = cache.get(cfg_key)

        if config is None:
            config = dc.get_device_config(dnac, dev_id)
            if config:
                cache.set(cfg_key, config, 600)

        if not config:
            return None

        # Search — case-insensitive, partial match
        matching_lines = [
            {"line_num": i + 1, "text": line}
            for i, line in enumerate(config.splitlines())
            if search in line.lower()
        ]

        if not matching_lines:
            return None

        return {
            "hostname":      hostname,
            "ip":            device.get("managementIpAddress"),
            "platform":      device.get("platformId"),
            "role":          device.get("role"),
            "reachability":  device.get("reachabilityStatus"),
            "device_id":     dev_id,
            "match_count":   len(matching_lines),
            "lines":         matching_lines[:200],   # cap per-device line output
        }

    # Run parallel config fetches
    futures_done = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futs = [executor.submit(fetch_and_search, d) for d in filtered]
        futures_done = [f.result() for f in futs]

    results = [r for r in futures_done if r is not None]
    results.sort(key=lambda r: (-r["match_count"], r["hostname"]))

    return {
        "search_string":         req.search_string,
        "devices_matched_filter": len(filtered),
        "devices_searched":       sum(1 for r in futures_done if r is not None or True),
        "devices_with_config":    sum(1 for r in futures_done if r is not None or True),
        "total_matches":          len(results),
        "total_matching_lines":   sum(r["match_count"] for r in results),
        "results":                results,
    }
