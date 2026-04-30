import csv
import json
import asyncio
import logging
import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from auth import SessionEntry, require_auth
from cache import cache, TTL_DEVICES
from collectors.nxos import NXOSCollector
from models.interface import InterfaceResult
from logger_config import run_with_context
from templates_module import templates

router = APIRouter()
logger = logging.getLogger(__name__)

NEXUS_CSV_PATH = Path("data/device_lists/nexus.csv")

def get_nexus_devices_from_csv() -> List[Dict[str, str]]:
    if not NEXUS_CSV_PATH.exists():
        return []

    devices = []
    try:
        with open(NEXUS_CSV_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                hostname = row.get('hostname')
                ip = row.get('management ip address')
                if hostname and ip:
                    devices.append({"hostname": hostname, "ip": ip})
    except Exception as e:
        logger.error(f"Error reading Nexus CSV: {e}")
    return devices

def get_cached_nexus_inventory() -> List[Dict]:
    return cache.get("nexus_inventory") or []

def get_cached_nexus_interfaces() -> List[Dict]:
    return cache.get("nexus_interfaces") or []

@router.get("/refresh")
async def refresh_nexus_data(session: SessionEntry = Depends(require_auth)):
    async def generate():
        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        loop = asyncio.get_event_loop()
        devices = get_nexus_devices_from_csv()

        if not devices:
            yield emit({"type": "log", "level": "warn", "message": "No Nexus devices found in CSV."})
            yield emit({"type": "complete", "count": 0})
            return

        yield emit({"type": "log", "level": "info", "message": f"Starting collection for {len(devices)} Nexus devices..."})

        # Use the current user's credentials for manual refresh
        username = session.username
        password = session.password

        all_interfaces = []
        all_inventory_items = []
        all_port_channels = []
        all_vpcs = []
        all_vlans = []

        def collect_device(dev):
            from dev import DEV_MODE
            hostname = dev['hostname']
            ip = dev['ip']

            if DEV_MODE:
                 inv_item = {
                    "id": f"nexus_{hostname}",
                    "hostname": hostname,
                    "managementIpAddress": ip,
                    "platformId": "Nexus",
                    "role": "SWITCH",
                    "siteName": "Nexus Inventory",
                    "reachabilityStatus": "Reachable",
                    "source": "Nexus",
                    "softwareVersion": "N/A",
                    "lastUpdateTime": int(time.time() * 1000)
                 }
                 return ([
                     InterfaceResult(hostname, ip, "nxos", "Ethernet1/1", "10.1.1.1/24", [], zone="trust", mac_address="00:de:ad:be:ef:01")
                 ], inv_item, None, {"port_channels": [], "vpcs": [], "vlans": []})

            collector = NXOSCollector(hostname, ip, username, password)
            try:
                interfaces, config, extras = collector.collect(collect_config=True)
                if config:
                    cache.set(f"config:nexus:{hostname}", config, 86400 * 7)

                inv_item = {
                    "id": f"nexus_{hostname}",
                    "hostname": hostname,
                    "managementIpAddress": ip,
                    "platformId": "Nexus",
                    "role": "SWITCH",
                    "siteName": "Nexus Inventory",
                    "reachabilityStatus": "Reachable" if not any(i.error for i in interfaces) else "Unreachable",
                    "source": "Nexus",
                    "softwareVersion": "N/A",
                    "lastUpdateTime": int(time.time() * 1000)
                }
                return interfaces, inv_item, None, extras
            except Exception as e:
                logger.error(f"Failed to collect from {hostname} ({ip}): {e}")
                return [], None, str(e), {"port_channels": [], "vpcs": [], "vlans": []}

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [loop.run_in_executor(executor, run_with_context(collect_device), d) for d in devices]
            completed = 0
            for fut in asyncio.as_completed(futures):
                interfaces, inv_item, error, extras = await fut
                completed += 1
                if inv_item:
                    all_interfaces.extend([vars(i) if not isinstance(i, dict) else i for i in interfaces])
                    all_inventory_items.append(inv_item)
                    all_port_channels.extend(extras.get("port_channels", []))
                    all_vpcs.extend(extras.get("vpcs", []))
                    all_vlans.extend(extras.get("vlans", []))
                    yield emit({"type": "log", "level": "success", "message": f"[{completed}/{len(devices)}] {inv_item['hostname']} collected."})
                else:
                    yield emit({"type": "log", "level": "error", "message": f"[{completed}/{len(devices)}] Failed to collect."})

        cache.set("nexus_inventory",     all_inventory_items, TTL_DEVICES)
        cache.set("nexus_interfaces",    all_interfaces,      TTL_DEVICES)
        cache.set("nexus_port_channels", all_port_channels,   TTL_DEVICES)
        cache.set("nexus_vpcs",          all_vpcs,            TTL_DEVICES)
        cache.set("nexus_vlans",         all_vlans,           TTL_DEVICES)
        yield emit({"type": "log", "level": "info", "message": "Nexus cache updated."})
        yield emit({"type": "complete", "count": len(all_inventory_items)})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@router.get("/inventory")
async def list_nexus_inventory():
    return get_cached_nexus_inventory()


# ── HTMX list/detail endpoints (Nexus Insights page) ─────────────────────────

NEXUS_CACHE_KEYS = [
    "nexus_inventory", "nexus_interfaces",
    "nexus_port_channels", "nexus_vpcs", "nexus_vlans",
]


@router.get("/cache/info")
async def nexus_cache_info():
    infos    = {k: cache.cache_info(k) for k in NEXUS_CACHE_KEYS}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}


@router.post("/cache/refresh")
async def nexus_cache_refresh():
    """Clear Nexus caches. New data is gathered by hitting /api/nexus/refresh (SSE)."""
    for k in NEXUS_CACHE_KEYS:
        cache.invalidate(k)
    return {"status": "nexus cache cleared"}


def _interfaces_for(hostname: str) -> list[dict]:
    return [i for i in (cache.get("nexus_interfaces") or []) if i.get("hostname") == hostname]


@router.get("/devices", response_class=HTMLResponse)
async def nexus_devices(request: Request):
    """Inventory list — rendered as an HTMX partial."""
    devices = sorted(get_cached_nexus_inventory(), key=lambda d: (d.get("hostname") or "").lower())
    iface_counts: dict[str, int] = {}
    for iface in (cache.get("nexus_interfaces") or []):
        h = iface.get("hostname") or ""
        iface_counts[h] = iface_counts.get(h, 0) + 1
    return templates.TemplateResponse(
        request,
        "partials/nexus_inventory.html",
        {"items": devices, "iface_counts": iface_counts},
    )


@router.get("/devices/{hostname}", response_class=HTMLResponse)
async def nexus_device_detail(request: Request, hostname: str):
    inv  = next((d for d in get_cached_nexus_inventory() if d.get("hostname") == hostname), None)
    if not inv:
        raise HTTPException(404, f"Unknown Nexus device: {hostname}")
    interfaces    = _interfaces_for(hostname)
    port_channels = [pc for pc in (cache.get("nexus_port_channels") or []) if pc.get("hostname") == hostname]
    vpcs          = [v  for v  in (cache.get("nexus_vpcs")          or []) if v.get("hostname")  == hostname]
    vlans         = [v  for v  in (cache.get("nexus_vlans")         or []) if v.get("hostname")  == hostname]
    return templates.TemplateResponse(
        request,
        "partials/nexus_device_detail.html",
        {
            "device":        inv,
            "interfaces":    interfaces,
            "port_channels": port_channels,
            "vpcs":          vpcs,
            "vlans":         vlans,
        },
    )


@router.get("/interfaces", response_class=HTMLResponse)
async def nexus_interfaces(request: Request):
    interfaces = sorted(
        cache.get("nexus_interfaces") or [],
        key=lambda i: ((i.get("hostname") or "").lower(), (i.get("interface_name") or "").lower()),
    )
    return templates.TemplateResponse(
        request,
        "partials/nexus_interfaces.html",
        {"items": interfaces},
    )


@router.get("/port-channels", response_class=HTMLResponse)
async def nexus_port_channels(request: Request):
    items = sorted(
        cache.get("nexus_port_channels") or [],
        key=lambda p: ((p.get("hostname") or "").lower(), p.get("group", 0)),
    )
    return templates.TemplateResponse(
        request,
        "partials/nexus_port_channels.html",
        {"items": items},
    )


@router.get("/vpcs", response_class=HTMLResponse)
async def nexus_vpcs(request: Request):
    items = sorted(
        cache.get("nexus_vpcs") or [],
        key=lambda v: ((v.get("hostname") or "").lower(), v.get("vpc_id", 0)),
    )
    return templates.TemplateResponse(
        request,
        "partials/nexus_vpcs.html",
        {"items": items},
    )


@router.get("/vlans", response_class=HTMLResponse)
async def nexus_vlans(request: Request):
    items = sorted(
        cache.get("nexus_vlans") or [],
        key=lambda v: ((v.get("hostname") or "").lower(), v.get("vlan_id", 0)),
    )
    return templates.TemplateResponse(
        request,
        "partials/nexus_vlans.html",
        {"items": items},
    )

async def init_nexus_collection(username: Optional[str] = None, password: Optional[str] = None):
    devices = get_nexus_devices_from_csv()
    if not devices: return

    loop = asyncio.get_event_loop()
    # Use provided creds (user's) or service account from env
    username = username or os.getenv("DOMAIN_USERNAME")
    password = password or os.getenv("DOMAIN_PASSWORD")

    if not username or not password:
        from dev import DEV_MODE
        if not DEV_MODE:
            logger.warning("Nexus collection skipped: DOMAIN_USERNAME or DOMAIN_PASSWORD not set.")
            return

    def collect_device(dev):
        from dev import DEV_MODE
        hostname = dev['hostname']
        ip = dev['ip']
        empty_extras = {"port_channels": [], "vpcs": [], "vlans": []}
        if DEV_MODE:
             inv_item = {
                "id": f"nexus_{hostname}",
                "hostname": hostname,
                "managementIpAddress": ip,
                "platformId": "Nexus",
                "role": "SWITCH",
                "siteName": "Nexus Inventory",
                "reachabilityStatus": "Reachable",
                "source": "Nexus",
                "softwareVersion": "N/A",
                "lastUpdateTime": int(time.time() * 1000)
             }
             return ([
                 InterfaceResult(hostname, ip, "nxos", "Ethernet1/1", "10.1.1.1/24", [], zone="trust", mac_address="00:de:ad:be:ef:01")
             ], inv_item, None, empty_extras)

        collector = NXOSCollector(hostname, ip, username, password)
        try:
            interfaces, config, extras = collector.collect(collect_config=True)
            if config:
                cache.set(f"config:nexus:{hostname}", config, 86400 * 7)
            inv_item = {
                "id": f"nexus_{hostname}",
                "hostname": hostname,
                "managementIpAddress": ip,
                "platformId": "Nexus",
                "role": "SWITCH",
                "siteName": "Nexus Inventory",
                "reachabilityStatus": "Reachable" if not any(i.error for i in interfaces) else "Unreachable",
                "source": "Nexus",
                "softwareVersion": "N/A",
                "lastUpdateTime": int(time.time() * 1000)
            }
            return interfaces, inv_item, None, extras
        except Exception:
            return [], None, None, empty_extras

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [loop.run_in_executor(executor, run_with_context(collect_device), d) for d in devices]
        results = await asyncio.gather(*futures)
        all_interfaces = []
        all_inventory_items = []
        all_port_channels = []
        all_vpcs = []
        all_vlans = []
        for res in results:
            if res and isinstance(res, (list, tuple)) and len(res) >= 4:
                interfaces, inv_item, _err, extras = res[0], res[1], res[2], res[3]
                if inv_item:
                    all_interfaces.extend([vars(i) if not isinstance(i, dict) else i for i in interfaces])
                    all_inventory_items.append(inv_item)
                    all_port_channels.extend(extras.get("port_channels", []))
                    all_vpcs.extend(extras.get("vpcs", []))
                    all_vlans.extend(extras.get("vlans", []))

        if all_inventory_items:
            cache.set("nexus_inventory",     all_inventory_items, TTL_DEVICES)
            cache.set("nexus_interfaces",    all_interfaces,      TTL_DEVICES)
            cache.set("nexus_port_channels", all_port_channels,   TTL_DEVICES)
            cache.set("nexus_vpcs",          all_vpcs,            TTL_DEVICES)
            cache.set("nexus_vlans",         all_vlans,           TTL_DEVICES)
