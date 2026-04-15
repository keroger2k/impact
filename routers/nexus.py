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
from fastapi.responses import StreamingResponse

from auth import SessionEntry, require_auth
from cache import cache
from collectors.nxos import NXOSCollector
from models.interface import InterfaceResult

router = APIRouter()
logger = logging.getLogger(__name__)

NEXUS_CSV_PATH = Path("data/device_lists/nexus.csv")
NEXUS_CACHE_PATH = Path("data/cache/nexus_inventory.json")
CONFIG_CACHE_DIR = Path("data/cache/configs")

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

@router.post("/refresh")
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
                 return [
                     InterfaceResult(hostname, ip, "nxos", "Ethernet1/1", "10.1.1.1/24", [], zone="trust", mac_address="00:de:ad:be:ef:01")
                 ], inv_item, None

            collector = NXOSCollector(hostname, ip, username, password)
            try:
                interfaces, config = collector.collect(collect_config=True)
                if config:
                    safe_host = hostname.replace("/", "_")
                    config_path = CONFIG_CACHE_DIR / f"nexus_{safe_host}.txt"
                    CONFIG_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    config_path.write_text(config, encoding="utf-8")

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
                return interfaces, inv_item, None
            except Exception as e:
                logger.error(f"Failed to collect from {hostname} ({ip}): {e}")
                return [], None, str(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [loop.run_in_executor(executor, collect_device, d) for d in devices]
            completed = 0
            for fut in asyncio.as_completed(futures):
                interfaces, inv_item, error = await fut
                completed += 1
                if inv_item:
                    all_interfaces.extend([vars(i) if not isinstance(i, dict) else i for i in interfaces])
                    all_inventory_items.append(inv_item)
                    yield emit({"type": "log", "level": "success", "message": f"[{completed}/{len(devices)}] {inv_item['hostname']} collected."})
                else:
                    yield emit({"type": "log", "level": "error", "message": f"[{completed}/{len(devices)}] Failed to collect."})

        cache.set("nexus_inventory", all_inventory_items, 86400 * 7)
        cache.set("nexus_interfaces", all_interfaces, 86400 * 7)
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

async def init_nexus_collection(username: Optional[str] = None, password: Optional[str] = None):
    devices = get_nexus_devices_from_csv()
    if not devices: return

    loop = asyncio.get_event_loop()
    # Use provided creds (user's) or service account from env
    username = username or os.getenv("DOMAIN_USERNAME")
    password = password or os.getenv("DOMAIN_PASSWORD")

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
             return [
                 InterfaceResult(hostname, ip, "nxos", "Ethernet1/1", "10.1.1.1/24", [], zone="trust", mac_address="00:de:ad:be:ef:01")
             ], inv_item, None

        collector = NXOSCollector(hostname, ip, username, password)
        try:
            interfaces, config = collector.collect(collect_config=True)
            if config:
                safe_host = hostname.replace("/", "_")
                config_path = CONFIG_CACHE_DIR / f"nexus_{safe_host}.txt"
                CONFIG_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                config_path.write_text(config, encoding="utf-8")
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
            return interfaces, inv_item, None
        except Exception:
            return [], None, None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [loop.run_in_executor(executor, collect_device, d) for d in devices]
        results = await asyncio.gather(*futures)
        all_interfaces = []
        all_inventory_items = []
        for res in results:
            if res and isinstance(res, (list, tuple)) and len(res) >= 2:
                interfaces, inv_item = res[0], res[1]
                if inv_item:
                    all_interfaces.extend([vars(i) if not isinstance(i, dict) else i for i in interfaces])
                    all_inventory_items.append(inv_item)

        if all_inventory_items:
            cache.set("nexus_inventory", all_inventory_items, 86400 * 7)
            cache.set("nexus_interfaces", all_interfaces, 86400 * 7)
