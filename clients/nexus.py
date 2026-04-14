import csv
import logging
import os
import asyncio
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from collectors.nxos import NXOSCollector
from models.interface import InterfaceResult

logger = logging.getLogger(__name__)

NEXUS_CSV_PATH = Path("data/device_lists/nexus.csv")

def get_nexus_device_list() -> List[Dict[str, str]]:
    """Read hostname and IP from nexus.csv."""
    devices = []
    if not NEXUS_CSV_PATH.exists():
        logger.warning(f"{NEXUS_CSV_PATH} not found")
        return []

    try:
        with open(NEXUS_CSV_PATH, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 2:
                    continue
                hostname, ip = row[0].strip(), row[1].strip()
                if hostname.lower() == "hostname": # Skip header if present
                    continue
                devices.append({"hostname": hostname, "ip": ip})
    except Exception as e:
        logger.error(f"Error reading {NEXUS_CSV_PATH}: {e}")

    return devices

def collect_from_nexus_device(hostname: str, ip: str, username: str, password: str) -> Tuple[str, List[InterfaceResult], str]:
    """Collect interfaces and config from a single Nexus device."""
    collector = NXOSCollector(hostname=hostname, ip_address=ip, username=username, password=password)
    interfaces, config = collector.collect(include_config=True)
    return ip, interfaces, config or ""

async def collect_all_nexus(username: str, password: str, progress_callback=None):
    """Collect from all Nexus devices in parallel."""
    devices = get_nexus_device_list()
    if not devices:
        return [], {}, {}

    loop = asyncio.get_event_loop()

    inventory = []
    all_interfaces = {}
    all_configs = {}

    if progress_callback:
        await progress_callback({"type": "log", "level": "info", "message": f"Starting collection for {len(devices)} Nexus devices..."})

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for dev in devices:
            futures.append(loop.run_in_executor(
                executor, collect_from_nexus_device, dev["hostname"], dev["ip"], username, password
            ))

        for i, future in enumerate(asyncio.as_completed(futures)):
            try:
                ip, interfaces, config = await future
                hostname = next(d["hostname"] for d in devices if d["ip"] == ip)

                # Check for errors in first interface result
                error = interfaces[0].error if interfaces and interfaces[0].error else None
                status = "Reachable" if not error else "Unreachable"

                inventory.append({
                    "id": f"nexus_{ip}",
                    "hostname": hostname,
                    "managementIpAddress": ip,
                    "platformId": "Nexus",
                    "role": "SWITCH",
                    "reachabilityStatus": status,
                    "reachabilityFailureReason": error,
                    "source": "nexus",
                    "lastUpdateTime": int(os.path.getmtime(NEXUS_CSV_PATH) * 1000) if NEXUS_CSV_PATH.exists() else 0
                })

                if not error:
                    all_interfaces[ip] = [vars(iface) for iface in interfaces]
                    all_configs[ip] = config

                if progress_callback:
                    msg = f"[{hostname}] Collected successfully" if not error else f"[{hostname}] Failed: {error}"
                    await progress_callback({"type": "log", "level": "success" if not error else "error", "message": msg})
            except Exception as e:
                logger.error(f"Error in Nexus collection future: {e}")

    return inventory, all_interfaces, all_configs
