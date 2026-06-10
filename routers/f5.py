"""
routers/f5.py — F5 BIG-IP visibility endpoints (READ-ONLY).

CSV-driven device list + per-user AD creds + SSE refresh, mirroring the Nexus
router. All data comes from `clients.f5`, which issues only HTTP GET — nothing
here can mutate an F5.
"""

import csv
import json
import asyncio
import logging
import os
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from auth import SessionEntry, require_auth
from cache import cache, TTL_MANUAL as TTL_F5
import clients.f5 as f5c
from logger_config import run_with_context
from templates_module import templates

router = APIRouter()
logger = logging.getLogger(__name__)

F5_CSV_PATH = Path("data/device_lists/f5.csv")

from datasets import F5_CACHE_KEYS


def get_f5_devices_from_csv() -> List[Dict[str, str]]:
    if not F5_CSV_PATH.exists():
        return []
    devices: List[Dict[str, str]] = []
    try:
        with open(F5_CSV_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                hostname = (row.get("hostname") or "").strip()
                ip = (row.get("management ip address") or "").strip()
                if hostname and ip:
                    devices.append({"hostname": hostname, "ip": ip})
    except Exception as e:
        logger.error(f"Error reading F5 CSV: {e}")
    return devices


def get_cached_f5_inventory() -> List[Dict]:
    return cache.get("f5_inventory") or []


def get_cached_f5_self_ips() -> List[Dict]:
    return cache.get("f5_self_ips") or []


def get_cached_f5_virtuals() -> List[Dict]:
    return cache.get("f5_virtuals") or []


# ── Site filtering ────────────────────────────────────────────────────────────
# F5s reside at a handful of locations; the site code is the first 4 chars of the
# hostname. The UI exposes a dropdown (built from the live inventory) so a user
# can scope every tab to one site instead of one big cross-site table.

def _site_of(hostname: str) -> str:
    return (hostname or "")[:4].upper()


def _by_site(rows: List[Dict], site: Optional[str]) -> List[Dict]:
    if not site or site.lower() == "all":
        return rows
    s = site.upper()
    return [r for r in rows if _site_of(r.get("hostname")) == s]


def get_f5_sites() -> List[str]:
    return sorted({_site_of(d.get("hostname")) for d in get_cached_f5_inventory() if d.get("hostname")})


# ── Collection helpers ────────────────────────────────────────────────────────

def _store_bundles(bundles: List[dict]) -> int:
    """Flatten per-device bundles into the flat f5_* caches. Returns device count."""
    inventory, self_ips, vlans, interfaces = [], [], [], []
    virtuals, pools, nodes, routes = [], [], [], []
    for b in bundles:
        if not b or not b.get("inventory"):
            continue
        inventory.append(b["inventory"])
        self_ips.extend(b.get("self_ips", []))
        vlans.extend(b.get("vlans", []))
        interfaces.extend(b.get("interfaces", []))
        virtuals.extend(b.get("virtuals", []))
        pools.extend(b.get("pools", []))
        nodes.extend(b.get("nodes", []))
        routes.extend(b.get("routes", []))
    cache.set("f5_inventory",  inventory,  TTL_F5)
    cache.set("f5_self_ips",   self_ips,   TTL_F5)
    cache.set("f5_vlans",      vlans,      TTL_F5)
    cache.set("f5_interfaces", interfaces, TTL_F5)
    cache.set("f5_virtuals",   virtuals,   TTL_F5)
    cache.set("f5_pools",      pools,      TTL_F5)
    cache.set("f5_nodes",      nodes,      TTL_F5)
    cache.set("f5_routes",     routes,     TTL_F5)
    return len(inventory)


def _seed_f5_dev() -> int:
    """DEV_MODE: populate the f5_* caches from the dev mock fixtures."""
    from dev import (
        MOCK_F5_DEVICES, MOCK_F5_SELF_IPS, MOCK_F5_VLANS, MOCK_F5_INTERFACES,
        MOCK_F5_VIRTUALS, MOCK_F5_POOLS, MOCK_F5_NODES, MOCK_F5_ROUTES,
    )
    cache.set("f5_inventory",  MOCK_F5_DEVICES,    TTL_F5)
    cache.set("f5_self_ips",   MOCK_F5_SELF_IPS,   TTL_F5)
    cache.set("f5_vlans",      MOCK_F5_VLANS,      TTL_F5)
    cache.set("f5_interfaces", MOCK_F5_INTERFACES, TTL_F5)
    cache.set("f5_virtuals",   MOCK_F5_VIRTUALS,   TTL_F5)
    cache.set("f5_pools",      MOCK_F5_POOLS,      TTL_F5)
    cache.set("f5_nodes",      MOCK_F5_NODES,      TTL_F5)
    cache.set("f5_routes",     MOCK_F5_ROUTES,     TTL_F5)
    return len(MOCK_F5_DEVICES)


# ── SSE refresh ───────────────────────────────────────────────────────────────

@router.get("/refresh")
async def refresh_f5_data(session: SessionEntry = Depends(require_auth)):
    async def generate():
        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        from dev import DEV_MODE
        loop = asyncio.get_event_loop()
        devices = get_f5_devices_from_csv()

        if DEV_MODE:
            yield emit({"type": "log", "level": "info", "message": "DEV_MODE: seeding mock F5 data..."})
            count = _seed_f5_dev()
            yield emit({"type": "log", "level": "success", "message": f"Seeded {count} mock F5 devices."})
            yield emit({"type": "complete", "count": count})
            return

        if not devices:
            yield emit({"type": "log", "level": "warn", "message": "No F5 devices found in CSV."})
            yield emit({"type": "complete", "count": 0})
            return

        yield emit({"type": "log", "level": "info", "message": f"Starting collection for {len(devices)} F5 devices..."})

        username = session.username
        password = session.password

        def collect(dev):
            try:
                return f5c.collect_device(dev["hostname"], dev["ip"], username, password)
            except Exception as e:
                logger.error(f"F5 collect failed for {dev['hostname']} ({dev['ip']}): {e}")
                return None

        bundles: List[dict] = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [loop.run_in_executor(executor, run_with_context(collect), d) for d in devices]
            completed = 0
            for fut in asyncio.as_completed(futures):
                b = await fut
                completed += 1
                if b and b.get("inventory"):
                    bundles.append(b)
                    yield emit({"type": "log", "level": "success",
                                "message": f"[{completed}/{len(devices)}] {b['inventory']['hostname']} collected."})
                else:
                    yield emit({"type": "log", "level": "error",
                                "message": f"[{completed}/{len(devices)}] Failed to collect."})

        count = _store_bundles(bundles)
        yield emit({"type": "log", "level": "info", "message": "F5 cache updated."})
        yield emit({"type": "complete", "count": count})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/inventory")
async def list_f5_inventory():
    return get_cached_f5_inventory()


# ── Cache info/refresh ────────────────────────────────────────────────────────

@router.get("/cache/info")
async def f5_cache_info():
    infos = {k: cache.cache_info(k) for k in F5_CACHE_KEYS}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}


@router.post("/cache/refresh")
async def f5_cache_refresh():
    """Clear F5 caches. New data is gathered by hitting /api/f5/refresh (SSE)."""
    for k in F5_CACHE_KEYS:
        cache.invalidate(k)
    return {"status": "f5 cache cleared"}


# ── HTMX list/detail endpoints ────────────────────────────────────────────────

def _filter(key: str, hostname: str) -> list[dict]:
    return [r for r in (cache.get(key) or []) if r.get("hostname") == hostname]


@router.get("/sites", response_class=HTMLResponse)
async def f5_site_options(request: Request, site: str = "all"):
    """Dropdown <option>s for the site filter, derived live from the inventory."""
    return templates.TemplateResponse(
        request, "partials/f5_site_options.html",
        {"sites": get_f5_sites(), "selected": (site or "all")},
    )


@router.get("/devices", response_class=HTMLResponse)
async def f5_devices(request: Request, site: str = "all"):
    """Inventory list — rendered as an HTMX partial."""
    devices = sorted(_by_site(get_cached_f5_inventory(), site), key=lambda d: (d.get("hostname") or "").lower())
    vip_counts: dict[str, int] = {}
    for v in _by_site(get_cached_f5_virtuals(), site):
        h = v.get("hostname") or ""
        vip_counts[h] = vip_counts.get(h, 0) + 1
    return templates.TemplateResponse(
        request, "partials/f5_inventory.html",
        {"items": devices, "vip_counts": vip_counts},
    )


@router.get("/devices/{hostname}", response_class=HTMLResponse)
async def f5_device_detail(request: Request, hostname: str):
    inv = next((d for d in get_cached_f5_inventory() if d.get("hostname") == hostname), None)
    if not inv:
        raise HTTPException(404, f"Unknown F5 device: {hostname}")
    return templates.TemplateResponse(
        request, "partials/f5_device_detail.html",
        {
            "device":     inv,
            "self_ips":   _filter("f5_self_ips", hostname),
            "vlans":      _filter("f5_vlans", hostname),
            "interfaces": _filter("f5_interfaces", hostname),
            "virtuals":   _filter("f5_virtuals", hostname),
            "pools":      _filter("f5_pools", hostname),
            "nodes":      _filter("f5_nodes", hostname),
            "routes":     _filter("f5_routes", hostname),
        },
    )


@router.get("/virtual-servers", response_class=HTMLResponse)
async def f5_virtual_servers(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_virtuals") or [], site),
        key=lambda v: ((v.get("hostname") or "").lower(), (v.get("name") or "").lower()),
    )
    return templates.TemplateResponse(request, "partials/f5_virtual_servers.html", {"items": items})


@router.get("/pools", response_class=HTMLResponse)
async def f5_pools(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_pools") or [], site),
        key=lambda p: ((p.get("hostname") or "").lower(), (p.get("name") or "").lower()),
    )
    return templates.TemplateResponse(request, "partials/f5_pools.html", {"items": items})


@router.get("/nodes", response_class=HTMLResponse)
async def f5_nodes(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_nodes") or [], site),
        key=lambda n: ((n.get("hostname") or "").lower(), (n.get("name") or "").lower()),
    )
    return templates.TemplateResponse(request, "partials/f5_nodes.html", {"items": items})


@router.get("/self-ips", response_class=HTMLResponse)
async def f5_self_ips(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_self_ips") or [], site),
        key=lambda s: ((s.get("hostname") or "").lower(), (s.get("name") or "").lower()),
    )
    return templates.TemplateResponse(request, "partials/f5_self_ips.html", {"items": items})


@router.get("/vlans", response_class=HTMLResponse)
async def f5_vlans(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_vlans") or [], site),
        key=lambda v: ((v.get("hostname") or "").lower(), (v.get("tag") or 0)),
    )
    return templates.TemplateResponse(request, "partials/f5_vlans.html", {"items": items})


@router.get("/interfaces", response_class=HTMLResponse)
async def f5_interfaces(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_interfaces") or [], site),
        key=lambda i: ((i.get("hostname") or "").lower(), (i.get("name") or "").lower()),
    )
    return templates.TemplateResponse(request, "partials/f5_interfaces.html", {"items": items})


@router.get("/routes", response_class=HTMLResponse)
async def f5_routes(request: Request, site: str = "all"):
    items = sorted(
        _by_site(cache.get("f5_routes") or [], site),
        key=lambda r: ((r.get("hostname") or "").lower(), (r.get("name") or "").lower()),
    )
    return templates.TemplateResponse(request, "partials/f5_routes.html", {"items": items})


# ── Startup / warm collection ─────────────────────────────────────────────────

async def init_f5_collection(username: Optional[str] = None, password: Optional[str] = None):
    from dev import DEV_MODE
    if DEV_MODE:
        _seed_f5_dev()
        return

    devices = get_f5_devices_from_csv()
    if not devices:
        return

    username = username or os.getenv("DOMAIN_USERNAME")
    password = password or os.getenv("DOMAIN_PASSWORD")
    if not username or not password:
        logger.warning("F5 collection skipped: DOMAIN_USERNAME or DOMAIN_PASSWORD not set.")
        return

    loop = asyncio.get_event_loop()

    def collect(dev):
        try:
            return f5c.collect_device(dev["hostname"], dev["ip"], username, password)
        except Exception as e:
            logger.error(f"F5 collect failed for {dev['hostname']} ({dev['ip']}): {e}")
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [loop.run_in_executor(executor, run_with_context(collect), d) for d in devices]
        bundles = await asyncio.gather(*futures)

    bundles = [b for b in bundles if b and b.get("inventory")]
    if bundles:
        _store_bundles(bundles)
