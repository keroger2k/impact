import asyncio
import time
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from auth import require_auth, SessionEntry
from cache import cache

router = APIRouter()

CACHE_SYSTEMS = [
    {
        "id": "dnac",
        "label": "DNAC",
        "icon": "ph-network",
        "keys": ["devices", "sites", "device_site_map"],
        "count_key": "devices",
        "refresh_url": "/api/cache/refresh/devices",
        "sse": False,
    },
    {
        "id": "ipam",
        "label": "IPAM",
        "icon": "ph-tree-structure",
        "keys": ["ipam_tree"],
        "count_key": "ipam_tree",
        "refresh_url": None,
        "sse": True,
        "sse_fn": "triggerIpamCacheRefresh()",
    },
    {
        "id": "ise",
        "label": "ISE",
        "icon": "ph-shield-check",
        "keys": ["ise_nads", "ise_users", "ise_sgts", "ise_policy_sets", "ise_authz_profiles"],
        "count_key": "ise_nads",
        "refresh_url": "/api/cache/refresh/ise",
        "sse": False,
    },
    {
        "id": "panorama",
        "label": "Panorama",
        "icon": "ph-fire",
        "keys": ["pan_device_groups", "pan_managed_devices", "pan_rules"],
        "count_key": "pan_managed_devices",
        "refresh_url": "/api/cache/refresh/panorama",
        "sse": False,
    },
    {
        "id": "aci",
        "label": "ACI",
        "icon": "ph-buildings",
        "keys": ["aci_nodes", "aci_l3outs", "aci_bgp_peers", "aci_epgs", "aci_faults"],
        "count_key": "aci_nodes",
        "refresh_url": "/api/cache/refresh/aci",
        "sse": False,
    },
    {
        "id": "nexus",
        "label": "Nexus",
        "icon": "ph-hard-drives",
        "keys": ["nexus_inventory", "nexus_interfaces"],
        "count_key": "nexus_inventory",
        "refresh_url": None,
        "sse": True,
        "sse_fn": "triggerNexusCacheRefresh()",
    },
]


def _fmt_time(ts: float | None) -> str:
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_age(ts: float | None) -> str:
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 60:
        return f"{int(age)}s ago"
    if age < 3600:
        return f"{int(age / 60)}m ago"
    return f"{int(age / 3600)}h ago"


def _get_system_status(system: dict) -> dict:
    warm_keys = 0
    total_keys = len(system["keys"])
    set_at = None

    for key in system["keys"]:
        info = cache.cache_info(key)
        if info and not info["is_expired"]:
            warm_keys += 1
            if set_at is None:
                set_at = info["set_at"]

    count = 0
    data = cache.get(system["count_key"])
    if isinstance(data, list):
        count = len(data)
    elif isinstance(data, dict):
        if "ipv4" in data and "ipv6" in data:
            count = len(data.get("ipv4", [])) + len(data.get("ipv6", []))
        elif "imdata" in data:
            count = len(data["imdata"])
        else:
            count = len(data)

    if warm_keys == 0:
        status = "empty"
    elif warm_keys == total_keys:
        status = "warm"
    else:
        status = "partial"

    return {
        **system,
        "warm_keys": warm_keys,
        "total_keys": total_keys,
        "count": count,
        "status": status,
        "set_at": _fmt_time(set_at),
        "age": _fmt_age(set_at),
    }


def _get_card_info(key, title, icon, color, refresh_url, sse=False, sse_fn=None):
    info = cache.cache_info(key)
    data = cache.get(key)
    count = 0
    if isinstance(data, list):
        count = len(data)
    elif isinstance(data, dict):
        if "ipv4" in data and "ipv6" in data:
            count = len(data.get("ipv4", [])) + len(data.get("ipv6", []))
        elif "imdata" in data:
            count = len(data["imdata"])
        else:
            count = len(data)

    return {
        "key": key,
        "title": title,
        "icon": icon,
        "color": color,
        "set_at": _fmt_time(info["set_at"]) if info else "Empty",
        "is_expired": info["is_expired"] if info else False,
        "count": count,
        "refresh_url": refresh_url,
        "sse": sse,
        "sse_fn": sse_fn or "triggerNexusCacheRefresh()",
    }


@router.get("/status", response_class=HTMLResponse)
async def get_cache_status(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates

    cards = [
        _get_card_info("devices",           "DNAC Inventory",        "ph ph-network",        "primary",   "/api/cache/refresh/devices"),
        _get_card_info("sites",             "DNAC Sites",            "ph ph-map-pin",         "secondary", "/api/cache/refresh/sites"),
        _get_card_info("ipam_tree",         "IPAM Tree",             "ph ph-tree-structure",  "info",      None,                           sse=True),
        _get_card_info("ise_nads",          "ISE NADs",              "ph ph-shield-check",    "success",   "/api/cache/refresh/ise"),
        _get_card_info("ise_users",         "ISE Users",             "ph ph-users",           "success",   "/api/cache/refresh/ise"),
        _get_card_info("ise_sgts",          "ISE SGTs",              "ph ph-tag",             "success",   "/api/cache/refresh/ise"),
        _get_card_info("pan_managed_devices","Panorama Devices",     "ph ph-fire",            "danger",    "/api/cache/refresh/panorama"),
        _get_card_info("pan_rules",         "Firewall Rules",        "ph ph-fire",            "danger",    "/api/cache/refresh/panorama"),
        _get_card_info("pan_interfaces",    "Firewall Interfaces",   "ph ph-fire",            "danger",    "/api/firewall/interfaces/refresh"),
        _get_card_info("aci_nodes",         "ACI Fabric Nodes",      "ph ph-buildings",       "purple",    "/api/cache/refresh/aci"),
        _get_card_info("aci_bgp_peers",     "ACI BGP Peers",         "ph ph-buildings",       "purple",    "/api/cache/refresh/aci"),
        _get_card_info("nexus_inventory",   "Nexus Switch Inventory","ph ph-hard-drives",     "warning",   None,                           sse=True, sse_fn="triggerNexusCacheRefresh()"),
        _get_card_info("nexus_interfaces",  "Nexus Interface Cache", "ph ph-hard-drives",     "warning",   None,                           sse=True, sse_fn="triggerNexusCacheRefresh()"),
    ]

    return templates.TemplateResponse(request, "partials/cache_cards.html", {"cards": cards})


@router.get("/widget", response_class=HTMLResponse)
async def get_cache_widget(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates
    systems = [_get_system_status(s) for s in CACHE_SYSTEMS]
    return templates.TemplateResponse(request, "partials/cache_widget.html", {"systems": systems})


@router.post("/refresh/{category}")
async def refresh_specific_cache(category: str, session: SessionEntry = Depends(require_auth)):
    if category in ("devices", "dnac"):
        cache.invalidate("devices")
        cache.invalidate("device_site_map")
        cache.invalidate("ipam_tree")
    elif category == "sites":
        cache.invalidate("sites")
        cache.invalidate("device_site_map")
        cache.invalidate("ipam_tree")
    elif category in ("nexus", "nexus_inventory", "nexus_interfaces"):
        cache.invalidate("nexus_inventory")
        cache.invalidate("nexus_interfaces")
    elif category in ("pan_interfaces", "firewall", "panorama"):
        cache.invalidate_prefix("pan_")
    elif category == "ise":
        cache.invalidate_prefix("ise_")
    elif category == "aci":
        cache.invalidate_prefix("aci_")
    elif category == "ipam":
        cache.invalidate("ipam_tree")

    return HTMLResponse(f"""
        <div class="alert alert-success alert-dismissible fade show mb-0" role="alert">
            <strong>Success!</strong> {category.replace('_', ' ').title()} cache invalidated.
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    """)
