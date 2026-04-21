import asyncio
import time
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from auth import require_auth, SessionEntry
from cache import cache
import logging



router = APIRouter()
logger = logging.getLogger(__name__)

# ── System definitions for cache widget ──────────────────────────────────────

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

# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _count_cached(key: str) -> int:
    data = cache.get(key)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        if "ipv4" in data and "ipv6" in data:
            return len(data.get("ipv4", [])) + len(data.get("ipv6", []))
        if "imdata" in data:
            return len(data["imdata"])
        return len(data)
    return 0


def _get_system_status(system: dict) -> dict:
    # Status is driven by the primary key — the one that represents whether
    # the system is actually usable. Secondary keys may be missing if the user
    # hasn't visited every sub-page yet (e.g. ACI faults, ISE authz profiles).
    primary_info = cache.cache_info(system["count_key"])
    primary_warm = primary_info is not None and not primary_info["is_expired"]

    any_warm = False
    set_at = primary_info["set_at"] if primary_info else None
    for key in system["keys"]:
        info = cache.cache_info(key)
        if info and not info["is_expired"]:
            any_warm = True
            if set_at is None:
                set_at = info["set_at"]

    count = _count_cached(system["count_key"])

    if primary_warm:
        status = "warm"
    elif any_warm:
        status = "partial"
    else:
        status = "empty"

    return {
        **system,
        "count": count,
        "status": status,
        "set_at": _fmt_time(set_at),
        "age": _fmt_age(set_at),
    }


def _get_card_info(key, title, icon, color, refresh_url, sse=False, sse_fn=None):
    info = cache.cache_info(key)
    return {
        "key": key,
        "title": title,
        "icon": icon,
        "color": color,
        "set_at": _fmt_time(info["set_at"]) if info else "Empty",
        "is_expired": info["is_expired"] if info else False,
        "count": _count_cached(key),
        "refresh_url": refresh_url,
        "sse": sse,
        "sse_fn": sse_fn or "triggerNexusCacheRefresh()",
    }

# ── Background re-fetch helpers ───────────────────────────────────────────────

async def _refetch_dnac(session: SessionEntry, include_devices: bool, include_sites: bool):
    from logger_config import run_with_context
    import clients.dnac as dc
    import auth as auth_module
    from cache import TTL_DEVICES, TTL_SITES
    loop = asyncio.get_event_loop()
    try:
        dnac = auth_module.get_dnac_for_session(session)

        if include_devices:
            logger.info("Cache refresh: re-fetching DNAC devices")
            devices = await loop.run_in_executor(None, run_with_context(dc.get_all_devices, dnac))
            if devices is not None:
                cache.set("devices", devices, TTL_DEVICES)
                logger.info(f"Cache refresh: stored {len(devices)} devices")

        if include_sites:
            logger.info("Cache refresh: re-fetching DNAC sites")
            sites = await loop.run_in_executor(None, run_with_context(dc.get_site_cache, dnac))
            if sites is not None:
                cache.set("sites", sites, TTL_SITES)
                logger.info(f"Cache refresh: stored {len(sites)} sites")

        # Rebuild device→site map if both are now available
        devices = cache.get("devices")
        sites = cache.get("sites")
        if devices is not None and sites is not None:
            logger.info("Cache refresh: rebuilding device-to-site map")
            dev_site_map = await loop.run_in_executor(
                None, run_with_context(dc.build_device_site_map, dnac, sites)
            )
            if dev_site_map is not None:
                cache.set("device_site_map", dev_site_map, TTL_SITES)
                logger.info(f"Cache refresh: stored {len(dev_site_map)} device-site mappings")

    except Exception as e:
        logger.warning(f"DNAC re-fetch failed: {e}")


async def _refetch_ise(session: SessionEntry):
    from logger_config import run_with_context
    import clients.ise as ic
    import auth as auth_module
    from cache import TTL_ISE_POLICIES
    loop = asyncio.get_event_loop()
    try:
        ise = auth_module.get_ise_for_session(session)
        key_loaders = [
            ("ise_nads",               lambda: ic.get_network_devices(ise, "")),
            ("ise_nad_groups",         lambda: ic.get_network_device_groups(ise)),
            ("ise_endpoint_groups",    lambda: ic.get_endpoint_groups(ise)),
            ("ise_identity_groups",    lambda: ic.get_identity_groups(ise)),
            ("ise_users",              lambda: ic.get_internal_users(ise, "")),
            ("ise_sgts",               lambda: ic.get_sgts(ise)),
            ("ise_sgacls",             lambda: ic.get_sgacls(ise)),
            ("ise_egress_matrix",      lambda: ic.get_egress_matrix(ise)),
            ("ise_policy_sets",        lambda: ic.get_policy_sets(ise)),
            ("ise_authz_profiles",     lambda: ic.get_authz_profiles(ise)),
            ("ise_allowed_protocols",  lambda: ic.get_allowed_protocols(ise)),
            ("ise_profiling_policies", lambda: ic.get_profiling_policies(ise)),
            ("ise_deployment_nodes",   lambda: ic.get_deployment_nodes(ise)),
        ]
        for key, loader in key_loaders:
            try:
                data = await loop.run_in_executor(None, run_with_context(loader))
                if data is not None:
                    cache.set(key, data, TTL_ISE_POLICIES)
            except Exception as e:
                logger.warning(f"ISE re-fetch failed for {key}: {e}")
        logger.info("Cache refresh: ISE re-fetch complete")
    except Exception as e:
        logger.warning(f"ISE re-fetch failed: {e}")


async def _refetch_panorama(session: SessionEntry):
    from logger_config import run_with_context
    import clients.panorama as pc
    import auth as auth_module
    from routers.firewall import PAN_TTL
    loop = asyncio.get_event_loop()
    try:
        pan_key = auth_module.get_panorama_key_for_session(session)
        all_dgs = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_device_groups",
            lambda: pc.get_device_groups(pan_key), PAN_TTL
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_managed_devices",
            lambda: pc.get_managed_devices(pan_key), PAN_TTL
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_addr",
            lambda: pc.get_address_objects_and_groups(pan_key, all_dgs), PAN_TTL
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_svc",
            lambda: pc.get_services(pan_key, all_dgs), PAN_TTL
        )

        def _build_rules():
            all_rules = pc.get_all_security_rules(pan_key, all_dgs)
            by_dg: dict[str, list] = {}
            for rule in all_rules:
                dg = rule.get("device_group", "shared")
                by_dg.setdefault(dg, []).append(rule)
            return {"dg_order": all_dgs, "by_dg": by_dg}

        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_rules", _build_rules, PAN_TTL
        )
        logger.info("Cache refresh: Panorama re-fetch complete")
    except Exception as e:
        logger.warning(f"Panorama re-fetch failed: {e}")

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status", response_class=HTMLResponse)
async def get_cache_status(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates

    cards = [
        _get_card_info("devices",            "DNAC Inventory",        "ph ph-network",         "primary",   "/api/cache/refresh/devices"),
        _get_card_info("sites",              "DNAC Sites",            "ph ph-map-pin",          "primary",   "/api/cache/refresh/sites"),
        _get_card_info("device_site_map",    "DNAC Device-Site Map",  "ph ph-map-trifold",      "primary",   "/api/cache/refresh/sites"),
        _get_card_info("ipam_tree",          "IPAM Tree",             "ph ph-tree-structure",   "info",      None,                             sse=True, sse_fn="triggerIpamCacheRefresh()"),
        _get_card_info("ise_nads",           "ISE NADs",              "ph ph-shield-check",     "success",   "/api/cache/refresh/ise"),
        _get_card_info("ise_users",          "ISE Users",             "ph ph-users",            "success",   "/api/cache/refresh/ise"),
        _get_card_info("ise_sgts",           "ISE SGTs",              "ph ph-tag",              "success",   "/api/cache/refresh/ise"),
        _get_card_info("ise_policy_sets",    "ISE Policy Sets",       "ph ph-scroll",           "success",   "/api/cache/refresh/ise"),
        _get_card_info("pan_managed_devices","Panorama Devices",      "ph ph-fire",             "danger",    "/api/cache/refresh/panorama"),
        _get_card_info("pan_rules",          "Firewall Rules",        "ph ph-fire",             "danger",    "/api/cache/refresh/panorama"),
        _get_card_info("pan_interfaces",     "Firewall Interfaces",   "ph ph-fire",             "danger",    "/api/firewall/interfaces/refresh"),
        _get_card_info("aci_nodes",          "ACI Fabric Nodes",      "ph ph-buildings",        "secondary", "/api/cache/refresh/aci"),
        _get_card_info("aci_bgp_peers",      "ACI BGP Peers",         "ph ph-plug-connect",     "secondary", "/api/cache/refresh/aci"),
        _get_card_info("aci_l3outs",         "ACI L3Outs",            "ph ph-globe-hemisphere-east", "secondary", "/api/cache/refresh/aci"),
        _get_card_info("nexus_inventory",    "Nexus Switch Inventory","ph ph-hard-drives",      "warning",   None,                             sse=True, sse_fn="triggerNexusCacheRefresh()"),
        _get_card_info("nexus_interfaces",   "Nexus Interface Cache", "ph ph-hard-drives",      "warning",   None,                             sse=True, sse_fn="triggerNexusCacheRefresh()"),
    ]

    return templates.TemplateResponse(request, "partials/cache_cards.html", {"cards": cards})


@router.get("/widget", response_class=HTMLResponse)
async def get_cache_widget(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates
    systems = [_get_system_status(s) for s in CACHE_SYSTEMS]
    return templates.TemplateResponse(request, "partials/cache_widget.html", {"systems": systems})


_KEY_TO_CATEGORY = {
    "devices": "devices",
    "sites": "sites",
    "device_site_map": "sites",
    "ipam_tree": "ipam",
    "ise_nads": "ise", "ise_nad_groups": "ise", "ise_endpoint_groups": "ise",
    "ise_identity_groups": "ise", "ise_users": "ise", "ise_sgts": "ise",
    "ise_sgacls": "ise", "ise_egress_matrix": "ise", "ise_policy_sets": "ise",
    "ise_authz_profiles": "ise", "ise_allowed_protocols": "ise",
    "ise_profiling_policies": "ise", "ise_deployment_nodes": "ise",
    "pan_device_groups": "panorama", "pan_managed_devices": "panorama",
    "pan_addr": "panorama", "pan_svc": "panorama", "pan_rules": "panorama",
    "pan_interfaces": "pan_interfaces",
    "aci_nodes": "aci", "aci_l3outs": "aci", "aci_bgp_peers": "aci",
    "aci_bgp_peer_cfg": "aci", "aci_ospf_peers": "aci", "aci_epgs": "aci",
    "aci_faults": "aci", "aci_subnets": "aci", "aci_health_overall": "aci",
    "nexus_inventory": "nexus", "nexus_interfaces": "nexus",
}


@router.post("/refresh/{category}")
async def refresh_specific_cache(category: str, session: SessionEntry = Depends(require_auth)):
    """Invalidate and re-fetch the specified cache category."""
    category = _KEY_TO_CATEGORY.get(category, category)

    if category == "devices":
        cache.invalidate("devices")
        cache.invalidate("device_site_map")
        cache.invalidate("ipam_tree")  # IPAM depends on device IP data
        asyncio.create_task(_refetch_dnac(session, include_devices=True, include_sites=False))
        msg = "DNAC Inventory is being refreshed in the background."

    elif category == "sites":
        cache.invalidate("sites")
        cache.invalidate("device_site_map")
        # IPAM does not depend on site hierarchy — do not invalidate ipam_tree here
        asyncio.create_task(_refetch_dnac(session, include_devices=False, include_sites=True))
        msg = "DNAC Sites is being refreshed in the background."

    elif category in ("nexus", "nexus_inventory", "nexus_interfaces"):
        cache.invalidate("nexus_inventory")
        cache.invalidate("nexus_interfaces")
        msg = "Nexus cache cleared. Use the Collect button to run SSH collection."

    elif category == "pan_interfaces":
        from logger_config import run_with_context
        import clients.panorama as pc
        import auth as auth_module
        from cache import TTL_PAN_INTERFACES
        cache.invalidate("pan_interfaces")
        async def _refetch_pan_interfaces():
            try:
                loop = asyncio.get_event_loop()
                pan_key = auth_module.get_panorama_key_for_session(session)
                await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_interfaces", lambda: pc.fetch_firewall_interfaces(pan_key), TTL_PAN_INTERFACES)
                logger.info("Cache refresh: Panorama interfaces re-fetch complete")
            except Exception as e:
                logger.warning(f"Panorama interfaces re-fetch failed: {e}")
        asyncio.create_task(_refetch_pan_interfaces())
        msg = "Firewall Interfaces are being refreshed in the background."

    elif category == "panorama":
        cache.invalidate_prefix("pan_")
        asyncio.create_task(_refetch_panorama(session))
        msg = "Panorama data is being refreshed in the background."

    elif category == "ise":
        cache.invalidate_prefix("ise_")
        asyncio.create_task(_refetch_ise(session))
        msg = "ISE data is being refreshed in the background."

    elif category == "aci":
        cache.invalidate_prefix("aci_")
        msg = "ACI cache cleared. Data will reload automatically when you visit ACI pages."

    elif category == "ipam":
        cache.invalidate("ipam_tree")
        msg = "IPAM cache cleared. Use the Collect button to rebuild the tree."

    else:
        msg = f"{category.replace('_', ' ').title()} cache cleared."

    return HTMLResponse(f"""
        <div class="alert alert-success alert-dismissible fade show mb-0" role="alert">
            <strong>Done.</strong> {msg}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    """)
