"""
datasets.py — single source of truth for every cached dataset.

Each entry describes one logical dataset: which cache keys belong to it, how it
refreshes, and how the cache UI should render it. The sidebar cache widget, the
Cache Management cards, and POST /api/cache/refresh/{id} all derive from this
registry — add a dataset here and every surface picks it up.

Three refresh kinds, matching the three TTL tiers in cache.py:

  api      Invalidate + re-fetch server-side in the background. These keys also
           self-refresh via stale-while-revalidate on normal page visits, so
           the manual button is only for "I want it fresh right now".
  lazy     Invalidate only; the data rebuilds through get_or_set the next time
           its pages are visited (ACI, tunnel inventory).
  collect  User-driven SSE collection (SSH / iControl REST fan-out). Data never
           expires logically (TTL_MANUAL) — it is valid until the user runs the
           next Collect. The UI button starts the collection stream.
"""

import asyncio
import logging

from cache import cache, IPAM_TREE_CACHE_KEY, TUNNEL_INVENTORY_CACHE_KEY, TTL_STANDARD

logger = logging.getLogger(__name__)

# ── Canonical key lists (importable; do not duplicate these elsewhere) ────────

DNAC_KEYS = ["devices", "sites", "device_site_map", "dnac_interfaces"]

ISE_KEYS = [
    "ise_nads", "ise_nad_groups", "ise_endpoint_groups", "ise_identity_groups",
    "ise_users", "ise_sgts", "ise_sgacls", "ise_egress_matrix",
    "ise_policy_sets", "ise_authz_profiles", "ise_allowed_protocols",
    "ise_profiling_policies", "ise_deployment_nodes",
]

PANORAMA_KEYS = [
    "pan_device_groups", "pan_managed_devices", "pan_rules",
    "pan_addr", "pan_svc", "pan_interfaces",
]

NEXUS_CACHE_KEYS = [
    "nexus_inventory", "nexus_interfaces",
    "nexus_port_channels", "nexus_vpcs", "nexus_vlans",
]

F5_CACHE_KEYS = [
    "f5_inventory", "f5_self_ips", "f5_vlans", "f5_interfaces",
    "f5_virtuals", "f5_pools", "f5_nodes", "f5_routes",
]

TUNNEL_KEYS = [
    TUNNEL_INVENTORY_CACHE_KEY, "pan_ike_gateways", "pan_ipsec_tunnels",
    "pan_ike_crypto_profiles", "pan_ipsec_crypto_profiles",
]

# ── Registry ──────────────────────────────────────────────────────────────────

DATASETS = [
    {
        "id": "dnac",
        "label": "DNAC",
        "title": "DNAC Inventory & Interfaces",
        "icon": "ph ph-network",
        "color": "primary",
        "kind": "api",
        "keys": DNAC_KEYS,
        "count_key": "devices",
    },
    {
        "id": "ise",
        "label": "ISE",
        "title": "ISE Policies & Identities",
        "icon": "ph ph-shield-check",
        "color": "success",
        "kind": "api",
        "keys": ISE_KEYS,
        # Per-policy-set auth rules (ise_auth_rules_{id}) are dynamic, so
        # invalidation goes by prefix rather than the fixed key list.
        "invalidate_prefix": "ise_",
        "count_key": "ise_nads",
    },
    {
        "id": "panorama",
        "label": "Panorama",
        "title": "Panorama Policies & Interfaces",
        "icon": "ph ph-fire",
        "color": "danger",
        "kind": "api",
        "keys": PANORAMA_KEYS,
        "count_key": "pan_managed_devices",
    },
    {
        "id": "aci",
        "label": "ACI",
        "title": "ACI Fabrics",
        "icon": "ph ph-buildings",
        "color": "secondary",
        "kind": "lazy",
        # Real keys are aci_{fabric_id}_{suffix}; expanded via dataset_keys().
        "key_suffixes": ["nodes", "l3outs", "bgp_peers", "epgs", "faults"],
        "invalidate_prefix": "aci_",
        "count_suffix": "nodes",
        "message": "ACI caches cleared — data reloads automatically as ACI pages are visited.",
    },
    {
        "id": "tunnels",
        "label": "Tunnels",
        "title": "VPN Tunnel Inventory",
        "icon": "ph ph-lock-key",
        "color": "info",
        "kind": "lazy",
        "keys": TUNNEL_KEYS,
        "count_key": TUNNEL_INVENTORY_CACHE_KEY,
        "message": "Tunnel inventory cleared — visit the VPN Tunnels page to rebuild it.",
    },
    {
        "id": "ipam",
        "label": "IPAM",
        "title": "IPAM Tree",
        "icon": "ph ph-tree-structure",
        "color": "info",
        "kind": "collect",
        "keys": [IPAM_TREE_CACHE_KEY],
        "count_key": IPAM_TREE_CACHE_KEY,
        "sse_fn": "triggerIpamCacheRefresh()",
    },
    {
        "id": "nexus",
        "label": "Nexus",
        "title": "Nexus Switches (SSH)",
        "icon": "ph ph-hard-drives",
        "color": "warning",
        "kind": "collect",
        "keys": NEXUS_CACHE_KEYS,
        "count_key": "nexus_inventory",
        "sse_fn": "triggerNexusCacheRefresh()",
    },
    {
        "id": "f5",
        "label": "F5",
        "title": "F5 BIG-IP (read-only)",
        "icon": "ph ph-scales",
        "color": "primary",
        "kind": "collect",
        "keys": F5_CACHE_KEYS,
        "count_key": "f5_inventory",
        "sse_fn": "triggerF5CacheRefresh()",
    },
]


def get_dataset(dataset_id: str) -> dict | None:
    return next((d for d in DATASETS if d["id"] == dataset_id), None)


def dataset_keys(ds: dict) -> list[str]:
    """Concrete cache keys for a dataset (expands per-fabric ACI suffixes)."""
    if "key_suffixes" in ds:
        import clients.aci_registry as reg
        return [f"aci_{f.id}_{suf}" for f in reg.list_fabrics() for suf in ds["key_suffixes"]]
    return ds["keys"]


def dataset_count_key(ds: dict) -> str:
    """The key whose row count / set-time represents the dataset in the UI."""
    if "count_suffix" in ds:
        import clients.aci_registry as reg
        fabrics = reg.list_fabrics()
        return f"aci_{fabrics[0].id}_{ds['count_suffix']}" if fabrics else ""
    return ds["count_key"]


# ── Background re-fetchers (api-kind datasets) ───────────────────────────────

async def _refresh_dnac(session):
    from logger_config import run_with_context
    import clients.dnac as dc
    import auth as auth_module
    loop = asyncio.get_event_loop()
    try:
        dnac = auth_module.get_dnac_for_session(session)

        logger.info("Cache refresh: re-fetching DNAC devices")
        devices = await loop.run_in_executor(None, run_with_context(dc.get_all_devices, dnac))
        if devices is not None:
            cache.set("devices", devices, TTL_STANDARD)
            logger.info(f"Cache refresh: stored {len(devices)} devices")

        logger.info("Cache refresh: re-fetching DNAC sites")
        sites = await loop.run_in_executor(None, run_with_context(dc.get_site_cache, dnac))
        if sites is not None:
            cache.set("sites", sites, TTL_STANDARD)
            logger.info(f"Cache refresh: stored {len(sites)} sites")

        if devices is not None and sites is not None:
            logger.info("Cache refresh: rebuilding device-to-site map")
            dev_site_map = await loop.run_in_executor(
                None, run_with_context(dc.build_device_site_map, dnac, sites)
            )
            if dev_site_map is not None:
                cache.set("device_site_map", dev_site_map, TTL_STANDARD)
                logger.info(f"Cache refresh: stored {len(dev_site_map)} device-site mappings")

        logger.info("Cache refresh: re-fetching DNAC interfaces")
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set),
            "dnac_interfaces", lambda: dc.get_all_interfaces(dnac), TTL_STANDARD
        )
        logger.info("Cache refresh: DNAC re-fetch complete")
    except Exception as e:
        logger.warning(f"DNAC re-fetch failed: {e}")


async def _refresh_ise(session):
    from logger_config import run_with_context
    import clients.ise as ic
    import auth as auth_module
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
                    cache.set(key, data, TTL_STANDARD)
            except Exception as e:
                logger.warning(f"ISE re-fetch failed for {key}: {e}")
        logger.info("Cache refresh: ISE re-fetch complete")
    except Exception as e:
        logger.warning(f"ISE re-fetch failed: {e}")


async def _refresh_panorama(session):
    from logger_config import run_with_context
    import clients.panorama as pc
    import auth as auth_module
    from routers.firewall import _pan_loader
    loop = asyncio.get_event_loop()
    try:
        auth_module.get_panorama_key_for_session(session)  # fail fast; loaders auto-refresh the key
        all_dgs = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_device_groups",
            _pan_loader(session, pc.get_device_groups), TTL_STANDARD
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_managed_devices",
            _pan_loader(session, pc.get_managed_devices), TTL_STANDARD
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_addr",
            _pan_loader(session, lambda key: pc.get_address_objects_and_groups(key, all_dgs)), TTL_STANDARD
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_svc",
            _pan_loader(session, lambda key: pc.get_services(key, all_dgs)), TTL_STANDARD
        )

        def _build_rules(key):
            all_rules = pc.get_all_security_rules(key, all_dgs)
            by_dg: dict[str, list] = {}
            for rule in all_rules:
                dg = rule.get("device_group", "shared")
                by_dg.setdefault(dg, []).append(rule)
            return {"dg_order": all_dgs, "by_dg": by_dg}

        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_rules",
            _pan_loader(session, _build_rules), TTL_STANDARD
        )
        await loop.run_in_executor(
            None, run_with_context(cache.get_or_set), "pan_interfaces",
            _pan_loader(session, pc.fetch_firewall_interfaces), TTL_STANDARD
        )
        logger.info("Cache refresh: Panorama re-fetch complete")
    except Exception as e:
        logger.warning(f"Panorama re-fetch failed: {e}")


_REFRESH_FNS = {
    "dnac": _refresh_dnac,
    "ise": _refresh_ise,
    "panorama": _refresh_panorama,
}


# ── Dispatcher ────────────────────────────────────────────────────────────────

async def refresh_dataset(dataset_id: str, session, fabric: str | None = None) -> str | None:
    """Refresh one dataset. Returns a user-facing message, or None if unknown."""
    ds = get_dataset(dataset_id)
    if ds is None:
        return None

    if ds["kind"] == "collect":
        # Collection-backed data stays valid until replaced — never blank it
        # out from here; the Collect stream overwrites it atomically.
        return f"{ds['label']} is collection-backed — use its Collect button to gather fresh data."

    if ds["id"] == "aci" and fabric:
        cache.invalidate_prefix(f"aci_{fabric}_")
        return f"ACI cache for {fabric} cleared — data reloads as ACI pages are visited."

    if "invalidate_prefix" in ds:
        cache.invalidate_prefix(ds["invalidate_prefix"])
    else:
        for k in dataset_keys(ds):
            cache.invalidate(k)

    if ds["kind"] == "lazy":
        return ds["message"]

    asyncio.create_task(_REFRESH_FNS[ds["id"]](session))
    return f"{ds['label']} data is being refreshed in the background."
