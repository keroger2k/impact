"""
cache.py — Persistent caching using diskcache.

Replaces manual JSON file storage and in-memory dicts with a robust,
thread-safe, and process-safe SQLite-backed disk cache.
"""

import asyncio
import functools
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Optional

import diskcache

logger = logging.getLogger(__name__)

# TTL Constants (in seconds). Each is overridable via env (IMPACT_TTL_*).
TTL_DEFAULT             = int(os.getenv("IMPACT_TTL_DEFAULT",          "172800"))  # 48 hours
TTL_DEVICES             = int(os.getenv("IMPACT_TTL_DEVICES",           "14400"))  # 4 hours
TTL_SITES               = int(os.getenv("IMPACT_TTL_SITES",             "14400"))  # 4 hours
TTL_ISE_POLICIES        = int(os.getenv("IMPACT_TTL_ISE_POLICIES",       "3600"))  # 1 hour
TTL_ACI_STATUS          = int(os.getenv("IMPACT_TTL_ACI_STATUS",          "900"))  # 15 minutes
TTL_ACI_ROUTE_TABLE     = int(os.getenv("IMPACT_TTL_ACI_ROUTE_TABLE",     "300"))  # 5 minutes
TTL_STATUS              = int(os.getenv("IMPACT_TTL_STATUS",              "300"))  # 5 minutes
TTL_PAN_INTERFACES      = int(os.getenv("IMPACT_TTL_PAN_INTERFACES",   "172800"))  # 48 hours
TTL_PAN_POLICY          = int(os.getenv("IMPACT_TTL_PAN_POLICY",         "3600"))  # 1 hour
TTL_DNAC_INTERFACES     = int(os.getenv("IMPACT_TTL_DNAC_INTERFACES",   "14400"))  # 4 hours
TTL_CONFIG_SEARCH_RESULT = int(os.getenv("IMPACT_TTL_CONFIG_SEARCH_RESULT", "300"))  # 5 minutes

IPAM_TREE_CACHE_KEY = "ipam_tree_v3" # Bumped — DNAC now contributes full interfaces (was v2)

CACHE_DIR = Path(__file__).parent / "data" / "cache" / "diskcache"

class AppCache:
    def __init__(self, directory: Path = CACHE_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        self._cache = diskcache.Cache(str(directory))

    def get(self, key: str) -> Any:
        """Standard get from cache. Returns only if not logically expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None

        data, expires_at, _ = entry
        if time.time() < expires_at:
            return data
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = TTL_DEFAULT):
        """Standard set to cache with logical TTL and longer physical TTL for stale support."""
        now = time.time()
        expires_at = now + (ttl if ttl is not None else TTL_DEFAULT)
        # Store (data, logical_expiry, set_at)
        # Physical expiry is 30 days to support stale-while-revalidate
        self._cache.set(key, (value, expires_at, now), expire=2592000)

    def get_or_set(self, key: str, loader: Callable, ttl: int = TTL_DEFAULT) -> Any:
        """
        Get a value from cache or fetch it using the loader if missing or expired.
        Implements stale-while-revalidate: if the loader fails, returns stale data if available.
        """
        entry = self._cache.get(key)
        now = time.time()

        if entry is not None:
            data, expires_at, _ = entry
            if now < expires_at:
                return data

            # Logically expired, try to revalidate
            try:
                new_data = loader()
                if new_data is not None:
                    self.set(key, new_data, ttl)
                    return new_data
            except Exception as e:
                logger.error(f"Cache revalidation failed for key '{key}', returning stale data: {e}")
                return data # Return stale data

        # Cache miss (truly missing)
        try:
            new_data = loader()
            if new_data is not None:
                self.set(key, new_data, ttl)
                return new_data
        except Exception as e:
            logger.error(f"Cache loader failed for new key '{key}': {e}")

        return None

    def cache_result(self, ttl: int = TTL_DEFAULT):
        """Decorator for caching function results."""
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Simple key generation based on function name and args
                key = f"decorator:{func.__module__}.{func.__name__}:{args}:{kwargs}"
                return self.get_or_set(key, lambda: func(*args, **kwargs), ttl)
            return wrapper
        return decorator

    def invalidate(self, key: str):
        self._cache.delete(key)

    def invalidate_prefix(self, prefix: str):
        """Invalidate all keys starting with the given prefix."""
        keys_to_delete = [k for k in self._cache.iterkeys() if isinstance(k, str) and k.startswith(prefix)]
        for k in keys_to_delete:
            self._cache.delete(k)

    def keys_for_prefix(self, prefix: str) -> list[str]:
        return [k for k in self._cache.iterkeys() if isinstance(k, str) and k.startswith(prefix)]

    def clear(self):
        self._cache.clear()

    def cleanup_old_aci_keys(self):
        """Purge legacy unprefixed ACI cache keys from disk."""
        legacy_keys = [
            "aci_nodes", "aci_l3outs", "aci_bgp_peers", "aci_bgp_peer_cfg",
            "aci_ospf_peers", "aci_epgs", "aci_faults", "aci_subnets",
            "aci_health_overall", "aci_health_tenants", "aci_health_pods",
            "aci_bgp_doms_all", "aci_bgp_adj_rib_out", "aci_bgp_adj_rib_in"
        ]
        count = 0
        for k in legacy_keys:
            if k in self._cache:
                self._cache.delete(k)
                count += 1
        if count > 0:
            logger.info(f"Cleanup: purged {count} legacy ACI cache keys")

    def cache_info(self, key: str) -> dict | None:
        """Return some metadata about a cached key."""
        entry = self._cache.get(key)
        if entry:
            data, expires_at, set_at = entry
            return {
                "set_at": set_at,
                "expires_at": expires_at,
                "ttl": expires_at - set_at,
                "is_expired": time.time() > expires_at
            }
        return None

    # ── Warming logic ──────────────────────────────────────────────────────────

    async def warm(self):
        """Pre-fetch devices, sites, and device-site map on startup."""
        from logger_config import set_correlation_id, run_with_context
        import uuid
        set_correlation_id(f"warm-startup-{uuid.uuid4().hex[:8]}")

        loop = asyncio.get_event_loop()
        if self.get("devices") is None:
            await loop.run_in_executor(None, run_with_context(self._load_devices))
        if self.get("sites") is None:
            await loop.run_in_executor(None, run_with_context(self._load_sites))
        if self.get("device_site_map") is None:
            await loop.run_in_executor(None, run_with_context(self._load_device_site_map))

        # Nexus warm-up
        if self.get("nexus_inventory") is None:
            from routers.nexus import init_nexus_collection
            await init_nexus_collection()

    def _load_devices(self):
        try:
            import clients.dnac as dc
            dnac    = dc.get_client()
            devices = dc.get_all_devices(dnac)
            self.set("devices", devices, TTL_DEVICES)
            logger.info(f"Cache warmed: {len(devices)} devices")
        except Exception as e:
            logger.warning(f"Device cache warm failed: {e}")

    def _load_sites(self):
        try:
            import clients.dnac as dc
            dnac  = dc.get_client()
            sites = dc.get_site_cache(dnac)
            self.set("sites", sites, TTL_SITES)
            logger.info(f"Cache warmed: {len(sites)} sites")
        except Exception as e:
            logger.warning(f"Site cache warm failed: {e}")

    def _load_device_site_map(self):
        try:
            import clients.dnac as dc
            dnac         = dc.get_client()
            sites        = self.get("sites") or []
            dev_site_map = dc.build_device_site_map(dnac, sites)
            self.set("device_site_map", dev_site_map, TTL_SITES)
            logger.info(f"Cache warmed: device_site_map ({len(dev_site_map)} entries)")
        except Exception as e:
            logger.warning(f"Device site map warm failed: {e}")

    # ── Connectivity checks ─────────────────────────────────────────────────────

    async def check_all_systems(self) -> dict:
        """Non-blocking connectivity check for all three systems."""
        loop = asyncio.get_event_loop()
        dnac_f  = loop.run_in_executor(None, self._check_dnac)
        ise_f   = loop.run_in_executor(None, self._check_ise)
        pano_f  = loop.run_in_executor(None, self._check_panorama)
        dnac_r, ise_r, pano_r = await asyncio.gather(dnac_f, ise_f, pano_f, return_exceptions=True)

        def _safe(r):
            return r if isinstance(r, dict) else {"ok": False, "detail": str(r)}

        return {
            "dnac":     _safe(dnac_r),
            "ise":      _safe(ise_r),
            "panorama": _safe(pano_r),
        }

    def _check_dnac(self) -> dict:
        return self.get_or_set("status_dnac", self.__check_dnac_internal, TTL_STATUS)

    def __check_dnac_internal(self) -> dict:
        try:
            import clients.dnac as dc
            dnac   = dc.get_client()
            result = dnac.custom_caller.call_api("GET", "/dna/intent/api/v1/network-device/count")
            count  = getattr(result, "response", 0)
            return {"ok": True, "detail": f"{count:,} devices"}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    def _check_ise(self) -> dict:
        return self.get_or_set("status_ise", self.__check_ise_internal, TTL_STATUS)

    def __check_ise_internal(self) -> dict:
        try:
            import clients.ise as ic
            ise = ic.get_client()
            ok  = ic.connectivity_check(ise)
            return {"ok": ok, "detail": "Connected" if ok else "Unreachable"}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    def _check_panorama(self) -> dict:
        return self.get_or_set("status_panorama", self.__check_panorama_internal, TTL_STATUS)

    def __check_panorama_internal(self) -> dict:
        try:
            import clients.panorama as pc
            ok, detail = pc.connectivity_check()
            return {"ok": ok, "detail": detail}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}


# Singleton used by routers
cache = AppCache()
