"""
cache.py — Persistent caching using diskcache.

Replaces manual JSON file storage and in-memory dicts with a robust,
thread-safe, and process-safe SQLite-backed disk cache.
"""

import asyncio
import functools
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Optional

import diskcache

logger = logging.getLogger(__name__)

# TTL Constants (in seconds). Each is overridable via env (IMPACT_TTL_*).
# Defaults are tuned for a slow-changing network: config/topology data lives for
# hours-to-a-day; only genuine telemetry (status probes, route tables) stays short.
TTL_DEFAULT             = int(os.getenv("IMPACT_TTL_DEFAULT",          "172800"))  # 48 hours
TTL_DEVICES             = int(os.getenv("IMPACT_TTL_DEVICES",           "86400"))  # 24 hours
TTL_SITES               = int(os.getenv("IMPACT_TTL_SITES",             "86400"))  # 24 hours
TTL_ISE_POLICIES        = int(os.getenv("IMPACT_TTL_ISE_POLICIES",      "43200"))  # 12 hours
TTL_ACI_STATUS          = int(os.getenv("IMPACT_TTL_ACI_STATUS",         "7200"))  # 2 hours
TTL_ACI_ROUTE_TABLE     = int(os.getenv("IMPACT_TTL_ACI_ROUTE_TABLE",    "1800"))  # 30 minutes
TTL_STATUS              = int(os.getenv("IMPACT_TTL_STATUS",              "300"))  # 5 minutes
TTL_PAN_INTERFACES      = int(os.getenv("IMPACT_TTL_PAN_INTERFACES",   "172800"))  # 48 hours
TTL_PAN_POLICY          = int(os.getenv("IMPACT_TTL_PAN_POLICY",        "43200"))  # 12 hours
TTL_DNAC_INTERFACES     = int(os.getenv("IMPACT_TTL_DNAC_INTERFACES",   "86400"))  # 24 hours
TTL_CONFIG_SEARCH_RESULT = int(os.getenv("IMPACT_TTL_CONFIG_SEARCH_RESULT", "300"))  # 5 minutes
TTL_DNAC_ROUTER_CONFIGS = int(os.getenv("IMPACT_TTL_DNAC_ROUTER_CONFIGS", "86400"))  # 24 hours
TTL_DNAC_IP_POOLS       = int(os.getenv("IMPACT_TTL_DNAC_IP_POOLS",       "86400"))  # 24 hours
TTL_TUNNEL_INVENTORY    = int(os.getenv("IMPACT_TTL_TUNNEL_INVENTORY",    "86400"))  # 24 hours
TTL_F5                  = int(os.getenv("IMPACT_TTL_F5",                  "86400"))  # 24 hours

IPAM_TREE_CACHE_KEY = "ipam_tree_v4" # Bumped — RFC1918 supernet aggregation + IP-first sort (was v3)
TUNNEL_INVENTORY_CACHE_KEY = "tunnel_inventory_v1"

CACHE_DIR = Path(__file__).parent / "data" / "cache" / "diskcache"

class AppCache:
    def __init__(self, directory: Path = CACHE_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        self._cache = diskcache.Cache(str(directory))
        # Track the most-recent loader failure per key so the UI can surface
        # silent fetch errors without the user having to grep server logs.
        self._last_errors: dict = {}
        # Stale-while-revalidate: when a logically-expired key is read we serve
        # the stale value instantly and refresh it on this pool, so callers never
        # block on an upstream fetch just because a TTL rolled over.
        self._refresh_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cache-swr")
        self._refreshing: set[str] = set()
        self._refresh_lock = threading.Lock()

    def get(self, key: str) -> Any:
        """Standard get from cache. Returns only if not logically expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None

        data, expires_at, _ = entry
        if time.time() < expires_at:
            return data
        return None

    def get_stale(self, key: str) -> Any:
        """Return the cached value regardless of logical expiry.

        Physically-present data lives for 30 days (see set()); read-only display
        paths prefer slightly-stale data over showing a blank/empty state when a
        logical TTL has rolled over but no refresh has run yet.
        """
        entry = self._cache.get(key)
        return entry[0] if entry is not None else None

    def set(self, key: str, value: Any, ttl: Optional[int] = TTL_DEFAULT):
        """Standard set to cache with logical TTL and longer physical TTL for stale support."""
        now = time.time()
        expires_at = now + (ttl if ttl is not None else TTL_DEFAULT)
        # Store (data, logical_expiry, set_at)
        # Physical expiry is 30 days to support stale-while-revalidate
        self._cache.set(key, (value, expires_at, now), expire=2592000)

    def _background_refresh(self, key: str, loader: Callable, ttl: int):
        """Refresh a key on the SWR pool, deduped so concurrent readers of the
        same expired key trigger at most one upstream fetch (no stampede)."""
        with self._refresh_lock:
            if key in self._refreshing:
                return
            self._refreshing.add(key)

        def _run():
            try:
                data = loader()
                if data is not None:
                    self.set(key, data, ttl)
                    self._last_errors.pop(key, None)
            except Exception as e:
                logger.error(f"Background cache refresh failed for '{key}': {e}")
                self._last_errors[key] = {"at": time.time(), "message": str(e)[:500]}
            finally:
                with self._refresh_lock:
                    self._refreshing.discard(key)

        self._refresh_pool.submit(_run)

    def get_or_set(self, key: str, loader: Callable, ttl: int = TTL_DEFAULT,
                   background: bool = True) -> Any:
        """
        Get a value from cache or fetch it using the loader if missing or expired.

        Stale-while-revalidate: when an entry is logically expired but still
        physically present, the stale value is returned immediately and (when
        ``background=True``, the default) a refresh is dispatched on a background
        thread — so requests never block just because a TTL rolled over. If the
        loader later fails, the stale value simply stays until the next attempt.

        Pass ``background=False`` for keys where serving stale is misleading
        (e.g. connectivity probes, cached search results); those revalidate
        synchronously as before.
        """
        entry = self._cache.get(key)
        now = time.time()

        if entry is not None:
            data, expires_at, _ = entry
            if now < expires_at:
                return data

            # Logically expired but physically present.
            if background:
                # Serve stale instantly; refresh out of band.
                self._background_refresh(key, loader, ttl)
                return data

            # Synchronous revalidation (opt-out path).
            try:
                new_data = loader()
                if new_data is not None:
                    self.set(key, new_data, ttl)
                    self._last_errors.pop(key, None)
                    return new_data
            except Exception as e:
                logger.error(f"Cache revalidation failed for key '{key}', returning stale data: {e}")
                self._last_errors[key] = {"at": time.time(), "message": str(e)[:500]}
                return data # Return stale data

        # Cache miss (truly missing) — must fetch synchronously, there is nothing
        # to serve in the meantime.
        try:
            new_data = loader()
            if new_data is not None:
                self.set(key, new_data, ttl)
                self._last_errors.pop(key, None)
                return new_data
        except Exception as e:
            logger.error(f"Cache loader failed for new key '{key}': {e}")
            self._last_errors[key] = {"at": time.time(), "message": str(e)[:500]}

        return None

    def last_error(self, key: str) -> Optional[dict]:
        """Return the most recent loader failure for a key (or None if last load succeeded)."""
        return self._last_errors.get(key)

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

    # Connectivity checks live in utils/system_status.py (the single source of
    # truth, using the status_*_live keys). The older duplicate stack that lived
    # here was dead code and has been removed.


# Singleton used by routers
cache = AppCache()
