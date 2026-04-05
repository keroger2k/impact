"""
cache.py — In-memory TTL cache + system connectivity checks.

Replaces Streamlit's @st.cache_data. Thread-safe, async-compatible.
Data is stored as plain dicts/lists — no SDK objects escape the client layer.
"""

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

TTL_DEVICES = 3600   # 1 hour
TTL_SITES   = 3600
TTL_STATUS  = 300    # 5 minutes


class _Entry:
    __slots__ = ("data", "expires_at")
    def __init__(self, data: Any, ttl: int):
        self.data       = data
        self.expires_at = time.monotonic() + ttl

    @property
    def valid(self) -> bool:
        return time.monotonic() < self.expires_at


class AppCache:
    def __init__(self):
        self._store: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        return entry.data if entry and entry.valid else None

    def set(self, key: str, data: Any, ttl: int):
        self._store[key] = _Entry(data, ttl)

    def invalidate(self, key: str):
        self._store.pop(key, None)

    def clear(self):
        self._store.clear()

    async def warm(self):
        """Pre-fetch devices and sites on startup."""
        async with self._lock:
            if self.get("devices") is None:
                await asyncio.get_event_loop().run_in_executor(None, self._load_devices)
            if self.get("sites") is None:
                await asyncio.get_event_loop().run_in_executor(None, self._load_sites)

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
        cached = self.get("status_dnac")
        if cached:
            return cached
        try:
            import clients.dnac as dc
            dnac   = dc.get_client()
            result = dnac.custom_caller.call_api("GET", "/dna/intent/api/v1/network-device/count")
            count  = getattr(result, "response", 0)
            r = {"ok": True, "detail": f"{count:,} devices"}
        except Exception as e:
            r = {"ok": False, "detail": str(e)[:80]}
        self.set("status_dnac", r, TTL_STATUS)
        return r

    def _check_ise(self) -> dict:
        cached = self.get("status_ise")
        if cached:
            return cached
        try:
            import clients.ise as ic
            ise = ic.get_client()
            ok  = ic.connectivity_check(ise)
            r   = {"ok": ok, "detail": "Connected" if ok else "Unreachable"}
        except Exception as e:
            r = {"ok": False, "detail": str(e)[:80]}
        self.set("status_ise", r, TTL_STATUS)
        return r

    def _check_panorama(self) -> dict:
        cached = self.get("status_panorama")
        if cached:
            return cached
        try:
            import clients.panorama as pc
            ok, detail = pc.connectivity_check()
            r = {"ok": ok, "detail": detail}
        except Exception as e:
            r = {"ok": False, "detail": str(e)[:80]}
        self.set("status_panorama", r, TTL_STATUS)
        return r


# Singleton used by routers
cache = AppCache()
