"""
cache.py — In-memory TTL cache with disk persistence + system connectivity checks.

Replaces Streamlit's @st.cache_data. Thread-safe, async-compatible.
Data is stored as plain dicts/lists — no SDK objects escape the client layer.

Keys matching DISK_KEYS or DISK_PREFIXES are written to data/cache/ as JSON and
survive server restarts. All other keys (status checks, per-device configs) are
memory-only.
"""

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TTL_DEVICES = 3600   # 1 hour
TTL_SITES   = 3600
TTL_STATUS  = 300    # 5 minutes

CACHE_DIR    = Path("data/cache")
DISK_KEYS    = {"devices", "sites"}
DISK_PREFIXES = ("pan_", "ise_")


def _should_persist(key: str) -> bool:
    return key in DISK_KEYS or any(key.startswith(p) for p in DISK_PREFIXES)


def _disk_path(key: str) -> Path:
    safe = re.sub(r"[^\w\-]", "_", key)
    return CACHE_DIR / f"{safe}.json"


class _Entry:
    __slots__ = ("data", "expires_at", "set_at", "ttl")

    def __init__(self, data: Any, ttl: int, set_at: float | None = None):
        self.data    = data
        self.set_at  = set_at if set_at is not None else time.time()
        self.ttl     = ttl
        remaining    = ttl if set_at is None else max(0.0, ttl - (time.time() - set_at))
        self.expires_at = time.monotonic() + remaining

    @property
    def valid(self) -> bool:
        return time.monotonic() < self.expires_at


class AppCache:
    def __init__(self):
        self._store: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry and entry.valid:
            return entry.data
        # Fall back to disk for persistent keys
        if _should_persist(key):
            path = _disk_path(key)
            if path.exists():
                try:
                    raw   = json.loads(path.read_text())
                    entry = _Entry(raw["data"], raw["ttl"], set_at=raw["set_at"])
                    if entry.valid:
                        self._store[key] = entry
                        return entry.data
                except Exception:
                    path.unlink(missing_ok=True)
        return None

    def set(self, key: str, data: Any, ttl: int):
        entry = _Entry(data, ttl)
        self._store[key] = entry
        if _should_persist(key):
            try:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                _disk_path(key).write_text(json.dumps(
                    {"key": key, "data": data, "set_at": entry.set_at, "ttl": ttl}
                ))
            except Exception as e:
                logger.warning(f"Disk cache write failed for {key}: {e}")

    def invalidate(self, key: str):
        self._store.pop(key, None)
        _disk_path(key).unlink(missing_ok=True)

    def invalidate_prefix(self, prefix: str):
        """Invalidate all in-memory and on-disk keys with the given prefix."""
        keys = [k for k in list(self._store) if k.startswith(prefix)]
        for k in keys:
            self.invalidate(k)
        if CACHE_DIR.exists():
            safe = re.sub(r"[^\w\-]", "_", prefix)
            for f in CACHE_DIR.glob(f"{safe}*.json"):
                f.unlink(missing_ok=True)

    def keys_for_prefix(self, prefix: str) -> list[str]:
        """Return all cached keys (memory + disk) that start with prefix."""
        keys: set[str] = {k for k in self._store if k.startswith(prefix)}
        if CACHE_DIR.exists():
            safe = re.sub(r"[^\w\-]", "_", prefix)
            for f in CACHE_DIR.glob(f"{safe}*.json"):
                try:
                    raw = json.loads(f.read_text())
                    if "key" in raw:
                        keys.add(raw["key"])
                except Exception:
                    pass
        return list(keys)

    def clear(self):
        self._store.clear()

    def cache_info(self, key: str) -> dict | None:
        """Return {set_at, ttl} for a key, checking disk if not in memory."""
        entry = self._store.get(key)
        if entry and entry.valid:
            return {"set_at": entry.set_at, "ttl": entry.ttl}
        if _should_persist(key):
            path = _disk_path(key)
            if path.exists():
                try:
                    raw = json.loads(path.read_text())
                    if time.time() - raw["set_at"] < raw["ttl"]:
                        return {"set_at": raw["set_at"], "ttl": raw["ttl"]}
                except Exception:
                    pass
        return None

    async def warm(self):
        """Pre-fetch devices and sites on startup (skipped if disk cache is valid)."""
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
