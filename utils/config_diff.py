"""Device resolution and config fetching shared by the Config Diff tool.

Combines DNAC's device inventory with the Nexus inventory into one
hostname-searchable list, and fetches a single device's running-config the
same way routers/dnac.py's GET /devices/{device_id}/config already does
(branching on the nexus_{hostname} id convention) so both code paths behave
identically in DEV_MODE and against real infrastructure.
"""
from typing import Dict, List, Optional

import clients.dnac as dc
from cache import cache


def _dnac_candidates() -> List[Dict]:
    devices = cache.get("devices") or []
    return [
        {
            "id": d.get("id"),
            "hostname": d.get("hostname") or "",
            "platform": d.get("platformId") or "",
            "family": "dnac",
        }
        for d in devices if d.get("id") and d.get("hostname")
    ]


def _nexus_candidates() -> List[Dict]:
    from routers.nexus import get_cached_nexus_inventory
    devices = get_cached_nexus_inventory()
    return [
        {
            "id": d.get("id") or f"nexus_{d.get('hostname')}",
            "hostname": d.get("hostname") or "",
            "platform": d.get("platform") or "nxos",
            "family": "nexus",
        }
        for d in devices if d.get("hostname")
    ]


def all_candidates() -> List[Dict]:
    return _dnac_candidates() + _nexus_candidates()


def search_candidates(q: str, limit: int = 20) -> List[Dict]:
    q = (q or "").strip().lower()
    if not q:
        return []
    matches = [c for c in all_candidates() if q in c["hostname"].lower()]
    matches.sort(key=lambda c: (not c["hostname"].lower().startswith(q), c["hostname"].lower()))
    return matches[:limit]


def resolve_hostname(hostname: str) -> List[Dict]:
    """Case-insensitive exact hostname matches across DNAC + Nexus."""
    target = (hostname or "").strip().lower()
    if not target:
        return []
    return [c for c in all_candidates() if c["hostname"].lower() == target]


def find_candidate_by_id(device_id: str) -> Optional[Dict]:
    for c in all_candidates():
        if c["id"] == device_id:
            return c
    return None


def fetch_config_by_id(device_id: str, dnac=None) -> str:
    """Running-config text for a device_id (DNAC UUID or nexus_{hostname}).

    Mirrors routers/dnac.py's /devices/{device_id}/config branch so this
    tool and that endpoint fetch identically. Blocking — callers on the
    event loop must run this in an executor.
    """
    if device_id.startswith("nexus_"):
        from dev import DEV_MODE
        if DEV_MODE:
            from dev import get_mock_config
            return get_mock_config(device_id) or ""
        hostname = device_id[len("nexus_"):]
        return cache.get(f"config:nexus:{hostname}") or ""

    return cache.get_or_set(f"config_{device_id}", lambda: dc.get_device_config(dnac, device_id), 600) or ""
