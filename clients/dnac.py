"""clients/dnac.py — Catalyst Center API client."""

import logging
import os

import urllib3
from dnacentersdk import api
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

_client = None

# Allow enough concurrent DNAC connections for bulk operations (config search,
# device-site map build, cache warm) without hitting urllib3's default pool of 10.
_POOL_SIZE = 50


def _make_client(username: str, password: str) -> api.DNACenterAPI:
    client = api.DNACenterAPI(
        base_url=os.getenv("DNA_CENTER_BASE_URL"),
        username=username,
        password=password,
        version=os.getenv("DNA_CENTER_VERSION", "2.3.7.6"),
        verify=False,
    )
    adapter = HTTPAdapter(pool_connections=_POOL_SIZE, pool_maxsize=_POOL_SIZE)
    session = client.custom_caller._session._req_session
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return client


def get_client() -> api.DNACenterAPI:
    """Return the shared service-account client (used for cache warming)."""
    global _client
    if _client is None:
        _client = _make_client(
            os.getenv("DOMAIN_USERNAME", ""),
            os.getenv("DOMAIN_PASSWORD", ""),
        )
    return _client


def create_user_client(username: str, password: str) -> api.DNACenterAPI:
    """Create a per-user DNAC client (not cached globally)."""
    return _make_client(username, password)


def _dictify(obj) -> dict:
    """Convert SDK response objects to plain dicts."""
    if isinstance(obj, dict):
        return obj
    try:
        return dict(obj)
    except Exception:
        return {}


def get_all_devices(dnac) -> list[dict]:
    devices, limit, offset = [], 500, 1
    while True:
        try:
            page  = dnac.devices.get_device_list(limit=limit, offset=offset)
            items = page.response if hasattr(page, "response") else page
            if not items:
                break
            devices.extend([_dictify(d) for d in items])
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            logger.error(f"Device fetch failed at offset {offset}: {e}")
            break
    return devices


def get_all_interfaces(dnac) -> list[dict]:
    interfaces, limit, offset = [], 500, 1
    while True:
        try:
            page  = dnac.devices.get_all_interfaces(offset=offset, limit=limit)
            batch = page.response if hasattr(page, "response") else page
            if not batch:
                break
            interfaces.extend([_dictify(i) for i in batch])
            if len(batch) < limit:
                break
            offset += limit
        except Exception as e:
            logger.error(f"Interface fetch failed: {e}")
            break
    return interfaces


def get_site_cache(dnac) -> list[dict]:
    cache, limit, offset = [], 500, 1
    while True:
        try:
            batch = dnac.sites.get_site(offset=offset, limit=limit)
            items = batch.response if hasattr(batch, "response") else batch
            if not items:
                break
            for site in items:
                s = _dictify(site)
                s_id   = s.get("id")
                s_name = s.get("siteNameHierarchy") or s.get("groupNameHierarchy") or ""
                if s_id and s_name:
                    cache.append({"id": s_id, "name": s_name})
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            logger.error(f"Site fetch failed: {e}")
            break
    cache.sort(key=lambda x: x["name"].count("/"), reverse=True)
    return cache


def get_managed_ips(dnac) -> set:
    return {d.get("managementIpAddress") for d in get_all_devices(dnac) if d.get("managementIpAddress")}


def find_best_site_match(site_cache: list, term: str) -> tuple[str | None, str | None]:
    for site in site_cache:
        if term.lower() in site["name"].lower():
            return site["id"], site["name"]
    return None, None


def get_device_config(dnac, device_id: str) -> str:
    try:
        resp = dnac.custom_caller.call_api(
            "GET", f"/dna/intent/api/v1/network-device/{device_id}/config"
        )
        return getattr(resp, "response", "") or ""
    except Exception as e:
        logger.warning(f"Config fetch failed for {device_id}: {e}")
        return ""


def build_device_site_map(dnac, site_cache: list[dict]) -> dict:
    """Return {device_id: site_name} for all site-assigned devices.

    Tier 1: uses the bulk assignedToSite endpoint via the Global site ID —
    ~6 paginated calls for 3000 devices instead of 500+ sequential per-site calls.
    Tier 2: falls back to parallel per-site fetches if Tier 1 returns nothing.
    """
    global_site = next((s for s in site_cache if s.get("name") == "Global"), None)
    if global_site:
        result = _build_via_bulk(dnac, global_site["id"])
        if result:
            logger.info(f"Site map: {len(result)} devices mapped via bulk API")
            return result

    logger.info("Bulk site map empty or failed — falling back to parallel per-site fetch")
    result = _build_via_per_site_parallel(dnac, site_cache)
    logger.info(f"Site map: {len(result)} devices mapped via parallel per-site fetch")
    return result


def _build_via_bulk(dnac, site_id: str) -> dict:
    """Fetch all device→site mappings in paginated bulk calls via the Global site ID.
    Returns empty dict on error or if the endpoint rejects the site_id."""
    result = {}
    offset = 1
    while True:
        try:
            resp  = dnac.site_design.get_site_assigned_network_devices(
                site_id=site_id, offset=offset, limit=500
            )
            items = getattr(resp, "response", None) or []
            if not items:
                break
            for rec in items:
                r    = _dictify(rec)
                uid  = r.get("deviceId")
                name = r.get("siteNameHierarchy")
                if uid and name and uid not in result:
                    result[uid] = name
            if len(items) < 500:
                break
            offset += 500
        except Exception as e:
            logger.warning(f"Bulk site-device fetch failed (will try per-site): {e}")
            return {}
    return result


def _build_via_per_site_parallel(dnac, site_cache: list[dict]) -> dict:
    """Parallel per-site fallback. Runs all site fetches concurrently and paginates
    each site so no devices are missed on larger sites."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    sites_to_fetch = [s for s in site_cache if s.get("id") and s.get("name") != "Global"]

    def fetch_site(site):
        uids, offset = [], 1
        while True:
            try:
                resp  = dnac.sites.get_devices_that_are_assigned_to_a_site(
                    id=site["id"], member_type="networkdevice",
                    offset=offset, limit=500
                )
                items = getattr(resp, "response", None) or []
                uids.extend(_dictify(dev).get("instanceUuid") for dev in items)
                if len(items) < 500:
                    break
                offset += 500
            except Exception as e:
                logger.warning(f"Site member fetch failed for {site['name']}: {e}")
                break
        return site["name"], uids

    ordered = [None] * len(sites_to_fetch)
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(fetch_site, s): i for i, s in enumerate(sites_to_fetch)}
        for fut in as_completed(futures):
            ordered[futures[fut]] = fut.result()

    # site_cache is sorted most-specific-first; first assignment wins
    result = {}
    for site_name, uids in ordered:
        for uid in uids:
            if uid and uid not in result:
                result[uid] = site_name
    return result


def get_or_create_tag(dnac, tag_name: str) -> str:
    """Return the ID of a tag with the given name, creating it if it doesn't exist."""
    def _lookup() -> str | None:
        resp  = dnac.tag.get_tag(name=tag_name)
        items = getattr(resp, "response", None) or []
        for t in items:
            d = _dictify(t)
            if d.get("name") == tag_name:
                return d["id"]
        return None

    existing = _lookup()
    if existing:
        return existing

    dnac.tag.create_tag(name=tag_name)

    # Wait for DNAC to commit the tag, then look it up by name
    import time as _time
    for _ in range(10):
        _time.sleep(0.5)
        tag_id = _lookup()
        if tag_id:
            return tag_id

    raise RuntimeError(f"Tag '{tag_name}' was created but could not be found afterwards")


def tag_network_devices(dnac, tag_id: str, device_ids: list[str]) -> None:
    """Associate tag_id with each device UUID using the bulk memberships endpoint."""
    payload = [{"id": dev_id, "tags": [{"id": tag_id}]} for dev_id in device_ids]
    dnac.tag.update_tags_associated_with_the_network_devices(payload=payload)


def get_interface_by_ip(dnac, ip: str) -> list[dict]:
    try:
        result = dnac.custom_caller.call_api(
            "GET", f"/dna/intent/api/v1/interface/ip-address/{ip}"
        )
        resp = getattr(result, "response", None)
        if isinstance(resp, dict):
            return [resp]
        if isinstance(resp, list):
            return [_dictify(r) for r in resp]
    except Exception as e:
        if "404" in str(e):
            return []   # IP not found — normal, not an error
        logger.warning(f"IP lookup failed for {ip}: {e}")
    return []


def get_global_credentials(dnac, sub_type: str) -> list:
    try:
        resp = dnac.discovery.get_global_credentials(credential_sub_type=sub_type)
        return list(resp.response) if hasattr(resp, "response") else []
    except Exception as e:
        logger.warning(f"Credential fetch failed: {e}")
        return []
