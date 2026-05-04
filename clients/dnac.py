"""clients/dnac.py — Catalyst Center API client."""

import logging
import os
import time
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
        verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true",
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
        start_time = time.time()
        try:
            page  = dnac.devices.get_device_list(limit=limit, offset=offset)
            duration = int((time.time() - start_time) * 1000)
            logger.info(f"DNAC GET Device List (offset={offset})", extra={
                "target": "DNAC",
                "action": "FETCH_DNAC_DEVICES",
                "status": 200,
                "duration_ms": duration
            })
            items = page.response if hasattr(page, "response") else page
            if not items:
                break
            devices.extend([_dictify(d) for d in items])
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            duration = int((time.time() - start_time) * 1000)
            logger.error(f"Device fetch failed at offset {offset}: {e}", extra={
                "target": "DNAC",
                "action": "FETCH_DNAC_DEVICES",
                "status": 500,
                "duration_ms": duration
            })
            # If first page failed, propagate so cache.get_or_set doesn't cache an empty list for 24h.
            if not devices:
                raise
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


def get_global_ip_pools(dnac) -> list[dict]:
    """Return every DNAC global IP pool (both IPv4 and IPv6).
    Pages through /dna/intent/api/v1/global-pool.
    """
    pools, limit, offset = [], 25, 1
    while True:
        try:
            page = dnac.network_settings.get_global_pool(offset=offset, limit=limit)
            items = page.response if hasattr(page, "response") else page
            if not items:
                break
            pools.extend([_dictify(p) for p in items])
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            logger.error(f"Global pool fetch failed at offset {offset}: {e}")
            if not pools:
                raise
            break
    return pools


def get_reserve_ip_subpools(dnac) -> list[dict]:
    """Return every DNAC site-reserved IP subpool (carved from global pools,
    attributed to a specific site). Each entry typically contains an inner
    `ipPools` list with one or two pools (IPv4 and/or IPv6).
    Pages through /dna/intent/api/v1/reserve-ip-subpool.
    """
    pools, limit, offset = [], 500, 1
    while True:
        try:
            # ignoreInheritedGroups=false returns all subpools across sites.
            page = dnac.network_settings.get_reserve_ip_subpool(
                offset=offset, limit=limit, ignore_inherited_groups="false"
            )
            items = page.response if hasattr(page, "response") else page
            if not items:
                break
            pools.extend([_dictify(p) for p in items])
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            logger.error(f"Reserve subpool fetch failed at offset {offset}: {e}")
            if not pools:
                raise
            break
    return pools


def find_best_site_match(site_cache: list, term: str) -> tuple[str | None, str | None]:
    for site in site_cache:
        if term.lower() in site["name"].lower():
            return site["id"], site["name"]
    return None, None


def get_device_config(dnac, device_id: str) -> str:
    from dev import DEV_MODE, get_mock_config
    if DEV_MODE: return get_mock_config(device_id)
    start_time = time.time()
    try:
        resp = dnac.custom_caller.call_api(
            "GET", f"/dna/intent/api/v1/network-device/{device_id}/config"
        )
        duration = int((time.time() - start_time) * 1000)
        logger.debug(f"DNAC GET Device Config: {device_id}", extra={
            "target": "DNAC",
            "action": "FETCH_DNAC_CONFIG",
            "status": 200,
            "duration_ms": duration
        })
        config = getattr(resp, "response", "") or ""
        logger.debug(f"DNAC Config Response: {config}", extra={"payload": config})
        return config
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        logger.warning(f"Config fetch failed for {device_id}: {e}", extra={
            "target": "DNAC",
            "action": "FETCH_DNAC_CONFIG",
            "status": 500,
            "duration_ms": duration
        })
        return ""


def build_device_site_map(dnac, site_cache: list[dict]) -> dict:
    """Return {device_id: site_name} for all site-assigned devices.

    Fetches all sites concurrently (with per-site pagination) rather than
    sequentially, reducing wall time from O(sites) to O(pages_per_slowest_site).
    site_cache is sorted most-specific-first so first assignment wins.
    """
    result = _build_via_per_site_parallel(dnac, site_cache)
    logger.info(f"Site map: {len(result)} devices mapped across {len(site_cache)} sites")
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
    from dev import DEV_MODE, MOCK_DEVICES
    if DEV_MODE:
        # Find if this IP belongs to a mock device
        match = next((d for d in MOCK_DEVICES if d.get("managementIpAddress") == ip), None)
        if match:
            return [{
                "deviceId": match["id"],
                "portName": "GigabitEthernet0/1",
                "ipv4Address": ip,
                "ipv4Mask": "255.255.255.0",
                "macAddress": "00:11:22:33:44:55",
                "vlanId": "10",
                "description": "Mock Management Interface",
                "adminStatus": "UP",
                "status": "up",
                "speed": "1000000"
            }]
        return []

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

def initiate_path_trace(dnac, source_ip, dest_ip, protocol="TCP", dest_port=80):
    payload = {
        "sourceIP": source_ip,
        "destIP": dest_ip,
        "protocol": protocol,
        "destPort": str(dest_port)
    }
    # SDK method name can vary, try initiate_a_new_pathtrace or initiate_new_path_trace
    try:
        return dnac.path_trace.initiate_a_new_pathtrace(payload=payload)
    except AttributeError:
        return dnac.path_trace.initiate_new_path_trace(payload=payload)

def get_path_trace_result(dnac, flow_id):
    """Retrieve path trace result using custom caller for reliability."""
    try:
        resp = dnac.custom_caller.call_api(
            "GET", f"/dna/intent/api/v1/flow-analysis/{flow_id}"
        )
        # custom_caller returns a response object with .response
        if hasattr(resp, "response"):
            return _dictify(resp.response)
        return _dictify(resp)
    except Exception as e:
        logger.error(f"Path trace fetch failed for {flow_id}: {e}")
        return {}

def get_device_detail(dnac, device_id):
    resp = dnac.devices.get_network_device_by_id(id=device_id)
    return _dictify(resp.response) if hasattr(resp, "response") else _dictify(resp)

def get_recent_issues(dnac) -> list:
    """Fetch and normalize recent global issues/alerts from DNAC."""
    from dev import DEV_MODE, MOCK_ISSUES
    from cache import cache

    raw_issues = []
    if DEV_MODE:
        raw_issues = MOCK_ISSUES
    else:
        try:
            import time
            end_time = int(time.time() * 1000)
            start_time = end_time - (24 * 60 * 60 * 1000)

            # Using custom caller for reliability across SDK versions.
            # We omit the 'priority' filter from the query to avoid 400 errors on DNAC versions
            # that have strict validation for that parameter, and filter manually instead.
            resp = dnac.custom_caller.call_api(
                "GET", "/dna/intent/api/v1/issues",
                params={
                    "startTime": start_time,
                    "endTime": end_time
                }
            )
            # custom_caller returns a response object with .response
            raw_issues = getattr(resp, "response", resp)
            if isinstance(raw_issues, dict) and "response" in raw_issues:
                raw_issues = raw_issues["response"]

            if not isinstance(raw_issues, list):
                raw_issues = []
        except Exception as e:
            logger.warning(f"Failed to fetch issues: {e}")
            return []

    # DNAC's issues API returns siteId/deviceId UUIDs; resolve via warmed caches.
    site_by_id = {s.get("id"): s.get("name") for s in (cache.get("sites") or []) if s.get("id")}
    device_site_map = cache.get("device_site_map") or {}
    device_by_id = {d.get("id"): (d.get("hostname") or d.get("managementIpAddress"))
                    for d in (cache.get("devices") or []) if d.get("id")}

    normalized = []
    for issue in raw_issues:
        d = _dictify(issue)

        # Manual filter for P1/P2
        priority = d.get("priority") or d.get("severity") or "P3"
        if priority not in ("P1", "P2"):
            continue

        # Time can be in many places. Real DNAC uses `last_occurence_time` (snake_case,
        # single 'r' typo); other shapes appear in mocks and older SDK versions.
        ts_raw = (d.get("last_occurence_time")
                  or d.get("lastOccurrenceTime")
                  or d.get("timestamp")
                  or d.get("occurredOn")
                  or d.get("startTime")
                  or "")
        ts = ""
        if isinstance(ts_raw, (int, float)) and ts_raw:
            from datetime import datetime
            ts = datetime.fromtimestamp(ts_raw/1000.0).strftime('%Y-%m-%d %H:%M')
        elif isinstance(ts_raw, str) and ts_raw:
            ts = ts_raw[:16].replace('T', ' ') # Simple ISO-ish slice

        # Device name: prefer explicit name fields, then resolve deviceId via cache.
        device_id = d.get("deviceId") or d.get("device_id")
        dev = (d.get("device_name") or d.get("deviceName") or d.get("host") or d.get("source")
               or (device_by_id.get(device_id) if device_id else None)
               or "Multiple")

        # Site name: prefer explicit hierarchy/name fields, then resolve siteId via
        # the sites cache, then fall back to device→site mapping.
        site_id = d.get("siteId") or d.get("site_id")
        site = (d.get("site_name") or d.get("siteName") or d.get("siteHierarchy") or d.get("siteNameHierarchy")
                or (site_by_id.get(site_id) if site_id else None)
                or (device_site_map.get(device_id) if device_id else None)
                or "—")

        normalized.append({
            "priority": priority,
            "issue_title": d.get("name") or d.get("issueTitle") or d.get("title") or "Unknown Issue",
            "device_name": dev,
            "site_name": site,
            "last_occurrence_time": ts
        })
    return normalized
