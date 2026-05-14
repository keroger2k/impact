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


def _paginated_get(dnac, path: str, params: dict, page_size: int, log_label: str) -> list[dict]:
    """Generic paginated GET via dnac.custom_caller — bypasses the SDK's strict
    parameter type checks (they vary between DNAC versions).
    """
    items, offset = [], 1
    while True:
        try:
            q = {**params, "offset": offset, "limit": page_size}
            resp = dnac.custom_caller.call_api("GET", path, params=q)
            batch = getattr(resp, "response", None)
            if batch is None:
                batch = resp.get("response", []) if isinstance(resp, dict) else []
            if not batch:
                break
            items.extend([_dictify(x) for x in batch])
            if len(batch) < page_size:
                break
            offset += page_size
        except Exception as e:
            logger.error(f"{log_label} fetch failed at offset {offset}: {e}")
            if not items:
                raise
            break
    return items


def get_global_ip_pools(dnac) -> list[dict]:
    """Return every DNAC global IP pool (both IPv4 and IPv6).
    Pages through /dna/intent/api/v1/global-pool.
    """
    return _paginated_get(
        dnac, "/dna/intent/api/v1/global-pool",
        params={}, page_size=25, log_label="Global pool",
    )


def get_reserve_ip_subpools(dnac) -> list[dict]:
    """Return every DNAC site-reserved IP subpool (carved from global pools,
    attributed to a specific site). Each entry typically contains an inner
    `ipPools` list with one or two pools (IPv4 and/or IPv6).

    DNAC versions disagree on what query parameters this endpoint accepts:
      - some require siteId or ignoreInheritedGroups to be present
      - some return 400 when ignoreInheritedGroups=false is sent
      - some accept a bare GET and return everything

    Try strategies in order until one succeeds.
    """
    strategies = [
        ("bare",                {}),
        ("ignoreInheritedGroups=true",  {"ignoreInheritedGroups": "true"}),
        ("ignoreInheritedGroups=false", {"ignoreInheritedGroups": "false"}),
    ]
    last_err = None
    for label, params in strategies:
        try:
            pools = _paginated_get(
                dnac, "/dna/intent/api/v1/reserve-ip-subpool",
                params=params, page_size=500,
                log_label=f"Reserve subpool ({label})",
            )
            logger.info(f"Reserve subpool fetch succeeded with strategy '{label}': {len(pools)} pools")
            return pools
        except Exception as e:
            last_err = e
            logger.warning(f"Reserve subpool strategy '{label}' failed: {e}")
            continue

    # All flat strategies failed — fall back to per-top-level-site iteration.
    # DNAC sites are hierarchical; querying parent sites returns all child
    # subpools too, so we only iterate the shallowest (≤1 "/" in the name).
    # This caps us at a handful of API calls instead of one-per-leaf-site.
    logger.warning("All flat strategies failed for reserve-ip-subpool; falling back to top-level-site iteration")
    sites = get_site_cache(dnac)
    top_level = [s for s in sites if s.get("name", "").count("/") <= 1]

    from concurrent.futures import ThreadPoolExecutor
    aggregated: list[dict] = []

    def _fetch_one(site):
        try:
            return _paginated_get(
                dnac, "/dna/intent/api/v1/reserve-ip-subpool",
                params={"siteId": site["id"]}, page_size=500,
                log_label=f"Reserve subpool (site={site.get('name','?')})",
            )
        except Exception as e:
            logger.debug(f"Per-site reserve subpool fetch failed for {site.get('id')}: {e}")
            return []

    with ThreadPoolExecutor(max_workers=10) as ex:
        for batch in ex.map(_fetch_one, top_level):
            aggregated.extend(batch)

    if aggregated:
        return aggregated
    raise last_err if last_err else RuntimeError("reserve-ip-subpool: all strategies failed")


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

# ── Template Programmer (config-change deploys) ─────────────────────────────
#
# Thin wrappers around DNAC's /dna/intent/api/v1/template-programmer endpoints.
# Used by the Command Runner's Config mode to push ad-hoc scripts to a set of
# devices and roll back via DNAC's running-config archive.

IMPACT_ADHOC_PROJECT_NAME = "IMPACT-AdHoc-Templates"

# DNAC softwareType strings expected by the template metadata.
DNAC_SOFTWARE_TYPE = {
    "cisco_ios":  "IOS-XE",
    "cisco_nxos": "NX-OS",
}


def _tp_call(dnac, method: str, path: str, **kwargs):
    """custom_caller wrapper that surfaces DNAC's error body in exceptions.
    The SDK's default exception message is just the URL + status — wrap it so the
    DNAC error JSON ends up in the message we propagate up to the UI."""
    try:
        return dnac.custom_caller.call_api(method, path, **kwargs)
    except Exception as e:
        # dnacentersdk attaches the requests.Response on the exception under
        # various attrs depending on version — try a few to dig out the body.
        body = None
        for attr in ("response", "details", "message"):
            r = getattr(e, attr, None)
            if r is not None:
                if hasattr(r, "text"):
                    body = r.text
                elif isinstance(r, (dict, str)):
                    body = r
                if body:
                    break
        if body:
            raise RuntimeError(f"DNAC {method} {path} failed: {e} | body={str(body)[:500]}") from e
        raise


def ensure_adhoc_project(dnac) -> str:
    """Return the projectId for IMPACT_ADHOC_PROJECT_NAME, creating it if missing."""
    from dev import DEV_MODE
    if DEV_MODE:
        return _uid(f"project-{IMPACT_ADHOC_PROJECT_NAME}")

    try:
        resp = _tp_call(dnac, "GET", "/dna/intent/api/v1/template-programmer/project",
                        params={"name": IMPACT_ADHOC_PROJECT_NAME})
        projects = getattr(resp, "response", None) or (resp if isinstance(resp, list) else [])
        for p in projects:
            d = _dictify(p)
            if d.get("name") == IMPACT_ADHOC_PROJECT_NAME:
                return d["id"]
    except Exception as e:
        logger.debug(f"Template project lookup failed: {e}")

    resp = _tp_call(dnac, "POST", "/dna/intent/api/v1/template-programmer/project",
                    json={"name": IMPACT_ADHOC_PROJECT_NAME,
                          "description": "Ephemeral templates created by IMPACT II Command Runner"})
    body = _dictify(getattr(resp, "response", resp))
    # DNAC returns {"response": {"taskId": "..."}} for async creates — poll the task for resultId.
    task_id = body.get("taskId")
    if task_id:
        project_id = _wait_for_task_resource(dnac, task_id)
        if project_id:
            return project_id

    # Fallback: re-list to find it
    resp = _tp_call(dnac, "GET", "/dna/intent/api/v1/template-programmer/project",
                    params={"name": IMPACT_ADHOC_PROJECT_NAME})
    projects = getattr(resp, "response", None) or []
    for p in projects:
        d = _dictify(p)
        if d.get("name") == IMPACT_ADHOC_PROJECT_NAME:
            return d["id"]
    raise RuntimeError("Failed to create or locate IMPACT-AdHoc-Templates project in DNAC")


def _wait_for_task_resource(dnac, task_id: str, timeout: int = 60) -> str | None:
    """Poll a DNAC task to completion, return its resulting resource id.

    DNAC encodes the id differently per version/endpoint:
      - data field is a bare UUID string (most common for project/template create)
      - data field is a JSON string like '{"templateId":"<uuid>"}'
      - progress is a JSON string with the id embedded
      - progress is plain text like "Template Id: <uuid>"
    We try each shape in order and fall back to a UUID regex on either field.
    """
    import json as _json
    import re
    uuid_re = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', re.I)

    deadline = time.time() + timeout
    last_task: dict = {}
    while time.time() < deadline:
        try:
            resp = _tp_call(dnac, "GET", f"/dna/intent/api/v1/task/{task_id}")
            t = _dictify(getattr(resp, "response", resp))
            last_task = t
            if not t.get("endTime"):
                time.sleep(1.0)
                continue

            if t.get("isError"):
                raise RuntimeError(f"DNAC task failed: {t.get('failureReason') or t.get('progress')}")

            for field in ("data", "progress"):
                v = t.get(field)
                if not v:
                    continue
                # JSON-string shape
                if isinstance(v, str) and v.strip().startswith("{"):
                    try:
                        parsed = _json.loads(v)
                    except (ValueError, TypeError):
                        parsed = None
                    if isinstance(parsed, dict):
                        # Catch DNAC tasks that end with isError=false but a body
                        # like {"errorMessage":"Resource does not exist. version 1.0"}
                        err = parsed.get("errorMessage") or parsed.get("error")
                        if err:
                            raise RuntimeError(f"DNAC task failed (task body): {err}")
                        for k in ("templateId", "id", "projectId", "deploymentId"):
                            if parsed.get(k):
                                return parsed[k]
                # Bare UUID string
                if isinstance(v, str):
                    m = uuid_re.search(v)
                    if m:
                        return m.group(0)
            # Task ended cleanly but we couldn't find an id — return None so caller
            # can fall back (e.g. re-list by name).
            return None
        except RuntimeError:
            raise
        except Exception as e:
            logger.debug(f"Task poll error for {task_id}: {e}")
            time.sleep(1.0)
    raise TimeoutError(f"DNAC task {task_id} did not complete within {timeout}s "
                       f"(last_task={str(last_task)[:200]})")


def create_adhoc_template(dnac, project_id: str, name: str, body: str,
                          software_type: str) -> str:
    """Create a single-version template in the ad-hoc project. Returns templateId
    after the version is committed and ready to deploy."""
    from dev import DEV_MODE
    if DEV_MODE:
        return _uid(f"template-{name}")

    payload = {
        "name": name,
        "projectId": project_id,
        "projectName": IMPACT_ADHOC_PROJECT_NAME,
        "softwareType": software_type,
        "deviceTypes": [{"productFamily": "Switches and Hubs"}, {"productFamily": "Routers"}],
        "language": "VELOCITY",
        "templateContent": body,
        "composite": False,
        "description": "Ephemeral ad-hoc template (auto-cleaned by IMPACT II)",
    }
    # DNAC create-template is project-scoped: POST /project/{projectId}/template
    resp = _tp_call(dnac, "POST",
                    f"/dna/intent/api/v1/template-programmer/project/{project_id}/template",
                    json=payload)
    body_out = _dictify(getattr(resp, "response", resp))
    task_id = body_out.get("taskId")
    template_id = _wait_for_task_resource(dnac, task_id) if task_id else None
    if not template_id:
        raise RuntimeError(f"Template creation did not return an id (task={task_id}, body={body_out})")
    logger.info(f"Template created in DNAC: id={template_id} name={name} project={project_id}")

    # Commit a version so the template is deployable
    version_payload = {"templateId": template_id, "comments": "IMPACT II initial version"}
    logger.info(f"Committing template version: {version_payload}")
    commit_resp = _tp_call(dnac, "POST", "/dna/intent/api/v1/template-programmer/template/version",
                           json=version_payload)
    commit_body = _dictify(getattr(commit_resp, "response", commit_resp))
    commit_task = commit_body.get("taskId")
    if commit_task:
        _wait_for_task_resource(dnac, commit_task)

    return template_id


def deploy_template(dnac, template_id: str, device_uuids: list[str]) -> str:
    """Deploy a committed template to a set of devices. Returns deploymentId."""
    from dev import DEV_MODE
    if DEV_MODE:
        return _uid(f"deploy-{template_id}-{time.time()}")

    payload = {
        "forcePushTemplate": True,
        "isComposite": False,
        "templateId": template_id,
        "targetInfo": [
            {"id": uuid, "type": "MANAGED_DEVICE_UUID", "params": {}}
            for uuid in device_uuids
        ],
    }
    resp = _tp_call(dnac, "POST", "/dna/intent/api/v2/template-programmer/template/deploy",
                    json=payload)
    body = _dictify(getattr(resp, "response", resp))

    # Sync shape (older versions): deploymentId is in the body directly.
    deployment_id = body.get("deploymentId") or (
        body.get("response", {}).get("deploymentId")
        if isinstance(body.get("response"), dict) else None)
    if deployment_id:
        return deployment_id

    # Async shape (DNAC 2.3.x+): response is {"taskId": "...", "url": "..."}.
    # Poll the task; deploymentId is embedded in task.progress (often as a JSON
    # string, sometimes as plain text like "Template Deployment Id : <uuid>").
    task_id = body.get("taskId") or (
        body.get("response", {}).get("taskId")
        if isinstance(body.get("response"), dict) else None)
    if task_id:
        return _wait_for_deployment_id(dnac, task_id)

    raise RuntimeError(f"deploy_template: no deploymentId or taskId in response ({body})")


def _wait_for_deployment_id(dnac, task_id: str, timeout: int = 120) -> str:
    """Poll a deploy task to completion and extract the deploymentId from its
    progress / data fields. Strict: only accepts a value explicitly labelled
    as a deployment id, so we don't accidentally polling-status the templateId."""
    import json as _json
    import re

    label_re = re.compile(r'[Dd]eployment\s*[Ii]d\s*[:=]\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.I)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = _tp_call(dnac, "GET", f"/dna/intent/api/v1/task/{task_id}")
            t = _dictify(getattr(resp, "response", resp))
            if not t.get("endTime"):
                time.sleep(1.0)
                continue

            if t.get("isError"):
                raise RuntimeError(
                    f"Deploy task failed: {t.get('failureReason') or t.get('progress')}")

            progress = t.get("progress") or ""
            data     = t.get("data") or ""

            # 1) JSON shape: surface explicit deploymentId AND explicit errorMessage
            #    (DNAC sometimes ends a task with isError=false but the body says
            #    "Resource does not exist. version 1.0" — catch that here.)
            for blob in (progress, data):
                if isinstance(blob, str) and blob.strip().startswith("{"):
                    try:
                        parsed = _json.loads(blob)
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(parsed, dict):
                        continue
                    if parsed.get("deploymentId"):
                        return parsed["deploymentId"]
                    err = parsed.get("errorMessage") or parsed.get("error") or parsed.get("description")
                    if err:
                        raise RuntimeError(f"Deploy failed (task body): {err}")

            # 2) labelled-UUID shape: "Deployment Id : <uuid>"
            for blob in (progress, data):
                if isinstance(blob, str):
                    m = label_re.search(blob)
                    if m:
                        return m.group(1)

            # No deploymentId AND no errorMessage — surface the raw blobs so we
            # can see what DNAC actually returned.
            raise RuntimeError(
                f"Deploy task completed without a deploymentId. "
                f"progress={str(progress)[:300]!r} data={str(data)[:200]!r}")
        except RuntimeError:
            raise
        except Exception as e:
            logger.debug(f"Deploy task poll error for {task_id}: {e}")
            time.sleep(1.0)
    raise TimeoutError(f"Deploy task {task_id} did not complete within {timeout}s")


def get_deployment_status(dnac, deployment_id: str) -> dict:
    """Fetch per-device status for a deployment. Returns the raw response dict."""
    from dev import DEV_MODE
    if DEV_MODE:
        return _mock_deployment_status(deployment_id)

    resp = _tp_call(dnac, "GET",
                    f"/dna/intent/api/v1/template-programmer/template/deploy/status/{deployment_id}")
    return _dictify(getattr(resp, "response", resp))


def delete_template(dnac, template_id: str) -> None:
    """Delete a template (best-effort, swallows errors for cleanup paths)."""
    from dev import DEV_MODE
    if DEV_MODE:
        return
    try:
        _tp_call(dnac, "DELETE",
                 f"/dna/intent/api/v1/template-programmer/template/{template_id}")
    except Exception as e:
        logger.warning(f"Template delete failed for {template_id}: {e}")


def list_adhoc_templates(dnac, project_id: str) -> list[dict]:
    """Return all templates under the ad-hoc project (for retention cleanup)."""
    from dev import DEV_MODE
    if DEV_MODE:
        return []
    try:
        resp = _tp_call(dnac, "GET", "/dna/intent/api/v1/template-programmer/template",
                        params={"projectId": project_id})
        items = getattr(resp, "response", None) or []
        return [_dictify(t) for t in items]
    except Exception as e:
        logger.warning(f"List templates failed: {e}")
        return []


def _mock_deployment_status(deployment_id: str) -> dict:
    """DEV_MODE: synthesize a deployment status response that looks like DNAC's.
    Cycles through stages keyed off elapsed time since the deployment_id was minted."""
    # The deployment_id we emit in DEV_MODE has a time-derived component; use the
    # cache to remember when each id was first seen, then mark complete after ~2s.
    from cache import cache
    key = f"dev_deploy_started:{deployment_id}"
    started = cache.get(key)
    if not started:
        started = time.time()
        cache.set(key, started, ttl=600)
    elapsed = time.time() - started

    # Pull device list out of the cache (router stashes it under dev_deploy_devices:<id>)
    devs = cache.get(f"dev_deploy_devices:{deployment_id}") or []
    if elapsed < 1.5:
        status = "IN_PROGRESS"
        per_dev_status = "IN_PROGRESS"
    else:
        status = "SUCCESS"
        per_dev_status = "SUCCESS"
    return {
        "deploymentId": deployment_id,
        "status": status,
        "devices": [
            {"deviceId": d, "ipAddress": "", "status": per_dev_status,
             "name": "", "startTime": "", "endTime": "",
             "statusMessage": "DEV_MODE simulated success"}
            for d in devs
        ],
    }


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
