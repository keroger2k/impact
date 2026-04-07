"""
ise_client.py — Cisco ISE read-only client.

Uses ciscoisesdk custom_caller with URL-encoded query strings built manually.
This avoids SDK version differences in how 'params' kwargs are handled.

ERS base:     https://{host}/ers/config/{resource}
OpenAPI base: https://{host}/api/v1/{resource}
"""

import logging
import os
from urllib.parse import urlencode

import urllib3
from ciscoisesdk import IdentityServicesEngineAPI
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
ISE_SDK_VERSION = "3.3_patch_1"


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTION
# ──────────────────────────────────────────────────────────────────────────────

def create_client() -> IdentityServicesEngineAPI:
    host     = os.getenv("ISE_HOST")
    username = os.getenv("DOMAIN_USERNAME")
    password = os.getenv("DOMAIN_PASSWORD")
    if not all([host, username, password]):
        raise EnvironmentError(
            "Missing credentials. "
            "Set ISE_HOST, DOMAIN_USERNAME, DOMAIN_PASSWORD in your .env file."
        )
    return IdentityServicesEngineAPI(
        username         = username,
        password         = password,
        uses_api_gateway = True,
        base_url         = f"https://{host}",
        version          = ISE_SDK_VERSION,
        verify           = False,
        debug            = False,
        uses_csrf_token  = False,
    )


# ──────────────────────────────────────────────────────────────────────────────
# RAW CALL HELPERS  (URL-based params — reliable across SDK versions)
# ──────────────────────────────────────────────────────────────────────────────

import json as _json   # alias to avoid shadowing

# ERS requires these headers — without Accept: application/json
# ISE may return XML which fails all dict parsing silently.
_ERS_HEADERS = {
    "Accept":       "application/json",
    "Content-Type": "application/json",
}


def _to_dict(obj) -> dict:
    """
    Reliably convert any ciscoisesdk response object to a plain Python dict.
    Handles MyDict, AttrDict, and regular dicts equally.
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    # ciscoisesdk wraps responses in MyDict/similar — serialise then re-parse
    try:
        return _json.loads(_json.dumps(obj))
    except Exception:
        try:
            return dict(obj)
        except Exception:
            return {}


def _build_url(base: str, params: dict) -> str:
    """Append query string to URL. Always encodes params into the URL itself."""
    if not params:
        return base
    return f"{base}?{urlencode(params)}"


def _ers_get(ise, path: str, params: dict = None) -> dict:
    """
    Single ERS GET with proper JSON headers.
    Returns a plain Python dict (never an SDK wrapper object).
    Returns {} on any error.
    """
    url = _build_url(f"/ers/config/{path}", params or {})
    try:
        resp = ise.custom_caller.call_api("GET", url, headers=_ERS_HEADERS)
        raw  = getattr(resp, "response", None)
        return _to_dict(raw)
    except Exception as e:
        logger.warning(f"ERS GET {url}: {e}")
        return {}


def _ers_paginate(ise, resource: str, size: int = 100, filter_str: str = "") -> list:
    """
    Walk all ERS pages. Returns flat list of summary dicts.
    Each item typically has: id, name, description, link.
    """
    results = []
    page    = 1
    while True:
        params = {"size": size, "page": page}
        if filter_str:
            params["filter"] = filter_str
        data  = _ers_get(ise, resource, params)
        sr    = data.get("SearchResult", {})
        items = sr.get("resources") or []
        if not items:
            break
        results.extend(items)
        if len(items) < size or not sr.get("nextPage"):
            break
        page += 1
    return results


def _ers_by_id(ise, resource: str, rid: str) -> dict:
    """
    Fetch single ERS resource by ID and unwrap the type envelope.
    ERS wraps objects: {"ERSEndPoint": {...}, "link": {...}}
    Returns the payload dict (e.g. the ERSEndPoint value), already converted
    to a plain Python dict via _to_dict.
    """
    data = _ers_get(ise, f"{resource}/{rid}")
    for key, val in data.items():
        # Skip navigation/meta keys; return the first real payload object
        if key not in ("link", "SearchResult") and hasattr(val, "get"):
            return _to_dict(val)
    return data


def _openapi_get(ise, path: str, params: dict = None) -> list | dict | None:
    """Single OpenAPI GET with JSON headers. Returns plain Python object or None."""
    url = _build_url(f"/api/v1/{path}", params or {})
    try:
        resp = ise.custom_caller.call_api("GET", url, headers=_ERS_HEADERS)
        raw  = getattr(resp, "response", None)
        if raw is None:
            return None
        if isinstance(raw, list):
            return [_to_dict(i) if hasattr(i, "get") else i for i in raw]
        return _to_dict(raw)
    except Exception as e:
        logger.warning(f"OpenAPI GET {url}: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTIVITY CHECK
# ──────────────────────────────────────────────────────────────────────────────

def connectivity_check(ise) -> bool:
    """Lightweight call — fetch 1 NAD to verify ISE is reachable."""
    try:
        data = _ers_get(ise, "networkdevice", {"size": 1, "page": 1})
        return "SearchResult" in data
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# NETWORK ACCESS DEVICES  /ers/config/networkdevice
# ──────────────────────────────────────────────────────────────────────────────

def get_network_devices(ise, search: str = "") -> list:
    if search:
        # Try name first, then IP
        results = _ers_paginate(ise, "networkdevice", filter_str=f"name.CONTAINS.{search}")
        if not results:
            results = _ers_paginate(ise, "networkdevice", filter_str=f"ipaddress.CONTAINS.{search}")
        return results
    return _ers_paginate(ise, "networkdevice")


def get_network_device_detail(ise, device_id: str) -> dict:
    return _ers_by_id(ise, "networkdevice", device_id)


def get_network_device_groups(ise) -> list:
    return _ers_paginate(ise, "networkdevicegroup")


# ──────────────────────────────────────────────────────────────────────────────
# ENDPOINTS  /ers/config/endpoint
#
# IMPORTANT: ISE ERS endpoint filter uses only the mac field.
# The filter value must use the MAC format as stored in ISE — typically
# uppercase with colons (AA:BB:CC:DD:EE:FF) but may vary by ISE version.
# We try multiple normalizations to maximise match rate.
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_mac_variants(raw: str) -> list[str]:
    """
    Return multiple MAC format variants from a raw search string so
    we can try each one against the ERS filter.
    ISE typically stores MACs as  AA:BB:CC:DD:EE:FF  (uppercase, colon-delimited).
    """
    # Strip all separators and uppercase
    clean = raw.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 2:
        return [raw.upper()]  # partial — just pass through

    variants = []

    # If it looks like a full or partial MAC, build colon form
    # Pad to nearest even length for grouping
    if len(clean) <= 12:
        # Colon-delimited pairs
        colon_form = ":".join(clean[i:i+2] for i in range(0, len(clean), 2))
        variants.append(colon_form)

    # Also try the raw input uppercased (in case user typed AA:BB already)
    variants.append(raw.upper())

    return list(dict.fromkeys(variants))  # deduplicate, preserve order


def get_endpoints(ise, mac_search: str = "") -> list:
    """
    Search endpoints by MAC address.
    Uses size=20 for filtered searches since MAC queries return very few results.
    Tries multiple MAC format variants and returns combined de-duplicated results.
    An empty mac_search returns all endpoints (paginated, may be slow).
    """
    if not mac_search:
        return _ers_paginate(ise, "endpoint")

    seen_ids = set()
    results  = []

    for mac_variant in _normalize_mac_variants(mac_search):
        batch = _ers_paginate(
            ise, "endpoint",
            size=20,                             # MAC searches return few results
            filter_str=f"mac.CONTAINS.{mac_variant}",
        )
        for item in batch:
            ep_id = item.get("id")
            if ep_id and ep_id not in seen_ids:
                seen_ids.add(ep_id)
                results.append(item)

    # If still empty, try without a filter on a small page and scan manually
    # This handles ISE instances that don't support CONTAINS on mac
    if not results and len(mac_search) >= 2:
        logger.info("Filter returned no results — falling back to manual scan (first 500 endpoints).")
        all_eps = _ers_paginate(ise, "endpoint", size=500)
        search_clean = mac_search.upper().replace(":", "").replace("-", "").replace(".", "")
        for ep in all_eps:
            name = (ep.get("name") or "").upper().replace(":", "").replace("-", "").replace(".", "")
            if search_clean in name:
                results.append(ep)

    return results


def get_endpoint_detail(ise, endpoint_id: str) -> dict:
    return _ers_by_id(ise, "endpoint", endpoint_id)


def get_endpoint_groups(ise) -> list:
    return _ers_paginate(ise, "endpointgroup")


# ──────────────────────────────────────────────────────────────────────────────
# IDENTITY  /ers/config/identitygroup  /ers/config/internaluser
# ──────────────────────────────────────────────────────────────────────────────

def get_identity_groups(ise) -> list:
    return _ers_paginate(ise, "identitygroup")


def get_internal_users(ise, search: str = "") -> list:
    if search:
        return _ers_paginate(ise, "internaluser", filter_str=f"name.CONTAINS.{search}")
    return _ers_paginate(ise, "internaluser")


def get_internal_user_detail(ise, user_id: str) -> dict:
    return _ers_by_id(ise, "internaluser", user_id)


# ──────────────────────────────────────────────────────────────────────────────
# TRUSTSEC  /ers/config/sgt  /ers/config/sgacl  /ers/config/egressmatrixcell
# ──────────────────────────────────────────────────────────────────────────────

def get_sgts(ise) -> list:
    return _ers_paginate(ise, "sgt")


def get_sgt_detail(ise, sgt_id: str) -> dict:
    return _ers_by_id(ise, "sgt", sgt_id)


def get_sgacls(ise) -> list:
    return _ers_paginate(ise, "sgacl")


def get_sgacl_detail(ise, sgacl_id: str) -> dict:
    return _ers_by_id(ise, "sgacl", sgacl_id)


def get_egress_matrix(ise) -> list:
    return _ers_paginate(ise, "egressmatrixcell", size=100)


# ──────────────────────────────────────────────────────────────────────────────
# POLICY  OpenAPI + ERS
# ──────────────────────────────────────────────────────────────────────────────

def get_policy_sets(ise) -> list:
    data = _openapi_get(ise, "policy/network-access/policy-set")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("response", []) or []
    return []


def get_auth_rules(ise, policy_id: str) -> list:
    data = _openapi_get(ise, f"policy/network-access/policy-set/{policy_id}/authentication/rules")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("response", []) or []
    return []


def get_authz_rules(ise, policy_id: str) -> list:
    data = _openapi_get(ise, f"policy/network-access/policy-set/{policy_id}/authorization/rules")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("response", []) or []
    return []


def get_authz_profiles(ise) -> list:
    return _ers_paginate(ise, "authorizationprofile")


def get_authz_profile_detail(ise, profile_id: str) -> dict:
    return _ers_by_id(ise, "authorizationprofile", profile_id)


def get_allowed_protocols(ise) -> list:
    return _ers_paginate(ise, "allowedprotocols")


# ──────────────────────────────────────────────────────────────────────────────
# PROFILING  /ers/config/profilerprofile
# ──────────────────────────────────────────────────────────────────────────────

def get_profiling_policies(ise) -> list:
    return _ers_paginate(ise, "profilerprofile")


# ──────────────────────────────────────────────────────────────────────────────
# DEPLOYMENT  /api/v1/deployment/node
# ──────────────────────────────────────────────────────────────────────────────

def get_deployment_nodes(ise) -> list:
    data = _openapi_get(ise, "deployment/node")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("response", []) or []
    return []


def get_node_detail(ise, hostname: str) -> dict:
    data = _openapi_get(ise, f"deployment/node/{hostname}")
    if isinstance(data, dict):
        return data.get("response", data) or {}
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# ACTIVE SESSIONS  /api/v1/session
# ──────────────────────────────────────────────────────────────────────────────

import xml.etree.ElementTree as _ET
import requests as _requests


def _xml_to_dict(xml_text: str) -> dict:
    """
    Convert ISE MNT XML response to a flat Python dict.
    Handles both single-level and nested session attribute structures.
    """
    result = {}
    if not xml_text:
        return result
    try:
        root = _ET.fromstring(xml_text)

        def _walk(node, prefix=""):
            for child in node:
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if len(child) == 0:
                    # Leaf node — store value
                    result[tag] = child.text or ""
                else:
                    # Branch node — recurse
                    _walk(child, tag)

        _walk(root)
    except _ET.ParseError as e:
        logger.warning(f"XML parse error: {e}")
    return result


def _mnt_get(path: str) -> dict:
    """
    Direct HTTP call to ISE MNT REST API with XML Accept header.
    Bypasses the SDK because the SDK assumes JSON and the MNT API only speaks XML.
    Returns a flat dict of attributes, or {} on any error.
    """
    from urllib.parse import urljoin

    host     = os.getenv("ISE_HOST")
    username = os.getenv("DOMAIN_USERNAME")
    password = os.getenv("DOMAIN_PASSWORD")

    if not all([host, username, password]):
        return {}

    url = f"https://{host}{path}"
    try:
        resp = _requests.get(
            url,
            auth    = (username, password),
            verify  = False,
            headers = {"Accept": "application/xml"},
            timeout = 15,
        )
        if resp.status_code == 200 and resp.text:
            return _xml_to_dict(resp.text)
        logger.warning(f"MNT {path}: HTTP {resp.status_code}")
        return {}
    except Exception as e:
        logger.warning(f"MNT direct request {path}: {e}")
        return {}




    """
    Fetch active RADIUS/TACACS session details from the ISE MNT REST API.
    This is the source of authentication attributes shown in ISE Context Visibility
    (AAA-Server, AD-Fetch-Host-Name, AllowedProtocolMatchedRule, etc.)
    that are NOT stored in the ERS endpoint record.

    MNT API: /admin/API/mnt/Session/MACAddress/{mac}
    Returns a flat dict of session attributes, or {} if no active session.
    """
    # MNT API expects MAC in uppercase colon format
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    # Normalise to XX:XX:XX:XX:XX:XX if given without separators
    if ":" not in mac_clean and len(mac_clean) == 12:
        mac_clean = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))

    url = f"/admin/API/mnt/Session/MACAddress/{mac_clean}"
    try:
        resp = ise.custom_caller.call_api("GET", url, headers=_ERS_HEADERS)
        raw  = getattr(resp, "response", None)
        if raw is None:
            return {}
        result = _to_dict(raw)
        # MNT wraps under "sessionParameters" or "passed" depending on ISE version
        for key in ("sessionParameters", "passed", "failed"):
            if key in result and isinstance(result[key], dict):
                return result[key]
        return result
    except Exception as e:
        logger.warning(f"MNT session GET {url}: {e}")
        return {}

# Convenience alias for FastAPI routers
_ise_client = None

def get_client():
    """Return the shared service-account ISE client (used for cache warming)."""
    global _ise_client
    if _ise_client is None:
        _ise_client = create_client()
    return _ise_client


def create_user_client(username: str, password: str) -> IdentityServicesEngineAPI:
    """Create a per-user ISE client (not cached globally)."""
    host = os.getenv("ISE_HOST")
    if not host:
        raise EnvironmentError("ISE_HOST not set")
    return IdentityServicesEngineAPI(
        username         = username,
        password         = password,
        uses_api_gateway = True,
        base_url         = f"https://{host}",
        version          = ISE_SDK_VERSION,
        verify           = False,
        debug            = False,
        uses_csrf_token  = False,
    )
