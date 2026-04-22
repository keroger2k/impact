"""
panorama_client.py — Cisco Panorama API client for security policy lookup.

Uses the Panorama XML API (PAN-OS REST-like API on /api/).
Authentication: generates an API key from username/password.
All config reads use type=config&action=get with XPath.

Required env vars:
    PANORAMA_HOST       hostname or IP of Panorama management server
    PANORAMA_USERNAME   admin account username
    PANORAMA_PASSWORD   admin account password
"""

import ipaddress
import logging
import os
import time
import xml.etree.ElementTree as ET

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class PanoramaAPIError(Exception):
    """Domain-specific error for Panorama API failures."""
    pass

# Module-level API key cache (survives the session, re-keyed if host changes)
_key_cache: dict[str, tuple[str, float]] = {}  # (key, expires_at)
KEY_TTL = 23 * 3600

BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTION & RAW CALLS
# ──────────────────────────────────────────────────────────────────────────────

def _keygen(host: str, user: str, pwd: str) -> str:
    """Exchange credentials for a Panorama API key."""
    if not host: raise PanoramaAPIError("Host not provided")
    start_time = time.time()
    try:
        host_clean = host.strip().split('/')[0]
        resp = requests.post(
            f"https://{host_clean}/api/",
            data={"type": "keygen", "user": user, "password": pwd},
            verify=os.getenv("IMPACT_VERIFY_SSL", "true").lower() == "true",
            timeout=15,
        )
        duration = int((time.time() - start_time) * 1000)
        logger.info(f"Panorama Keygen: {user}", extra={
            "target": "Panorama",
            "action": "KEYGEN",
            "status": resp.status_code,
            "duration_ms": duration
        })
        root   = ET.fromstring(resp.text)
        key_el = root.find(".//key")
        if key_el is not None and key_el.text:
            return key_el.text
        raise PanoramaAPIError(f"Keygen failed: {resp.text[:200]}")
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"Keygen error: {e}")


def get_api_key() -> str:
    """Generate and cache a Panorama API key from shared env credentials."""
    host = os.getenv("PANORAMA_HOST")
    user = os.getenv("DOMAIN_USERNAME")
    pwd  = os.getenv("DOMAIN_PASSWORD")

    if not all([host, user, pwd]):
        raise PanoramaAPIError("Missing Panorama credentials in environment")

    cache_key = f"{host}:{user}"
    now = time.time()
    if cache_key in _key_cache:
        key, exp = _key_cache[cache_key]
        if now < exp:
            return key

    key = _keygen(host, user, pwd)
    if key:
        _key_cache[cache_key] = (key, now + KEY_TTL)
    return key


def get_user_api_key(username: str, password: str) -> str:
    """Generate a Panorama API key for a specific user. Cached at module level for TTL."""
    host = os.getenv("PANORAMA_HOST")
    if not host:
        raise PanoramaAPIError("PANORAMA_HOST not set")

    cache_key = f"{host}:{username}"
    now = time.time()
    if cache_key in _key_cache:
        key, exp = _key_cache[cache_key]
        if now < exp:
            return key

    key = _keygen(host, username, password)
    if key:
        _key_cache[cache_key] = (key, now + KEY_TTL)
    return key


def _config_get(xpath: str, api_key: str) -> ET.Element:
    """Panorama config GET — returns the <result> element or raises PanoramaAPIError."""
    host = os.getenv("PANORAMA_HOST")
    if not host: raise PanoramaAPIError("PANORAMA_HOST not set")
    start_time = time.time()
    try:
        host_clean = host.strip().split('/')[0]
        resp = requests.get(
            f"https://{host_clean}/api/",
            params={
                "type":   "config",
                "action": "get",
                "xpath":  xpath,
                "key":    api_key,
            },
            verify=os.getenv("IMPACT_VERIFY_SSL", "true").lower() == "true",
            timeout=30,
        )
        duration = int((time.time() - start_time) * 1000)
        logger.info(f"Panorama Config GET: {xpath}", extra={
            "target": "Panorama",
            "action": "CONFIG_GET",
            "status": resp.status_code,
            "duration_ms": duration
        })
        root   = ET.fromstring(resp.text)
        status = root.get("status", "")
        if status != "success":
            raise PanoramaAPIError(f"Config GET failed ({status}): {xpath}")
        res = root.find("result")
        if res is None: raise PanoramaAPIError(f"No result in response for {xpath}")
        return res
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"Config GET error ({xpath}): {e}")


def _op(cmd: str, api_key: str) -> ET.Element:
    """Panorama op command — returns the <result> element or raises PanoramaAPIError."""
    host = os.getenv("PANORAMA_HOST")
    if not host: raise PanoramaAPIError("PANORAMA_HOST not set")
    start_time = time.time()
    try:
        host_clean = host.strip().split('/')[0]
        resp = requests.get(
            f"https://{host_clean}/api/",
            params={"type": "op", "cmd": cmd, "key": api_key},
            verify=os.getenv("IMPACT_VERIFY_SSL", "true").lower() == "true",
            timeout=30,
        )
        duration = int((time.time() - start_time) * 1000)
        logger.info(f"Panorama OP: {cmd}", extra={
            "target": "Panorama",
            "action": "OP",
            "status": resp.status_code,
            "duration_ms": duration
        })
        root = ET.fromstring(resp.text)
        if root.get("status") != "success":
             raise PanoramaAPIError(f"OP failed: {cmd}")
        res = root.find("result")
        if res is None: raise PanoramaAPIError(f"No result in response for {cmd}")
        return res
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"OP error ({cmd}): {e}")


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTIVITY CHECK
# ──────────────────────────────────────────────────────────────────────────────

def connectivity_check_with_key(api_key: str) -> tuple[bool, str]:
    """Lightweight call — verify Panorama is reachable with the given key."""
    try:
        _op("<show><system><info></info></system></show>", api_key)
        return True, "Connected"
    except Exception as e:
        return False, str(e)[:80]


def connectivity_check() -> tuple[bool, str]:
    """No-args check — mints a key from env credentials and verifies reachability."""
    try:
        return connectivity_check_with_key(get_api_key())
    except Exception as e:
        return False, str(e)[:80]


def _op_targeted(cmd: str, api_key: str, target: str) -> ET.Element | None:
    """Like _op but targets a specific managed firewall by serial number. Returns None if unreachable."""
    host = os.getenv("PANORAMA_HOST")
    if not host: return None
    try:
        host_clean = host.strip().split('/')[0]
        resp = requests.get(
            f"https://{host_clean}/api/",
            params={"type": "op", "cmd": cmd, "key": api_key, "target": target},
            verify=os.getenv("IMPACT_VERIFY_SSL", "true").lower() == "true",
            timeout=20,
        )
        if not resp.text or not resp.text.strip():
            return None
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") == "error":
            return None
        return root.find("result")
    except Exception:
        return None
