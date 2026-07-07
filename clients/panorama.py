"""
panorama_client.py — Cisco Panorama API client for security policy lookup.

Backed by pan-os-python (panos package) for object/policy operations; falls back
to raw XML for managed-device op commands and diagnostics where the SDK doesn't
add value.
"""

import ipaddress
import logging
import os
import time
import xml.etree.ElementTree as ET

import requests
from dotenv import load_dotenv
from panos.errors import PanDeviceXapiError
from panos.firewall import Firewall
from panos.panorama import DeviceGroup, Panorama

from clients import verify_ssl

load_dotenv()

logger = logging.getLogger(__name__)

class PanoramaAPIError(Exception):
    """Domain-specific error for Panorama API failures."""
    pass


class PanoramaAuthError(PanoramaAPIError):
    """The API key was rejected by Panorama (403 / "Invalid Credential").

    Distinct from PanoramaAPIError so callers can tell a *stale key* (which is
    fixable by regenerating the key and retrying) apart from a genuine API/data
    failure. Subclasses PanoramaAPIError so existing ``except PanoramaAPIError``
    handlers still catch it.
    """
    pass


def _is_invalid_credential(status_code: int | None, text: str | None) -> bool:
    """True if a Panorama response signals a rejected/expired API key.

    Panorama returns HTTP 403 with an ``Invalid Credential`` message body when a
    key is stale (rotated, expired, or issued before a Panorama restart).
    """
    if status_code == 403:
        return True
    return "invalid credential" in (text or "").lower()


def _xp(value: str) -> str:
    """Validate a name interpolated into an XPath predicate (`[@name='...']`).

    Panorama object/device-group/template names can't legitimately contain
    quotes or brackets, so reject those defensively — this rules out XPath
    injection from any name that ever reaches here from a less-trusted source.
    Names are system-enumerated today (callers validate user input against the
    real list first), so this is defense-in-depth, not the only guard.
    """
    s = "" if value is None else str(value)
    if any(c in s for c in "'\"[]<>&"):
        raise PanoramaAPIError(f"Unsafe XPath name: {value!r}")
    return s

# Module-level API key cache (survives the session, re-keyed if host changes)
_key_cache: dict[str, tuple[str, float]] = {}  # (key, expires_at)
KEY_TTL = 23 * 3600

BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"


def _host() -> str:
    host = os.getenv("PANORAMA_HOST")
    if not host:
        raise PanoramaAPIError("PANORAMA_HOST not set")
    return host.strip().split('/')[0]


def _pan(api_key: str) -> Panorama:
    """Build a Panorama SDK client from an already-issued API key."""
    if not api_key:
        raise PanoramaAPIError("API key not provided")
    return Panorama(hostname=_host(), api_key=api_key)


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTION & RAW CALLS
# ──────────────────────────────────────────────────────────────────────────────

def _keygen(user: str, pwd: str) -> str:
    """Exchange credentials for a Panorama API key."""
    start_time = time.time()
    try:
        resp = requests.post(
            f"https://{_host()}/api/",
            data={"type": "keygen", "user": user, "password": pwd},
            verify=verify_ssl(),
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


def get_api_key(force: bool = False) -> str:
    """Generate and cache a Panorama API key from shared env credentials.

    ``force=True`` bypasses the module cache and re-issues a fresh key, used to
    recover from a key Panorama has since rejected as stale.
    """
    host = os.getenv("PANORAMA_HOST")
    user = os.getenv("DOMAIN_USERNAME")
    pwd  = os.getenv("DOMAIN_PASSWORD")

    if not all([host, user, pwd]):
        raise PanoramaAPIError("Missing Panorama credentials in environment")

    cache_key = f"{host}:{user}"
    now = time.time()
    if not force and cache_key in _key_cache:
        key, exp = _key_cache[cache_key]
        if now < exp:
            return key

    key = _keygen(user, pwd)
    if key:
        _key_cache[cache_key] = (key, now + KEY_TTL)
    return key


def get_user_api_key(username: str, password: str, force: bool = False) -> str:
    """Generate a Panorama API key for a specific user. Cached at module level for TTL.

    ``force=True`` bypasses the module cache and re-issues a fresh key, used to
    recover from a key Panorama has since rejected as stale.
    """
    host = os.getenv("PANORAMA_HOST")
    if not host:
        raise PanoramaAPIError("PANORAMA_HOST not set")

    cache_key = f"{host}:{username}"
    now = time.time()
    if not force and cache_key in _key_cache:
        key, exp = _key_cache[cache_key]
        if now < exp:
            return key

    key = _keygen(username, password)
    if key:
        _key_cache[cache_key] = (key, now + KEY_TTL)
    return key


def _config_get(xpath: str, api_key: str) -> ET.Element:
    """Panorama config GET — returns the <result> element or raises PanoramaAPIError."""
    start_time = time.time()
    try:
        resp = requests.get(
            f"https://{_host()}/api/",
            params={
                "type":   "config",
                "action": "get",
                "xpath":  xpath,
                "key":    api_key,
            },
            verify=verify_ssl(),
            timeout=30,
        )
        duration = int((time.time() - start_time) * 1000)
        logger.info(f"Panorama Config GET: {xpath}", extra={
            "target": "Panorama",
            "action": "CONFIG_GET",
            "status": resp.status_code,
            "duration_ms": duration
        })
        if _is_invalid_credential(resp.status_code, resp.text):
            raise PanoramaAuthError(f"Panorama rejected API key (Invalid Credential): {xpath}")
        root   = ET.fromstring(resp.text)
        status = root.get("status", "")
        if status != "success":
            raise PanoramaAPIError(f"Panorama config GET failed ({status}): {xpath}")
        res = root.find("result")
        if res is None: raise PanoramaAPIError(f"No result in response for {xpath}")
        return res
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"Panorama config GET error ({xpath}): {e}")


def _op(cmd: str, api_key: str) -> ET.Element:
    """Panorama op command — returns the <result> element or raises PanoramaAPIError."""
    start_time = time.time()
    try:
        resp = requests.get(
            f"https://{_host()}/api/",
            params={"type": "op", "cmd": cmd, "key": api_key},
            verify=verify_ssl(),
            timeout=30,
        )
        duration = int((time.time() - start_time) * 1000)
        logger.info(f"Panorama OP: {cmd}", extra={
            "target": "Panorama",
            "action": "OP",
            "status": resp.status_code,
            "duration_ms": duration
        })
        if _is_invalid_credential(resp.status_code, resp.text):
            raise PanoramaAuthError(f"Panorama rejected API key (Invalid Credential): {cmd}")
        root = ET.fromstring(resp.text)
        if root.get("status") != "success":
             raise PanoramaAPIError(f"Panorama op failed: {cmd}")
        res = root.find("result")
        if res is None: raise PanoramaAPIError(f"No result in response for {cmd}")
        return res
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"Panorama op error: {e}")


def _config_get_targeted(xpath: str, api_key: str, target: str, timeout: int = 20) -> ET.Element | None:
    """Like _config_get, but routes the query through Panorama to a specific
    managed firewall by serial (target=SERIAL). Returns the <result> element
    representing that firewall's view of the config — which includes anything
    pushed via templates/stacks AND any local-only config the firewall has.

    Tunnels defined directly on a firewall (not via shared/template/stack)
    only surface here.
    """
    try:
        host = _host()
    except PanoramaAPIError:
        return None
    try:
        resp = requests.get(
            f"https://{host}/api/",
            params={
                "type":   "config",
                "action": "get",
                "xpath":  xpath,
                "key":    api_key,
                "target": target,
            },
            verify=verify_ssl(),
            timeout=timeout,
        )
        if not resp.text or not resp.text.strip():
            return None
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") != "success":
            return None
        return root.find("result")
    except Exception:
        return None


def op_via_sdk(
    cmd: str,
    api_key: str,
    target: str | None = None,
    timeout: int = 20,
) -> ET.Element | None:
    """Run an operational command via pan-os-python — preferred over hand-rolled XML.

    `cmd` is the plain CLI string (e.g. ``show vpn flow name "my-tunnel"``); the SDK
    tokenizes and builds the XML, which avoids the injection / escaping foot-guns we'd
    otherwise hit by interpolating user data into ``<show>...</show>`` literals. Quote
    any non-keyword tokens per ``panos.string_to_xml`` semantics.

    When ``target`` is set, the request is routed through Panorama to that managed
    firewall by attaching a ``Firewall(serial=target)`` to the Panorama parent.
    """
    try:
        host = _host()
    except PanoramaAPIError:
        return None
    try:
        pan = Panorama(hostname=host, api_key=api_key, timeout=timeout)
        if target:
            fw = Firewall(serial=target)
            pan.add(fw)
            return fw.op(cmd)
        return pan.op(cmd)
    except PanDeviceXapiError as e:
        msg = str(e)
        if "not connected" in msg:
            logger.debug("panos op skipped (target=%s not connected): %s", target, cmd)
        else:
            logger.warning("panos op failed (target=%s): %s — %s", target, cmd, msg)
        return None
    except Exception:
        logger.exception("panos op failed (target=%s): %s", target, cmd)
        return None


def _op_targeted(cmd: str, api_key: str, target: str) -> ET.Element | None:
    """Like _op but targets a specific managed firewall by serial number."""
    try:
        host_clean = _host()
    except PanoramaAPIError:
        return None
    try:
        resp = requests.get(
            f"https://{host_clean}/api/",
            params={"type": "op", "cmd": cmd, "key": api_key, "target": target},
            verify=verify_ssl(),
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


# ──────────────────────────────────────────────────────────────────────────────
# FIREWALL INTERFACE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

def fetch_firewall_interfaces(api_key: str) -> list[dict]:
    """
    Fetch all managed firewall interface IP addresses from Panorama.
    """
    try:
        result = _op("<show><devices><all/></devices></show>", api_key)
    except PanoramaAuthError:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch Panorama devices: {e}")
        return []

    entries = result.findall(".//entry")
    if not entries:
        entries = result.findall("./entry")

    processed_serials: set[str] = set()
    devices: list[dict] = []

    for dev in entries:
        serial   = dev.get("name", "") or dev.findtext("serial", "")
        hostname = dev.findtext("hostname", "")

        if not serial or not hostname:
            continue
        if serial in processed_serials:
            continue

        # Skip pseudo-entries (no model means it's a sub-system entry)
        model = dev.findtext("model", "")
        if not model and not hostname:
            continue

        mgmt_ip      = dev.findtext("ip-address", "")
        device_group = dev.findtext("device-group", "") or "N/A"
        os_version   = dev.findtext("os-version", "")
        ha_state     = dev.findtext("ha-state", "")
        ha_enabled   = dev.findtext("ha-enabled", "") == "yes"

        # Seed iface_map with management interface from device list
        iface_map: dict[str, dict] = {}
        _SKIP_VALUES = {"", "unknown", "none", "n/a", "0.0.0.0", "::", "::/0"}

        if mgmt_ip and mgmt_ip.lower() not in _SKIP_VALUES:
            iface_map["management"] = {"name": "management", "ipv4": mgmt_ip, "ipv6": []}

        mgmt_v6 = (dev.findtext("ipv6-address") or "").strip()
        if mgmt_v6 and mgmt_v6.lower() not in _SKIP_VALUES:
            iface_map.setdefault("management", {"name": "management", "ipv4": "", "ipv6": []})
            iface_map["management"]["ipv6"].append(mgmt_v6)

        # Fetch detailed interface info from the device itself
        iface_result = _op_targeted(
            "<show><interface>all</interface></show>", api_key, serial
        )
        if iface_result is not None:
            for entry in iface_result.findall(".//entry"):
                name = entry.findtext("name")
                if not name:
                    continue
                iface_map.setdefault(name, {"name": name, "ipv4": "", "ipv6": [], "zone": ""})

                # IPv4
                v4 = (entry.findtext("ip") or "").strip()
                if v4 and v4.lower() not in _SKIP_VALUES:
                    iface_map[name]["ipv4"] = v4  # may include /prefix

                # IPv6 — handles <addr6>, <ipv6>, <ipv6ll> with nested member/entry
                for tag in ("addr6", "ipv6", "ipv6ll"):
                    node = entry.find(tag)
                    if node is None:
                        continue
                    sub_nodes = node.findall(".//member") + node.findall(".//entry")
                    if sub_nodes:
                        for sub in sub_nodes:
                            val = (sub.text or sub.get("name") or "").strip()
                            if val and val.lower() not in _SKIP_VALUES:
                                if val not in iface_map[name]["ipv6"]:
                                    iface_map[name]["ipv6"].append(val)
                    elif node.text:
                        val = node.text.strip()
                        if val.lower() not in _SKIP_VALUES and val not in iface_map[name]["ipv6"]:
                            iface_map[name]["ipv6"].append(val)

        # Fetch zone information to map interfaces to zones.
        zone_result = _op_targeted("<show><zone></show>", api_key, serial)
        if zone_result is not None:
            # We use a case-insensitive map for interface lookups to be safe
            iface_keys_lower = {k.lower(): k for k in iface_map.keys()}

            for entry in zone_result.findall(".//entry"):
                zone_name = entry.get("name") or entry.findtext("name")
                if not zone_name:
                    continue

                iface_nodes = (
                    entry.findall(".//interface/member") +
                    entry.findall("./member") +
                    entry.findall(".//vsys/entry/interface/member")
                )

                for iface_node in iface_nodes:
                    iface_name_raw = (iface_node.text or "").strip()
                    if not iface_name_raw:
                        continue

                    # Case-insensitive match against our collected interfaces
                    if iface_name_raw.lower() in iface_keys_lower:
                        actual_key = iface_keys_lower[iface_name_raw.lower()]
                        iface_map[actual_key]["zone"] = zone_name

        # Only include devices that have at least one IP
        interfaces = [v for v in iface_map.values() if v["ipv4"] or v["ipv6"]]
        if not interfaces:
            continue

        devices.append({
            "serial":       serial,
            "hostname":     hostname,
            "model":        model,
            "management_ip": mgmt_ip,
            "device_group": device_group,
            "os_version":   os_version,
            "ha_state":     ha_state,
            "ha_enabled":   ha_enabled,
            "interfaces":   interfaces,
        })
        processed_serials.add(serial)

    devices.sort(key=lambda d: d["hostname"].lower())
    return devices


def search_firewall_interfaces(ip: str, devices: list[dict]) -> list[dict]:
    """
    Search the interface inventory for a matching IP address.
    """
    import ipaddress as _ipa
    try:
        query = _ipa.ip_address(ip)
    except ValueError:
        return []

    matches = []
    for dev in devices:
        for iface in dev.get("interfaces", []):
            raw_v4 = iface.get("ipv4", "")
            bare_v4 = raw_v4.split("/")[0].strip()
            if bare_v4:
                try:
                    if _ipa.ip_address(bare_v4) == query:
                        matches.append({"device": dev, "interface": iface})
                        continue
                except ValueError:
                    pass

            for raw_v6 in iface.get("ipv6", []):
                bare_v6 = raw_v6.split("/")[0].strip()
                try:
                    if _ipa.ip_address(bare_v6) == query:
                        matches.append({"device": dev, "interface": iface})
                        break
                except ValueError:
                    pass

    return matches


def connectivity_check() -> tuple[bool, str]:
    """Return (ok, detail_string). Lightweight auth + version check."""
    try:
        key = get_api_key()
        if not key:
            return False, "Cannot obtain API key"
        return connectivity_check_with_key(key)
    except Exception as e:
        return False, str(e)


def connectivity_check_with_key(key: str) -> tuple[bool, str]:
    """Version check using an already-obtained API key."""
    try:
        result = _op("<show><system><info></info></system></show>", key)
        hostname = result.findtext(".//hostname", "Unknown")
        version  = result.findtext(".//sw-version", "Unknown")
        model    = result.findtext(".//model", "")
        return True, f"{hostname}  ·  {model}  ·  PAN-OS {version}"
    except Exception as e:
        return False, str(e)


# ──────────────────────────────────────────────────────────────────────────────
# DEVICE GROUPS
# ──────────────────────────────────────────────────────────────────────────────

def get_device_groups(api_key: str) -> list[str]:
    """Return a list of all device group names from Panorama."""
    start_time = time.time()
    try:
        pan = _pan(api_key)
        dgs = DeviceGroup.refreshall(pan, add=False)
        names = sorted(dg.name for dg in dgs if dg.name)
        logger.info("Panorama DeviceGroup.refreshall", extra={
            "target": "Panorama",
            "action": "DEVICE_GROUPS",
            "status": 200,
            "duration_ms": int((time.time() - start_time) * 1000),
        })
        return names
    except Exception as e:
        if _is_invalid_credential(None, str(e)):
            raise PanoramaAuthError(f"Panorama rejected API key (Invalid Credential): {e}")
        raise PanoramaAPIError(f"get_device_groups error: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# ADDRESS OBJECTS & GROUPS
# ──────────────────────────────────────────────────────────────────────────────

def _unwrap(result, tag):
    """Unwrap Panorama's extra nesting."""
    if result is None:
        return None
    if result.find("entry") is not None:
        return result
    child = result.find(tag)
    return child if child is not None else result


def _parse_address_entries(parent):
    """Parse address blocks."""
    result = {}
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name = entry.get("name", "")
        ips  = []
        for tag in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
            val = entry.findtext(tag)
            if val:
                ips.append(val.strip())
        result[name] = ips
    return result


def _parse_group_entries(parent: ET.Element | None) -> dict[str, list[str]]:
    """Parse <address-group> entries into {group_name: [member_names]}."""
    result = {}
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name    = entry.get("name", "")
        members = [m.text for m in entry.findall(".//static/member") if m.text]
        result[name] = members
    return result


def get_address_objects_and_groups(
    api_key: str,
    device_groups: list[str],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """
    Return (address_objects, address_groups) merged from shared + device groups.
    """
    objects: dict[str, list[str]] = {}
    groups:  dict[str, list[str]] = {}

    # Shared level
    try:
        r = _config_get("/config/shared/address", api_key)
        objects.update(_parse_address_entries(_unwrap(r, "address")))
    except PanoramaAuthError: raise
    except Exception: pass
    try:
        r = _config_get("/config/shared/address-group", api_key)
        groups.update(_parse_group_entries(_unwrap(r, "address-group")))
    except PanoramaAuthError: raise
    except Exception: pass

    # Per device-group level
    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{_xp(dg)}']/address", api_key)
            objects.update(_parse_address_entries(_unwrap(r, "address")))
        except PanoramaAuthError: raise
        except Exception: pass
        try:
            r = _config_get(f"{dg_base}/entry[@name='{_xp(dg)}']/address-group", api_key)
            groups.update(_parse_group_entries(_unwrap(r, "address-group")))
        except PanoramaAuthError: raise
        except Exception: pass

    return objects, groups


def resolve_name(
    name: str,
    objects: dict[str, list[str]],
    groups:  dict[str, list[str]],
    visited: set | None = None,
) -> list[str]:
    """Recursively expand an address object name or group name to IP strings."""
    if visited is None:
        visited = set()
    if name in visited:
        return []
    visited.add(name)

    if name in objects:
        return list(objects[name])
    if name in groups:
        result = []
        for member in groups[name]:
            result.extend(resolve_name(member, objects, groups, visited))
        return result
    # Rules may reference literal IPs/CIDRs/ranges instead of named objects
    value = name.strip()
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return [value]
        if "-" in value:
            lo, hi = value.split("-", 1)
            ipaddress.ip_address(lo.strip())
            ipaddress.ip_address(hi.strip())
            return [value]
        ipaddress.ip_address(value)
        return [value]
    except ValueError:
        return []


# ──────────────────────────────────────────────────────────────────────────────
# SERVICE OBJECTS
# ──────────────────────────────────────────────────────────────────────────────

# Built-in service names Panorama treats as special
_BUILTIN_SERVICES = {
    "any":                 [("any", "any")],
    "application-default": [("any", "any")],
    "service-http":        [("tcp", "80")],
    "service-https":       [("tcp", "443")],
}


def _parse_service_entries(parent: ET.Element | None) -> dict[str, list[tuple[str, str]]]:
    """Parse <service> entries into {name: [(protocol, port_str), ...]}. """
    result = {}
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name  = entry.get("name", "")
        ports = []
        for proto in ("tcp", "udp"):
            port_el = entry.find(f"protocol/{proto}/port")
            if port_el is not None and port_el.text:
                ports.append((proto, port_el.text.strip()))
        if ports:
            result[name] = ports
    return result


def _parse_service_group_entries(parent: ET.Element | None) -> dict[str, list[str]]:
    """Parse <service-group> entries into {name: [member_name, ...]}."""
    result = {}
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name    = entry.get("name", "")
        members = [m.text for m in entry.findall(".//members/member") if m.text]
        result[name] = members
    return result


def get_services(
    api_key:       str,
    device_groups: list[str],
) -> tuple[dict[str, list[tuple[str, str]]], dict[str, list[str]]]:
    """
    Return (service_objects, service_groups) merged from shared + device groups.
    """
    objects: dict[str, list[tuple[str, str]]] = dict(_BUILTIN_SERVICES)
    groups:  dict[str, list[str]]             = {}

    try:
        r = _config_get("/config/shared/service", api_key)
        objects.update(_parse_service_entries(_unwrap(r, "service")))
    except PanoramaAuthError: raise
    except Exception: pass
    try:
        r = _config_get("/config/shared/service-group", api_key)
        groups.update(_parse_service_group_entries(_unwrap(r, "service-group")))
    except PanoramaAuthError: raise
    except Exception: pass

    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{_xp(dg)}']/service", api_key)
            objects.update(_parse_service_entries(_unwrap(r, "service")))
        except PanoramaAuthError: raise
        except Exception: pass
        try:
            r = _config_get(f"{dg_base}/entry[@name='{_xp(dg)}']/service-group", api_key)
            groups.update(_parse_service_group_entries(_unwrap(r, "service-group")))
        except PanoramaAuthError: raise
        except Exception: pass

    return objects, groups


def resolve_service(
    name:    str,
    svc_obj: dict[str, list[tuple[str, str]]],
    svc_grp: dict[str, list[str]],
    visited: set | None = None,
) -> list[tuple[str, str]]:
    """Recursively expand a service name to [(protocol, port_str), ...]."""
    if visited is None:
        visited = set()
    if name in visited:
        return []
    visited.add(name)

    if name in svc_obj:
        return list(svc_obj[name])
    if name in svc_grp:
        result = []
        for member in svc_grp[name]:
            result.extend(resolve_service(member, svc_obj, svc_grp, visited))
        return result
    return []


def _port_in_portstr(query_port: int, port_str: str) -> bool:
    """Check if query_port is covered by port_str."""
    for segment in port_str.split(","):
        segment = segment.strip()
        if "-" in segment:
            try:
                lo, hi = segment.split("-", 1)
                if int(lo) <= query_port <= int(hi):
                    return True
            except ValueError:
                pass
        else:
            try:
                if int(segment) == query_port:
                    return True
            except ValueError:
                pass
    return False


def service_matches(
    query_proto: str,
    query_port:  int | None,
    service_names: list[str],
    svc_obj: dict[str, list[tuple[str, str]]],
    svc_grp: dict[str, list[str]],
) -> bool:
    """Return True if the query proto/port is covered by any service in service_names."""
    if query_port is None:
        return True

    if not service_names or "any" in service_names or "application-default" in service_names:
        return True

    for svc_name in service_names:
        for (proto, port_str) in resolve_service(svc_name, svc_obj, svc_grp):
            if proto != "any" and query_proto != "any" and proto != query_proto:
                continue
            if port_str == "any":
                return True
            if _port_in_portstr(query_port, port_str):
                return True

    return False

def _ip_in_value(query_ip: str, value: str) -> bool:
    """Check whether query_ip falls within a Panorama address value."""
    value = value.strip()
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(query_ip)
        if "/" in value:
            return ip in ipaddress.ip_network(value, strict=False)
        if "-" in value:
            parts = value.split("-", 1)
            if len(parts) == 2:
                lo = ipaddress.ip_address(parts[0].strip())
                hi = ipaddress.ip_address(parts[1].strip())
                return lo <= ip <= hi
        return ip == ipaddress.ip_address(value)
    except ValueError:
        return False


def ip_matches_address_list(
    query_ip: str,
    address_names: list[str],
    objects: dict[str, list[str]],
    groups:  dict[str, list[str]],
    negate:  bool = False,
) -> bool:
    """Return True if query_ip is covered by any name in address_names."""
    if not address_names or "any" in address_names:
        matched = True
    else:
        matched = False
        for name in address_names:
            values = resolve_name(name, objects, groups)
            if any(_ip_in_value(query_ip, v) for v in values):
                matched = True
                break

    return (not matched) if negate else matched


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY RULES
# ──────────────────────────────────────────────────────────────────────────────

def _members(entry: ET.Element, tag: str) -> list[str]:
    return [m.text for m in entry.findall(f".//{tag}/member") if m.text]


def get_managed_devices(api_key: str) -> list[dict]:
    """Fetch the list of managed firewalls from Panorama."""
    devices = []
    try:
        result = _op("<show><devices><all/></devices></show>", api_key)
        possible_paths = [".//entry", ".//device/entry", "./device/entry", "devices/entry", "./entry"]

        entries = []
        for xpath in possible_paths:
            entries = result.findall(xpath)
            if entries:
                break

        if not entries:
            return devices

        for entry in entries:
            serial = entry.get("name", "")
            if not serial:
                continue

            hostname = entry.findtext("hostname") or ""
            model = entry.findtext("model") or ""
            if not hostname and not model:
                continue

            # Tri-state connected: True / False / None (unknown). The PAN-OS
            # `<connected>` tag is normally yes/no, but on some versions or for
            # certain pseudo-entries it may be absent — treat absent as unknown
            # rather than disconnected so callers don't silently skip the device.
            conn_raw = (entry.findtext("connected") or "").strip().lower()
            if conn_raw in ("yes", "true"):
                conn_state: bool | None = True
            elif conn_raw in ("no", "false"):
                conn_state = False
            else:
                conn_state = None
            devices.append({
                "serial":        serial,
                "hostname":      hostname,
                "model":         model,
                "ip_address":    entry.findtext("ip-address") or "",
                "device_group":  entry.findtext("device-group") or "N/A",
                "os_version":    entry.findtext("os-version") or "",
                "ha_state":      entry.findtext("ha-state") or "",
                "ha_enabled":    entry.findtext("ha-enabled") == "yes",
                "connected":     conn_state,
            })

        devices.sort(key=lambda d: (d.get("hostname", "").lower(), d.get("model", "")))
    except PanoramaAuthError:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch managed devices: {e}")

    return devices


def _parse_rules(
    parent:       ET.Element | None,
    device_group: str,
    rulebase:     str,
) -> list[dict]:
    """Parse a <rules> element into a list of rule dicts."""
    if parent is None:
        return []
    rules = []
    for entry in parent.findall("entry"):
        rules.append({
            "device_group": device_group,
            "rulebase":     rulebase,
            "name":         entry.get("name", "unnamed"),
            "action":       entry.findtext("action") or "allow",
            "disabled":     entry.findtext("disabled") == "yes",
            "source":          _members(entry, "source"),
            "source_negate":   entry.findtext("negate-source") == "yes",
            "from_zones":      _members(entry, "from"),
            "source_user":     _members(entry, "source-user"),
            "destination":     _members(entry, "destination"),
            "dest_negate":     entry.findtext("negate-destination") == "yes",
            "to_zones":        _members(entry, "to"),
            "application":     _members(entry, "application"),
            "service":         _members(entry, "service"),
            "category":        _members(entry, "category"),
            "description":     entry.findtext("description") or "",
            "tag":             _members(entry, "tag"),
        })
    return rules


def get_all_security_rules(
    api_key:       str,
    device_groups: list[str],
    progress_cb=None,
) -> list[dict]:
    """Fetch all security rules in evaluation order."""
    all_rules = []
    dg_base = f"{BASE_XPATH}/device-group"

    # Shared pre
    try:
        r = _config_get(f"{BASE_XPATH}/pre-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "pre"))
    except PanoramaAuthError: raise
    except Exception: pass

    # Per device-group pre
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{_xp(dg)}']/pre-rulebase/security/rules", api_key)
            all_rules.extend(_parse_rules(_unwrap(r, "rules"), dg, "pre"))
        except PanoramaAuthError: raise
        except Exception: pass

    # Per device-group post
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{_xp(dg)}']/post-rulebase/security/rules", api_key)
            all_rules.extend(_parse_rules(_unwrap(r, "rules"), dg, "post"))
        except PanoramaAuthError: raise
        except Exception: pass

    # Shared post
    try:
        r = _config_get(f"{BASE_XPATH}/post-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "post"))
    except PanoramaAuthError: raise
    except Exception: pass

    return all_rules


def get_device_to_group_mapping(api_key: str, device_groups: list[str]) -> dict[str, str]:
    """Build serial -> device group mapping."""
    mapping = {}
    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        try:
            xpath = f"{dg_base}/entry[@name='{_xp(dg)}']/devices"
            result = _config_get(xpath, api_key)
            entries = result.findall(".//entry") or result.findall("entry")
            for entry in entries:
                serial = entry.get("name", "")
                if serial:
                    mapping[serial] = dg
        except Exception:
            pass
    return mapping


def get_device_vsys(api_key: str, device_serial: str) -> list[str]:
    """Fetch vsys for a managed device."""
    vsys_list = []
    try:
        xpath = f"/config/devices/entry[@name='{_xp(device_serial)}']/vsys"
        result = _config_get(xpath, api_key)
        entries = result.findall(".//entry") or result.findall("entry")
        for entry in entries:
            name = entry.get("name", "")
            if name:
                vsys_list.append(name)
    except Exception:
        pass
    if not vsys_list:
        vsys_list = ["vsys1"]
    return vsys_list


def get_device_vsys_policies(
    api_key:        str,
    device_serial:  str,
    vsys_name:      str,
    device_groups:  list[str] = None,
    progress_cb=None,
) -> list[dict]:
    """Fetch policies for a specific vsys on a managed device."""
    all_rules = []

    # Device shared pre-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{_xp(device_serial)}']/pre-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "pre"))
    except Exception: pass

    # vsys pre-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{_xp(device_serial)}']/vsys/entry[@name='{_xp(vsys_name)}']/pre-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), vsys_name, "pre"))
    except Exception: pass

    # vsys post-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{_xp(device_serial)}']/vsys/entry[@name='{_xp(vsys_name)}']/post-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), vsys_name, "post"))
    except Exception: pass

    # Device shared post-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{_xp(device_serial)}']/post-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "post"))
    except Exception: pass

    for idx, rule in enumerate(all_rules, 1):
        rule["rule_number"] = idx

    return all_rules


# ──────────────────────────────────────────────────────────────────────────────
# POLICY LOOKUP
# ──────────────────────────────────────────────────────────────────────────────

def find_matching_rules(
    src_ip:      str,
    dst_ip:      str,
    rules:       list[dict],
    objects:     dict[str, list[str]],
    groups:      dict[str, list[str]],
    svc_obj:     dict | None = None,
    svc_grp:     dict | None = None,
    dst_port:    int | None = None,
    proto:       str        = "any",
    include_disabled: bool  = False,
) -> list[dict]:
    """Return matching rules in evaluation order."""
    if svc_obj is None:
        svc_obj = dict(_BUILTIN_SERVICES)
    if svc_grp is None:
        svc_grp = {}

    matches, first_recorded = [], False
    for rule in rules:
        if rule.get("disabled") and not include_disabled:
            continue

        src_ok = ip_matches_address_list(src_ip, rule["source"], objects, groups, rule.get("source_negate", False))
        dst_ok = ip_matches_address_list(dst_ip, rule["destination"], objects, groups, rule.get("dest_negate", False))
        svc_ok = service_matches(proto, dst_port, rule["service"], svc_obj, svc_grp)

        if src_ok and dst_ok and svc_ok:
            r = dict(rule)
            r["first_match"] = not first_recorded
            if not first_recorded:
                first_recorded = True
            matches.append(r)

    return matches


# ──────────────────────────────────────────────────────────────────────────────
# LIVE POLICY TEST (test security-policy-match on a managed firewall)
# ──────────────────────────────────────────────────────────────────────────────

_PROTO_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}


def build_policy_match_cmd(
    src_ip:      str,
    dst_ip:      str,
    protocol:    str,
    dst_port:    int | None = None,
    from_zone:   str | None = None,
    to_zone:     str | None = None,
    application: str | None = None,
) -> str:
    """Build the ``test security-policy-match`` CLI string for op_via_sdk."""
    parts = [
        "test security-policy-match",
        f"source {src_ip}",
        f"destination {dst_ip}",
        f"protocol {_PROTO_NUMBERS[protocol]}",
    ]
    if dst_port is not None:
        parts.append(f"destination-port {dst_port}")
    if from_zone:
        parts.append(f'from "{from_zone}"')
    if to_zone:
        parts.append(f'to "{to_zone}"')
    if application:
        parts.append(f'application "{application}"')
    return " ".join(parts)


def parse_policy_match_result(result: ET.Element | None) -> dict:
    """Parse the firewall's response into {ok, rules: [{name, action, ...}]}.

    Newer PAN-OS returns ``<rules><entry name="..."><action>...</action>...``;
    older versions return bare ``<entry>rule-name</entry>`` text. The implicit
    default rules come back named intrazone-default / interzone-default — infer
    their action when the firewall omits it.
    """
    if result is None:
        return {"ok": False, "error": "no response from firewall (offline, unreachable, or command failed)"}
    rules = []
    for entry in result.findall(".//rules/entry"):
        name = entry.get("name") or (entry.text or "").strip()
        rule = {"name": name}
        for tag in ("action", "index", "from", "to", "source", "destination",
                    "application", "service", "category", "terminal"):
            val = entry.findtext(tag)
            if val is not None:
                rule[tag] = val.strip()
        if not rule.get("action"):
            if name == "intrazone-default":
                rule["action"] = "allow"
            elif name == "interzone-default":
                rule["action"] = "deny"
        rules.append(rule)
    return {"ok": True, "rules": rules}


def test_security_policy_match(
    api_key:     str,
    serial:      str,
    src_ip:      str,
    dst_ip:      str,
    protocol:    str,
    dst_port:    int | None = None,
    from_zone:   str | None = None,
    to_zone:     str | None = None,
    application: str | None = None,
) -> dict:
    """Run ``test security-policy-match`` on a managed firewall via Panorama.

    This asks the firewall's own policy engine, so the verdict reflects the
    actually-pushed config — authoritative, unlike offline rule matching.
    """
    cmd = build_policy_match_cmd(src_ip, dst_ip, protocol, dst_port, from_zone, to_zone, application)
    parsed = parse_policy_match_result(op_via_sdk(cmd, api_key, target=serial))
    parsed["cmd"] = cmd
    return parsed


def run_diagnostics(api_key: str) -> dict[str, str]:
    """Probe Panorama API with various XPaths."""
    host, results = _host(), {}

    def raw_get(xpath: str) -> str:
        try:
            resp = requests.get(
                f"https://{host}/api/",
                params={"type": "config", "action": "get", "xpath": xpath, "key": api_key},
                verify=verify_ssl(), timeout=20,
            )
            return resp.text[:3000]
        except Exception as e:
            return f"ERROR: {e}"

    def raw_op(cmd: str) -> str:
        try:
            resp = requests.get(
                f"https://{host}/api/",
                params={"type": "op", "cmd": cmd, "key": api_key},
                verify=verify_ssl(), timeout=20,
            )
            return resp.text[:3000]
        except Exception as e:
            return f"ERROR: {e}"

    results["op: show system info"] = raw_op("<show><system><info/></system></show>")
    results["device-groups"] = raw_get(f"{BASE_XPATH}/device-group")

    return results

def get_client() -> str | None:
    """FastAPI router alias."""
    try:
        return get_api_key()
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# IKE / IPSEC OBJECTS (network profiles + tunnels)
# ──────────────────────────────────────────────────────────────────────────────

def _members_text(parent: ET.Element | None, path: str) -> list[str]:
    if parent is None: return []
    return [m.text for m in parent.findall(path) if m is not None and m.text]


def _parse_ike_crypto_profiles(parent: ET.Element | None, scope: str) -> list[dict]:
    """Parse <ike-crypto-profiles>/<entry> blocks."""
    out: list[dict] = []
    if parent is None: return out
    for entry in parent.findall("entry"):
        out.append({
            "scope":          scope,
            "name":           entry.get("name", ""),
            "encryption":     _members_text(entry, ".//encryption/member"),
            "hash":           _members_text(entry, ".//hash/member"),
            "dh_group":       _members_text(entry, ".//dh-group/member"),
            "lifetime_value": (entry.find(".//lifetime/*").text if entry.find(".//lifetime/*") is not None else ""),
            "lifetime_unit":  (entry.find(".//lifetime/*").tag if entry.find(".//lifetime/*") is not None else ""),
            "authentication_multiple": entry.findtext("authentication-multiple") or "",
        })
    return out


def _parse_ipsec_crypto_profiles(parent: ET.Element | None, scope: str) -> list[dict]:
    """Parse <ipsec-crypto-profiles>/<entry> blocks. Each entry has an esp or ah child."""
    out: list[dict] = []
    if parent is None: return out
    for entry in parent.findall("entry"):
        esp = entry.find("esp")
        ah  = entry.find("ah")
        proto = "esp" if esp is not None else ("ah" if ah is not None else "")
        body = esp if esp is not None else ah
        out.append({
            "scope":          scope,
            "name":           entry.get("name", ""),
            "protocol":       proto,
            "encryption":     _members_text(body, ".//encryption/member") if body is not None else [],
            "authentication": _members_text(body, ".//authentication/member") if body is not None else [],
            "dh_group":       entry.findtext("dh-group") or "",
            "lifetime_value": (entry.find(".//lifetime/*").text if entry.find(".//lifetime/*") is not None else ""),
            "lifetime_unit":  (entry.find(".//lifetime/*").tag if entry.find(".//lifetime/*") is not None else ""),
            "lifesize_value": (entry.find(".//lifesize/*").text if entry.find(".//lifesize/*") is not None else ""),
            "lifesize_unit":  (entry.find(".//lifesize/*").tag if entry.find(".//lifesize/*") is not None else ""),
        })
    return out


def _parse_ike_gateways(parent: ET.Element | None, scope: str, template: str = "") -> list[dict]:
    """Parse <ike/gateway>/<entry> blocks."""
    out: list[dict] = []
    if parent is None: return out
    for entry in parent.findall("entry"):
        peer_addr = ""
        for path in (".//peer-address/ip", ".//peer-address/fqdn", ".//peer-address/dynamic"):
            v = entry.find(path)
            if v is not None:
                peer_addr = v.text or ("dynamic" if path.endswith("dynamic") else "")
                break

        local_iface = entry.findtext(".//local-address/interface") or ""
        local_ip    = entry.findtext(".//local-address/ip") or ""
        protocol    = entry.findtext("protocol/version") or "ikev1"

        # IKEv1
        v1 = entry.find("protocol/ikev1")
        v1_profile = v1.findtext("ike-crypto-profile") if v1 is not None else ""
        v1_mode    = v1.findtext("exchange-mode") if v1 is not None else ""

        # IKEv2
        v2 = entry.find("protocol/ikev2")
        v2_profile = v2.findtext("ike-crypto-profile") if v2 is not None else ""

        auth_psk = entry.find(".//authentication/pre-shared-key") is not None
        auth_cert = entry.find(".//authentication/certificate") is not None

        out.append({
            "scope":          scope,
            "template":       template,
            "name":           entry.get("name", ""),
            "peer_address":   peer_addr,
            "local_interface": local_iface,
            "local_ip":       local_ip,
            "protocol":       protocol,
            "ikev1_profile":  v1_profile or "",
            "ikev1_mode":     v1_mode or "",
            "ikev2_profile":  v2_profile or "",
            "auth":           "pre-shared-key" if auth_psk else ("certificate" if auth_cert else ""),
            "disabled":       entry.findtext("disabled") == "yes",
        })
    return out


def _parse_ipsec_tunnels(parent: ET.Element | None, scope: str, template: str = "") -> list[dict]:
    """Parse <ipsec/tunnel>/<entry> blocks."""
    out: list[dict] = []
    if parent is None: return out
    for entry in parent.findall("entry"):
        ak = entry.find("auto-key")
        ike_gateway = ""
        ipsec_profile = ""
        proxy_ids: list[dict] = []
        if ak is not None:
            ig = ak.find("ike-gateway/entry")
            if ig is not None:
                ike_gateway = ig.get("name", "")
            ipsec_profile = ak.findtext("ipsec-crypto-profile") or ""
            for pid in ak.findall(".//proxy-id/entry"):
                proxy_ids.append({
                    "name":     pid.get("name", ""),
                    "local":    pid.findtext("local") or "",
                    "remote":   pid.findtext("remote") or "",
                    "protocol": "any" if pid.find(".//protocol/any") is not None
                               else (pid.findtext(".//protocol/number") or ""),
                })

        tunnel_iface = entry.findtext("tunnel-interface") or ""
        disabled = entry.findtext("disabled") == "yes"
        out.append({
            "scope":           scope,
            "template":        template,
            "name":            entry.get("name", ""),
            "tunnel_interface": tunnel_iface,
            "ike_gateway":     ike_gateway,
            "ipsec_profile":   ipsec_profile,
            "proxy_ids":       proxy_ids,
            "disabled":        disabled,
            "anti_replay":     entry.findtext("anti-replay") or "",
        })
    return out


def _network_xpath_roots() -> dict[str, str]:
    """Where IKE/IPsec live on Panorama. We search shared + all templates."""
    return {
        "shared_ike_crypto":   "/config/shared/network/ike/crypto-profiles/ike-crypto-profiles",
        "shared_ipsec_crypto": "/config/shared/network/ike/crypto-profiles/ipsec-crypto-profiles",
        "shared_ike_gateway":  "/config/shared/network/ike/gateway",
        "shared_ipsec_tunnel": "/config/shared/network/tunnel/ipsec",
    }


def _list_templates(api_key: str) -> list[str]:
    """Panorama templates that may carry network/IKE config.

    Only direct <entry> children of the <template> element count. Earlier
    versions used `.//entry`, which recursively matched every nested entry
    (device entries, vsys entries, interfaces, subnets, crypto profile
    names, QoS classes) and treated them all as templates — producing
    hundreds of bogus XPath fetches per refresh.
    """
    names: list[str] = []
    try:
        r = _config_get(f"{BASE_XPATH}/template", api_key)
        parent = _unwrap(r, "template")
        if parent is not None:
            for entry in parent.findall("./entry"):
                n = entry.get("name", "")
                if n:
                    names.append(n)
    except Exception:
        pass
    return names


def _list_template_stacks(api_key: str) -> list[str]:
    """Panorama template-stacks that may carry network/IKE config.

    In Panorama, firewalls are typically assigned to a template-stack rather
    than a single template. The stack references multiple templates AND can
    define its own stack-level config (which is where IPsec tunnels often
    live in practice — they're per-firewall-pair, not per-shared-template).

    Iterating templates alone misses those tunnels. We iterate template-stacks
    separately and fetch their network/ike subtree the same way.
    """
    names: list[str] = []
    try:
        r = _config_get(f"{BASE_XPATH}/template-stack", api_key)
        parent = _unwrap(r, "template-stack")
        if parent is not None:
            for entry in parent.findall("./entry"):
                n = entry.get("name", "")
                if n:
                    names.append(n)
    except Exception:
        pass
    return names


def get_ike_crypto_profiles(api_key: str) -> list[dict]:
    """Fetch IKE crypto profiles from shared + every template."""
    out: list[dict] = []
    roots = _network_xpath_roots()
    try:
        r = _config_get(roots["shared_ike_crypto"], api_key)
        out.extend(_parse_ike_crypto_profiles(_unwrap(r, "ike-crypto-profiles"), "shared"))
    except Exception: pass

    for tpl in _list_templates(api_key):
        try:
            xpath = (
                f"{BASE_XPATH}/template/entry[@name='{_xp(tpl)}']"
                "/config/devices/entry[@name='localhost.localdomain']"
                "/network/ike/crypto-profiles/ike-crypto-profiles"
            )
            r = _config_get(xpath, api_key)
            out.extend(_parse_ike_crypto_profiles(_unwrap(r, "ike-crypto-profiles"), f"template:{tpl}"))
        except Exception: continue
    return out


def get_ipsec_crypto_profiles(api_key: str) -> list[dict]:
    """Fetch IPsec crypto profiles from shared + every template."""
    out: list[dict] = []
    roots = _network_xpath_roots()
    try:
        r = _config_get(roots["shared_ipsec_crypto"], api_key)
        out.extend(_parse_ipsec_crypto_profiles(_unwrap(r, "ipsec-crypto-profiles"), "shared"))
    except Exception: pass

    for tpl in _list_templates(api_key):
        try:
            xpath = (
                f"{BASE_XPATH}/template/entry[@name='{_xp(tpl)}']"
                "/config/devices/entry[@name='localhost.localdomain']"
                "/network/ike/crypto-profiles/ipsec-crypto-profiles"
            )
            r = _config_get(xpath, api_key)
            out.extend(_parse_ipsec_crypto_profiles(_unwrap(r, "ipsec-crypto-profiles"), f"template:{tpl}"))
        except Exception: continue
    return out


def get_ike_gateways(api_key: str) -> list[dict]:
    """Fetch IKE gateways from shared + every template."""
    out: list[dict] = []
    roots = _network_xpath_roots()
    try:
        r = _config_get(roots["shared_ike_gateway"], api_key)
        out.extend(_parse_ike_gateways(_unwrap(r, "gateway"), "shared"))
    except Exception: pass

    for tpl in _list_templates(api_key):
        try:
            xpath = (
                f"{BASE_XPATH}/template/entry[@name='{_xp(tpl)}']"
                "/config/devices/entry[@name='localhost.localdomain']"
                "/network/ike/gateway"
            )
            r = _config_get(xpath, api_key)
            out.extend(_parse_ike_gateways(_unwrap(r, "gateway"), f"template:{tpl}", template=tpl))
        except Exception: continue
    return out


def get_ipsec_tunnels(api_key: str) -> list[dict]:
    """Fetch IPsec tunnels from shared + every template."""
    out: list[dict] = []
    roots = _network_xpath_roots()
    try:
        r = _config_get(roots["shared_ipsec_tunnel"], api_key)
        out.extend(_parse_ipsec_tunnels(_unwrap(r, "ipsec"), "shared"))
    except Exception: pass

    for tpl in _list_templates(api_key):
        try:
            xpath = (
                f"{BASE_XPATH}/template/entry[@name='{_xp(tpl)}']"
                "/config/devices/entry[@name='localhost.localdomain']"
                "/network/tunnel/ipsec"
            )
            r = _config_get(xpath, api_key)
            out.extend(_parse_ipsec_tunnels(_unwrap(r, "ipsec"), f"template:{tpl}", template=tpl))
        except Exception: continue
    return out


# ──────────────────────────────────────────────────────────────────────────────
# COMBINED IKE / IPSEC INVENTORY FETCH
# ──────────────────────────────────────────────────────────────────────────────
# Replaces four separate get_* functions that each iterated every template.
# This walks shared once and each template once, fetching the entire `network`
# subtree per template and slicing the four object types out of it client-side.
# Round-trips: 4*(N+1) → (N+2). On a fleet with 30 templates and ~2s per call,
# that's a 4-minute speedup.
#
# The optional `progress` callback fires at meaningful boundaries with
# kwargs: step, status ("loading"/"done"/"warn"), message, current, total.
# Designed for SSE streaming.

def _slice_network_tree(network_el, scope: str, template: str = "") -> dict:
    """Given a parsed <network> Element, return all four IKE/IPsec object lists."""
    if network_el is None:
        return {"ike_profiles": [], "ipsec_profiles": [], "ike_gateways": [], "ipsec_tunnels": []}

    ike_crypto   = network_el.find(".//ike/crypto-profiles/ike-crypto-profiles")
    ipsec_crypto = network_el.find(".//ike/crypto-profiles/ipsec-crypto-profiles")
    gateway      = network_el.find(".//ike/gateway")
    ipsec_tun    = network_el.find(".//tunnel/ipsec")

    return {
        "ike_profiles":   _parse_ike_crypto_profiles(ike_crypto, scope),
        "ipsec_profiles": _parse_ipsec_crypto_profiles(ipsec_crypto, scope),
        "ike_gateways":   _parse_ike_gateways(gateway, scope, template=template),
        "ipsec_tunnels":  _parse_ipsec_tunnels(ipsec_tun, scope, template=template),
    }


def get_ipsec_inventory(api_key: str, progress=None) -> dict:
    """Fetch all IKE/IPsec objects from Panorama (shared + every template) in
    one pass. Returns {"ike_profiles": [...], "ipsec_profiles": [...],
    "ike_gateways": [...], "ipsec_tunnels": [...]}.

    progress is an optional callable: progress(step, status, message,
    current=None, total=None). Step is one of: "shared", "templates_list",
    "template", "done".
    """
    def _emit(step, status, message, current=None, total=None):
        if progress:
            try:
                progress(step=step, status=status, message=message,
                         current=current, total=total)
            except Exception as e:
                logger.warning(f"tunnel progress callback failed: {e}")

    out = {"ike_profiles": [], "ipsec_profiles": [], "ike_gateways": [], "ipsec_tunnels": []}

    # 1. Shared — one fetch of the whole network subtree.
    _emit("shared", "loading", "Fetching shared IKE/IPsec config…")
    try:
        r = _config_get("/config/shared/network", api_key)
        shared = _slice_network_tree(r, scope="shared")
        for k in out: out[k].extend(shared[k])
        _emit("shared", "done",
              f"shared: {len(shared['ike_gateways'])} gateways, "
              f"{len(shared['ipsec_tunnels'])} tunnels, "
              f"{len(shared['ike_profiles'])} IKE profiles, "
              f"{len(shared['ipsec_profiles'])} IPsec profiles")
    except Exception as e:
        _emit("shared", "warn", f"shared fetch failed (continuing): {e}")

    # 2. Templates — list them once, then one fetch per template.
    _emit("templates_list", "loading", "Listing Panorama templates…")
    templates = _list_templates(api_key)
    _emit("templates_list", "done", f"Found {len(templates)} template(s).",
          current=len(templates), total=len(templates))

    for i, tpl in enumerate(templates, 1):
        _emit("template", "loading", f"Fetching template '{tpl}' ({i}/{len(templates)})…",
              current=i, total=len(templates))
        xpath = (
            f"{BASE_XPATH}/template/entry[@name='{_xp(tpl)}']"
            "/config/devices/entry[@name='localhost.localdomain']/network"
        )
        try:
            r = _config_get(xpath, api_key)
            sliced = _slice_network_tree(r, scope=f"template:{tpl}", template=tpl)
            for k in out: out[k].extend(sliced[k])
            counts = (
                f"{len(sliced['ike_gateways'])} gw, "
                f"{len(sliced['ipsec_tunnels'])} tun"
            )
            _emit("template", "done", f"{tpl}: {counts}", current=i, total=len(templates))
        except Exception as e:
            _emit("template", "warn", f"{tpl}: skipped ({e})", current=i, total=len(templates))

    # 3. Template-stacks — where firewalls actually live in most Panorama
    #    deployments. Tunnels often defined here rather than in shared templates.
    _emit("stacks_list", "loading", "Listing Panorama template-stacks…")
    stacks = _list_template_stacks(api_key)
    _emit("stacks_list", "done", f"Found {len(stacks)} template-stack(s).",
          current=len(stacks), total=len(stacks))

    for i, stack in enumerate(stacks, 1):
        _emit("stack", "loading", f"Fetching template-stack '{stack}' ({i}/{len(stacks)})…",
              current=i, total=len(stacks))
        xpath = (
            f"{BASE_XPATH}/template-stack/entry[@name='{_xp(stack)}']"
            "/config/devices/entry[@name='localhost.localdomain']/network"
        )
        try:
            r = _config_get(xpath, api_key)
            sliced = _slice_network_tree(r, scope=f"template-stack:{stack}", template=stack)
            for k in out: out[k].extend(sliced[k])
            counts = (
                f"{len(sliced['ike_gateways'])} gw, "
                f"{len(sliced['ipsec_tunnels'])} tun"
            )
            _emit("stack", "done", f"{stack}: {counts}", current=i, total=len(stacks))
        except Exception as e:
            _emit("stack", "warn", f"{stack}: skipped ({e})", current=i, total=len(stacks))

    # 4. Per-firewall config — the last place tunnels can live. Tunnels
    #    configured directly on a firewall (not pushed via Panorama shared/
    #    template/template-stack) only show up when we query that firewall's
    #    view via the `target=SERIAL` parameter. This is the same mechanism
    #    fetch_firewall_interfaces uses for the firewall-interface page.
    #    Run in parallel since 50+ firewalls × ~500ms sequential is painful.
    _emit("firewalls_list", "loading", "Listing managed firewalls…")
    firewalls: list[tuple[str, str]] = []
    try:
        for d in get_managed_devices(api_key):
            serial = d.get("serial")
            host = d.get("hostname") or serial
            if serial:
                firewalls.append((serial, host))
    except Exception as e:
        _emit("firewalls_list", "warn", f"Could not list firewalls: {e}")
    _emit("firewalls_list", "done",
          f"Found {len(firewalls)} managed firewall(s).",
          current=len(firewalls), total=len(firewalls))

    if firewalls:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Disambiguate HA-pair hostnames in the log: same hostname can map
        # to two serials (active + passive). Tag with the serial suffix when
        # we detect a collision.
        from collections import Counter
        host_count = Counter(h for _, h in firewalls)
        def _label(serial: str, hostname: str) -> str:
            return f"{hostname}/{serial[-6:]}" if host_count[hostname] > 1 else hostname

        def _fetch_one(serial: str, hostname: str):
            xpath = "/config/devices/entry[@name='localhost.localdomain']/network"
            net = _config_get_targeted(xpath, api_key, serial, timeout=20)
            if net is None:
                return None, "no response"
            return _slice_network_tree(
                net, scope=f"firewall:{_label(serial, hostname)}",
                template=_label(serial, hostname),
            ), None

        completed = 0
        # 10-worker pool — Panorama handles concurrent target= queries fine.
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(_fetch_one, s, h): (s, h) for s, h in firewalls}
            for fut in as_completed(futures):
                completed += 1
                serial, hostname = futures[fut]
                label = _label(serial, hostname)
                try:
                    sliced, err = fut.result()
                except Exception as e:
                    sliced, err = None, str(e)
                if sliced is None:
                    _emit("firewall", "warn",
                          f"{label}: skipped ({err})",
                          current=completed, total=len(firewalls))
                    continue
                for k in out: out[k].extend(sliced[k])
                _emit("firewall", "done",
                      f"{label}: {len(sliced['ike_gateways'])} gw, "
                      f"{len(sliced['ipsec_tunnels'])} tun",
                      current=completed, total=len(firewalls))

    # ── Dedup: same tunnel can surface from multiple scopes (e.g. a tunnel
    #    defined in template:X AND in firewall:Y where Y uses X). Firewall
    #    scope wins because it represents the as-deployed view. HA pairs that
    #    mirror tunnels collapse here too (same name + same peer).
    raw_counts = {k: len(v) for k, v in out.items()}
    out = _dedup_palo_inventory(out)
    dedup_counts = {k: len(v) for k, v in out.items()}
    if raw_counts != dedup_counts:
        _emit("dedup", "done",
              f"Deduplicated: "
              f"{raw_counts['ike_gateways']}→{dedup_counts['ike_gateways']} gateways, "
              f"{raw_counts['ipsec_tunnels']}→{dedup_counts['ipsec_tunnels']} tunnels, "
              f"{raw_counts['ike_profiles']}→{dedup_counts['ike_profiles']} IKE profiles, "
              f"{raw_counts['ipsec_profiles']}→{dedup_counts['ipsec_profiles']} IPsec profiles.")

    _emit("done", "done",
          f"Palo done: {len(out['ike_gateways'])} gateways, "
          f"{len(out['ipsec_tunnels'])} tunnels.")
    return out


def _dedup_palo_inventory(palo: dict) -> dict:
    """Collapse duplicate gateways/tunnels/profiles surfaced by multiple scopes.

    Dedup keys:
      - gateways:       (name, peer_address)   — same gateway = same name + same peer
      - ipsec_tunnels:  (name, ike_gateway)    — same tunnel = same name + same upstream gateway
      - profiles:       (name,)                — profile names are globally unique-ish

    For each key, prefer the firewall-scoped entry (`scope` starts with
    `firewall:`) because that's the as-deployed view. Templates/stacks are
    intent; per-firewall is reality.
    """
    def _prefer_firewall(existing: dict, candidate: dict) -> dict:
        if candidate.get("scope", "").startswith("firewall:"):
            return candidate
        return existing

    gw_map: dict[tuple, dict] = {}
    for gw in palo.get("ike_gateways", []):
        key = (gw.get("name", ""), gw.get("peer_address", ""))
        gw_map[key] = _prefer_firewall(gw_map.get(key, gw), gw)

    tun_map: dict[tuple, dict] = {}
    for t in palo.get("ipsec_tunnels", []):
        key = (t.get("name", ""), t.get("ike_gateway", ""))
        tun_map[key] = _prefer_firewall(tun_map.get(key, t), t)

    ikep_map: dict[str, dict] = {}
    for p in palo.get("ike_profiles", []):
        key = p.get("name", "")
        ikep_map[key] = _prefer_firewall(ikep_map.get(key, p), p)

    ipsecp_map: dict[str, dict] = {}
    for p in palo.get("ipsec_profiles", []):
        key = p.get("name", "")
        ipsecp_map[key] = _prefer_firewall(ipsecp_map.get(key, p), p)

    return {
        "ike_gateways":   list(gw_map.values()),
        "ipsec_tunnels":  list(tun_map.values()),
        "ike_profiles":   list(ikep_map.values()),
        "ipsec_profiles": list(ipsecp_map.values()),
    }
