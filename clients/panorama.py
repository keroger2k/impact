"""
panorama_client.py — Cisco Panorama API client for security policy lookup.
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
            verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true",
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
            verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true",
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
            raise PanoramaAPIError(f"Panorama config GET failed ({status}): {xpath}")
        res = root.find("result")
        if res is None: raise PanoramaAPIError(f"No result in response for {xpath}")
        return res
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"Panorama config GET error ({xpath}): {e}")


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
            verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true",
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
             raise PanoramaAPIError(f"Panorama op failed: {cmd}")
        res = root.find("result")
        if res is None: raise PanoramaAPIError(f"No result in response for {cmd}")
        return res
    except Exception as e:
        if isinstance(e, PanoramaAPIError): raise e
        raise PanoramaAPIError(f"Panorama op error: {e}")


def _op_targeted(cmd: str, api_key: str, target: str) -> ET.Element | None:
    """Like _op but targets a specific managed firewall by serial number."""
    host = os.getenv("PANORAMA_HOST")
    if not host: return None
    try:
        host_clean = host.strip().split('/')[0]
        resp = requests.get(
            f"https://{host_clean}/api/",
            params={"type": "op", "cmd": cmd, "key": api_key, "target": target},
            verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true",
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
    result = _config_get(f"{BASE_XPATH}/device-group", api_key)
    # Response shape: <result><device-group><entry name="...">
    entries = result.findall("device-group/entry")
    if not entries:
        entries = result.findall("entry")
    return sorted(e.get("name", "") for e in entries if e.get("name"))


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
    except Exception: pass
    try:
        r = _config_get("/config/shared/address-group", api_key)
        groups.update(_parse_group_entries(_unwrap(r, "address-group")))
    except Exception: pass

    # Per device-group level
    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{dg}']/address", api_key)
            objects.update(_parse_address_entries(_unwrap(r, "address")))
        except Exception: pass
        try:
            r = _config_get(f"{dg_base}/entry[@name='{dg}']/address-group", api_key)
            groups.update(_parse_group_entries(_unwrap(r, "address-group")))
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
    except Exception: pass
    try:
        r = _config_get("/config/shared/service-group", api_key)
        groups.update(_parse_service_group_entries(_unwrap(r, "service-group")))
    except Exception: pass

    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{dg}']/service", api_key)
            objects.update(_parse_service_entries(_unwrap(r, "service")))
        except Exception: pass
        try:
            r = _config_get(f"{dg_base}/entry[@name='{dg}']/service-group", api_key)
            groups.update(_parse_service_group_entries(_unwrap(r, "service-group")))
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

            devices.append({
                "serial":        serial,
                "hostname":      hostname,
                "model":         model,
                "ip_address":    entry.findtext("ip-address") or "",
                "device_group":  entry.findtext("device-group") or "N/A",
                "os_version":    entry.findtext("os-version") or "",
                "ha_state":      entry.findtext("ha-state") or "",
                "ha_enabled":    entry.findtext("ha-enabled") == "yes",
            })

        devices.sort(key=lambda d: (d.get("hostname", "").lower(), d.get("model", "")))
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
    except Exception: pass

    # Per device-group pre
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{dg}']/pre-rulebase/security/rules", api_key)
            all_rules.extend(_parse_rules(_unwrap(r, "rules"), dg, "pre"))
        except Exception: pass

    # Per device-group post
    for dg in device_groups:
        try:
            r = _config_get(f"{dg_base}/entry[@name='{dg}']/post-rulebase/security/rules", api_key)
            all_rules.extend(_parse_rules(_unwrap(r, "rules"), dg, "post"))
        except Exception: pass

    # Shared post
    try:
        r = _config_get(f"{BASE_XPATH}/post-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "post"))
    except Exception: pass

    return all_rules


def get_device_to_group_mapping(api_key: str, device_groups: list[str]) -> dict[str, str]:
    """Build serial -> device group mapping."""
    mapping = {}
    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        try:
            xpath = f"{dg_base}/entry[@name='{dg}']/devices"
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
        xpath = f"/config/devices/entry[@name='{device_serial}']/vsys"
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
        r = _config_get(f"/config/devices/entry[@name='{device_serial}']/pre-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "pre"))
    except Exception: pass

    # vsys pre-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{device_serial}']/vsys/entry[@name='{vsys_name}']/pre-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), vsys_name, "pre"))
    except Exception: pass

    # vsys post-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{device_serial}']/vsys/entry[@name='{vsys_name}']/post-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), vsys_name, "post"))
    except Exception: pass

    # Device shared post-rules
    try:
        r = _config_get(f"/config/devices/entry[@name='{device_serial}']/post-rulebase/security/rules", api_key)
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


def run_diagnostics(api_key: str) -> dict[str, str]:
    """Probe Panorama API with various XPaths."""
    host, results = os.getenv("PANORAMA_HOST"), {}

    def raw_get(xpath: str) -> str:
        try:
            resp = requests.get(
                f"https://{host}/api/",
                params={"type": "config", "action": "get", "xpath": xpath, "key": api_key},
                verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true", timeout=20,
            )
            return resp.text[:3000]
        except Exception as e:
            return f"ERROR: {e}"

    def raw_op(cmd: str) -> str:
        try:
            resp = requests.get(
                f"https://{host}/api/",
                params={"type": "op", "cmd": cmd, "key": api_key},
                verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true", timeout=20,
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
