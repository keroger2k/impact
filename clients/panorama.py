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
import xml.etree.ElementTree as ET

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Module-level API key cache (survives the session, re-keyed if host changes)
_key_cache: dict[str, str] = {}

BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTION & RAW CALLS
# ──────────────────────────────────────────────────────────────────────────────

def get_api_key() -> str | None:
    """Generate and cache a Panorama API key from env credentials."""
    host = os.getenv("PANORAMA_HOST")
    user = os.getenv("DOMAIN_USERNAME")
    pwd  = os.getenv("DOMAIN_PASSWORD")

    if not all([host, user, pwd]):
        return None

    cache_key = f"{host}:{user}"
    if cache_key in _key_cache:
        return _key_cache[cache_key]

    try:
        resp = requests.get(
            f"https://{host}/api/",
            params={"type": "keygen", "user": user, "password": pwd},
            verify=False,
            timeout=15,
        )
        root   = ET.fromstring(resp.text)
        key_el = root.find(".//key")
        if key_el is not None and key_el.text:
            _key_cache[cache_key] = key_el.text
            return key_el.text
        logger.warning(f"Panorama keygen failed: {resp.text[:200]}")
    except Exception as e:
        logger.warning(f"Panorama keygen error: {e}")
    return None


def _config_get(xpath: str, api_key: str) -> ET.Element | None:
    """Panorama config GET — returns the <result> element or None."""
    host = os.getenv("PANORAMA_HOST")
    try:
        resp = requests.get(
            f"https://{host}/api/",
            params={
                "type":   "config",
                "action": "get",
                "xpath":  xpath,
                "key":    api_key,
            },
            verify=False,
            timeout=30,
        )
        root   = ET.fromstring(resp.text)
        status = root.get("status", "")
        if status != "success":
            logger.warning(f"Panorama config GET failed ({status}): {xpath}")
            return None
        return root.find("result")
    except Exception as e:
        logger.warning(f"Panorama config GET error ({xpath}): {e}")
        return None


def _op(cmd: str, api_key: str) -> ET.Element | None:
    """Panorama op command — returns the <result> element or None."""
    host = os.getenv("PANORAMA_HOST")
    try:
        resp = requests.get(
            f"https://{host}/api/",
            params={"type": "op", "cmd": cmd, "key": api_key},
            verify=False,
            timeout=30,
        )
        root = ET.fromstring(resp.text)
        return root.find("result")
    except Exception as e:
        logger.warning(f"Panorama op error: {e}")
        return None


def connectivity_check() -> tuple[bool, str]:
    """Return (ok, detail_string). Lightweight auth + version check."""
    key = get_api_key()
    if not key:
        return False, "Cannot obtain API key — check PANORAMA_HOST/USERNAME/PASSWORD"
    result = _op("<show><system><info></info></system></show>", key)
    if result is not None:
        hostname = result.findtext(".//hostname", "Unknown")
        version  = result.findtext(".//sw-version", "Unknown")
        model    = result.findtext(".//model", "")
        return True, f"{hostname}  ·  {model}  ·  PAN-OS {version}"
    return False, "API key valid but op command failed"


# ──────────────────────────────────────────────────────────────────────────────
# DEVICE GROUPS
# ──────────────────────────────────────────────────────────────────────────────

def get_device_groups(api_key: str) -> list[str]:
    """Return a list of all device group names from Panorama."""
    result = _config_get(f"{BASE_XPATH}/device-group", api_key)
    if result is None:
        return []
    # Response shape: <result><device-group><entry name="...">
    # Must search device-group/entry, NOT just entry
    entries = result.findall("device-group/entry")
    if not entries:
        # Some Panorama versions return entries directly under result
        entries = result.findall("entry")
    return sorted(e.get("name", "") for e in entries if e.get("name"))


# ──────────────────────────────────────────────────────────────────────────────
# ADDRESS OBJECTS & GROUPS
# ──────────────────────────────────────────────────────────────────────────────

def _unwrap(result, tag):
    """Unwrap Panorama's extra nesting: <result><tag><entry...> -> parent of <entry>."""
    if result is None:
        return None
    if result.find("entry") is not None:
        return result
    child = result.find(tag)
    return child if child is not None else result


def _parse_address_entries(parent):
    """Parse <address><entry name=\'...\'><ip-netmask>...</ip-netmask></entry> blocks."""
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
    Return (address_objects, address_groups) merged from:
      - /config/shared/address
      - /config/shared/address-group
      - each device group's address and address-group

    address_objects: {name: [ip_string, ...]}
    address_groups:  {name: [member_name, ...]}
    """
    objects: dict[str, list[str]] = {}
    groups:  dict[str, list[str]] = {}

    # Shared level
    r = _config_get("/config/shared/address", api_key)
    objects.update(_parse_address_entries(_unwrap(r, "address")))
    r = _config_get("/config/shared/address-group", api_key)
    groups.update(_parse_group_entries(_unwrap(r, "address-group")))

    # Per device-group level
    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        r = _config_get(f"{dg_base}/entry[@name='{dg}']/address", api_key)
        objects.update(_parse_address_entries(_unwrap(r, "address")))
        r = _config_get(f"{dg_base}/entry[@name='{dg}']/address-group", api_key)
        groups.update(_parse_group_entries(_unwrap(r, "address-group")))

    return objects, groups


def resolve_name(
    name: str,
    objects: dict[str, list[str]],
    groups:  dict[str, list[str]],
    visited: set | None = None,
) -> list[str]:
    """
    Recursively expand an address object name or group name to IP strings.
    Prevents infinite loops via the visited set.
    """
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
    "application-default": [("any", "any")],   # can't resolve without app context
    "service-http":        [("tcp", "80")],
    "service-https":       [("tcp", "443")],
}


def _parse_service_entries(parent: ET.Element | None) -> dict[str, list[tuple[str, str]]]:
    """
    Parse <service> entries into {name: [(protocol, port_str), ...]}.
    port_str may be a single port "443", a range "8080-8090", or
    a comma-separated list "80,443,8080".
    """
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
    service_objects: {name: [(protocol, port_str), ...]}
    service_groups:  {name: [member_name, ...]}
    """
    objects: dict[str, list[tuple[str, str]]] = dict(_BUILTIN_SERVICES)
    groups:  dict[str, list[str]]             = {}

    r = _config_get("/config/shared/service", api_key)
    objects.update(_parse_service_entries(_unwrap(r, "service")))
    r = _config_get("/config/shared/service-group", api_key)
    groups.update(_parse_service_group_entries(_unwrap(r, "service-group")))

    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        r = _config_get(f"{dg_base}/entry[@name='{dg}']/service", api_key)
        objects.update(_parse_service_entries(_unwrap(r, "service")))
        r = _config_get(f"{dg_base}/entry[@name='{dg}']/service-group", api_key)
        groups.update(_parse_service_group_entries(_unwrap(r, "service-group")))

    return objects, groups


def resolve_service(
    name:    str,
    svc_obj: dict[str, list[tuple[str, str]]],
    svc_grp: dict[str, list[str]],
    visited: set | None = None,
) -> list[tuple[str, str]]:
    """
    Recursively expand a service name to [(protocol, port_str), ...].
    Returns [("any","any")] for 'any' / 'application-default'.
    """
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
    """
    Check if query_port is covered by port_str.
    port_str may be: "443", "8080-8090", "80,443,8080-8090"
    """
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
    query_proto: str,          # "tcp", "udp", or "any"
    query_port:  int | None,   # None means "any port"
    service_names: list[str],
    svc_obj: dict[str, list[tuple[str, str]]],
    svc_grp: dict[str, list[str]],
) -> bool:
    """
    Return True if the query proto/port is covered by any service in service_names.
    'any' and 'application-default' always match.
    If query_port is None (user left it blank) we skip port filtering entirely.
    """
    # No port filter requested — skip service matching
    if query_port is None:
        return True

    if not service_names or "any" in service_names or "application-default" in service_names:
        return True

    for svc_name in service_names:
        for (proto, port_str) in resolve_service(svc_name, svc_obj, svc_grp):
            # Protocol check
            if proto != "any" and query_proto != "any" and proto != query_proto:
                continue
            # Port check
            if port_str == "any" or query_port is None:
                return True
            if _port_in_portstr(query_port, port_str):
                return True

    return False

def _ip_in_value(query_ip: str, value: str) -> bool:
    """
    Check whether query_ip falls within a Panorama address value.
    Supports: ip-netmask (10.0.0.0/8), ip-range (10.1.1.1-10.1.1.50),
              exact IP, FQDN (skip — can't resolve at audit time).
    """
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
        # Exact IP
        return ip == ipaddress.ip_address(value)
    except ValueError:
        return False  # FQDN or wildcard — skip


def ip_matches_address_list(
    query_ip: str,
    address_names: list[str],
    objects: dict[str, list[str]],
    groups:  dict[str, list[str]],
    negate:  bool = False,
) -> bool:
    """
    Return True if query_ip is covered by any name in address_names.
    'any' always matches. Handles negation flag.
    """
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
        name = entry.get("name", "unnamed")
        rules.append({
            "device_group": device_group,
            "rulebase":     rulebase,
            "name":         name,
            "action":       entry.findtext("action") or "allow",
            "disabled":     entry.findtext("disabled") == "yes",

            # Source
            "source":          _members(entry, "source"),
            "source_negate":   entry.findtext("negate-source") == "yes",
            "from_zones":      _members(entry, "from"),

            # Destination
            "destination":     _members(entry, "destination"),
            "dest_negate":     entry.findtext("negate-destination") == "yes",
            "to_zones":        _members(entry, "to"),

            # What
            "application":     _members(entry, "application"),
            "service":         _members(entry, "service"),

            # Meta
            "description":     entry.findtext("description") or "",
            "tag":             _members(entry, "tag"),
            "log_setting":     entry.findtext("log-setting") or "",
            "profile_group":   entry.findtext(".//profile-setting/group/member") or "",
        })
    return rules


def get_all_security_rules(
    api_key:       str,
    device_groups: list[str],
    progress_cb=None,
) -> list[dict]:
    """
    Fetch all security rules in policy evaluation order:
      1. Shared pre-rules
      2. Per-device-group pre-rules (in order)
      3. Per-device-group post-rules (in order)
      4. Shared post-rules

    progress_cb(step, total, message) — optional progress callback.
    """
    all_rules = []
    total     = 2 + len(device_groups) * 2   # shared pre/post + dg pre/post
    step      = 0

    def _progress(msg):
        nonlocal step
        step += 1
        if progress_cb:
            progress_cb(step, total, msg)

    # Shared pre
    r = _config_get(f"{BASE_XPATH}/pre-rulebase/security/rules", api_key)
    all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "pre"))
    _progress("Shared pre-rules")

    # Per device-group pre
    dg_base = f"{BASE_XPATH}/device-group"
    for dg in device_groups:
        r = _config_get(f"{dg_base}/entry[@name='{dg}']/pre-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), dg, "pre"))
        _progress(f"{dg} pre-rules")

    # Per device-group post
    for dg in device_groups:
        r = _config_get(f"{dg_base}/entry[@name='{dg}']/post-rulebase/security/rules", api_key)
        all_rules.extend(_parse_rules(_unwrap(r, "rules"), dg, "post"))
        _progress(f"{dg} post-rules")

    # Shared post
    r = _config_get(f"{BASE_XPATH}/post-rulebase/security/rules", api_key)
    all_rules.extend(_parse_rules(_unwrap(r, "rules"), "shared", "post"))
    _progress("Shared post-rules")

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
    svc_obj:     dict[str, list[tuple[str, str]]] | None = None,
    svc_grp:     dict[str, list[str]]             | None = None,
    dst_port:    int | None = None,      # None = skip port filtering
    proto:       str        = "any",     # "tcp", "udp", or "any"
    include_disabled: bool  = False,
) -> list[dict]:
    """
    Walk rules in policy-evaluation order and return those that match
    src_ip, dst_ip, and (optionally) dst_port/proto.
    Marks the first matching enabled rule as 'first_match'.
    """
    if svc_obj is None:
        svc_obj = dict(_BUILTIN_SERVICES)
    if svc_grp is None:
        svc_grp = {}

    matches        = []
    first_recorded = False

    for rule in rules:
        if rule.get("disabled") and not include_disabled:
            continue

        src_ok = ip_matches_address_list(
            src_ip, rule["source"], objects, groups, rule.get("source_negate", False)
        )
        dst_ok = ip_matches_address_list(
            dst_ip, rule["destination"], objects, groups, rule.get("dest_negate", False)
        )
        svc_ok = service_matches(proto, dst_port, rule["service"], svc_obj, svc_grp)

        if src_ok and dst_ok and svc_ok:
            r = dict(rule)
            r["first_match"] = not first_recorded
            if not first_recorded:
                first_recorded = True
            matches.append(r)

    return matches

    return matches


def run_diagnostics(api_key: str) -> dict[str, str]:
    """
    Probe several XPath and op command variations and return raw XML/text
    for each so the caller can inspect what Panorama actually returns.
    This is used to tune XPaths for a specific Panorama installation.
    """
    host    = os.getenv("PANORAMA_HOST")
    results = {}

    def raw_get(xpath: str) -> str:
        try:
            resp = requests.get(
                f"https://{host}/api/",
                params={"type": "config", "action": "get",
                        "xpath": xpath, "key": api_key},
                verify=False, timeout=20,
            )
            return resp.text[:3000]
        except Exception as e:
            return f"ERROR: {e}"

    def raw_op(cmd: str) -> str:
        try:
            resp = requests.get(
                f"https://{host}/api/",
                params={"type": "op", "cmd": cmd, "key": api_key},
                verify=False, timeout=20,
            )
            return resp.text[:3000]
        except Exception as e:
            return f"ERROR: {e}"

    # System info
    results["op: show system info"] = raw_op("<show><system><info/></system></show>")

    # Try to find device groups via several XPaths
    results["/config/devices/entry[@name='localhost.localdomain']/device-group"] = \
        raw_get("/config/devices/entry[@name='localhost.localdomain']/device-group")

    # Explicit device-group names from the above
    try:
        import xml.etree.ElementTree as _ET2
        xml_text = results["/config/devices/entry[@name='localhost.localdomain']/device-group"]
        root = _ET2.fromstring(xml_text)
        names = [e.get("name") for e in root.findall(".//device-group/entry") if e.get("name")]
        if not names:
            names = [e.get("name") for e in root.findall(".//entry") if e.get("name")]
        results["[device group names found]"] = ", ".join(names) if names else "(none)"
    except Exception as e:
        results["[device group names found]"] = f"parse error: {e}"

    results["/config/devices"] = raw_get("/config/devices")

    # Shared address objects
    results["/config/shared/address"] = raw_get("/config/shared/address")

    # Shared pre/post rulebases
    results["/config/shared/pre-rulebase/security/rules"] = \
        raw_get("/config/shared/pre-rulebase/security/rules")

    results["/config/shared/post-rulebase/security/rules"] = \
        raw_get("/config/shared/post-rulebase/security/rules")

    # Top-level config structure
    results["/config"] = raw_get("/config")

    return results

# Convenience alias for FastAPI routers
def get_client() -> str | None:
    """Return the Panorama API key (equivalent to 'client' for this API)."""
    return get_api_key()
