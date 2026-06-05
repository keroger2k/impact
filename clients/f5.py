"""
clients/f5.py — F5 BIG-IP iControl REST client (READ-ONLY).

╔══════════════════════════════════════════════════════════════════════════╗
║  READ-ONLY CONTRACT                                                        ║
║                                                                            ║
║  This module issues ONLY HTTP GET requests against the BIG-IP iControl     ║
║  REST API. There is NO POST / PUT / PATCH / DELETE code path anywhere in   ║
║  this file — every network call funnels through the single private        ║
║  ``_get()`` helper. The F5 integration can read inventory / config /       ║
║  state, but can never create, modify, or delete anything on an F5.         ║
║  ``tests/test_f5.py`` enforces this by asserting no mutating HTTP verb     ║
║  appears in this module's source.                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

Auth: HTTP Basic Auth with the logged-in user's AD credentials (the F5s use
remote LDAP/AD auth), passed per request. We deliberately avoid token auth
(``POST /mgmt/shared/authn/login``) so that not even a session-token write
ever occurs — Basic Auth keeps the read-only contract absolute.

API base: ``https://<host>/mgmt/tm/...`` — returns JSON. SSL verification is
disabled by default (self-signed certs); override with IMPACT_VERIFY_SSL=true.
"""

import logging
import time

import requests
from requests.auth import HTTPBasicAuth

from clients import verify_ssl

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30


class F5APIError(Exception):
    """Domain-specific error for F5 iControl REST failures."""
    pass


class F5AuthError(F5APIError):
    """The BIG-IP rejected the credentials (401).

    Distinct from F5APIError so callers can tell bad credentials apart from a
    generic API/data failure. Subclasses F5APIError so ``except F5APIError``
    still catches it.
    """
    pass


def _host(host: str) -> str:
    """Normalize a host string to a bare hostname (strip scheme/path)."""
    return host.strip().split("/")[0]


def _short(name) -> str:
    """Strip the F5 partition path from a name (``/Common/foo`` → ``foo``)."""
    if not name:
        return ""
    return str(name).split("/")[-1]


# ──────────────────────────────────────────────────────────────────────────────
#  THE ONLY NETWORK CALL IN THIS MODULE
# ──────────────────────────────────────────────────────────────────────────────

def _get(host: str, path: str, user: str, pwd: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Issue a read-only HTTP GET against iControl REST and return parsed JSON.

    ``path`` is an iControl REST path beginning with ``/mgmt/``. This is the
    sole network primitive in the module — no other HTTP verb is used anywhere,
    which is what makes the read-only contract structural rather than a matter
    of discipline.
    """
    url = f"https://{_host(host)}{path}"
    start = time.time()
    try:
        resp = requests.get(
            url,
            auth=HTTPBasicAuth(user, pwd),
            verify=verify_ssl(),
            timeout=timeout,
        )
        duration = int((time.time() - start) * 1000)
        logger.info(f"F5 GET {path}", extra={
            "target": "F5",
            "action": "GET",
            "status": resp.status_code,
            "duration_ms": duration,
        })
        if resp.status_code == 401:
            raise F5AuthError(f"F5 authentication rejected for {_host(host)}")
        resp.raise_for_status()
        return resp.json()
    except (F5AuthError, F5APIError):
        raise
    except Exception as e:
        raise F5APIError(f"F5 GET {path} failed: {e}")


# ──────────────────────────────────────────────────────────────────────────────
#  PARSERS / HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _parse_destination(dest: str) -> tuple[str, str]:
    """Parse an F5 virtual-server ``destination`` into ``(ip, port)``.

    Formats handled::

        /Common/1.2.3.4:443      -> ("1.2.3.4", "443")
        /Common/1.2.3.4%2:443    -> ("1.2.3.4", "443")     (route domain stripped)
        /Common/1.2.3.4:0        -> ("1.2.3.4", "0")       (0 = any port)
        /Common/2001:db8::1.443  -> ("2001:db8::1", "443") (IPv6 port sep is '.')
        /Common/2001:db8::1.any  -> ("2001:db8::1", "any")
    """
    if not dest:
        return "", ""
    # The address[:.]port lives in the last path segment.
    tail = str(dest).rsplit("/", 1)[-1]

    # IPv6 addresses contain 2+ colons and use '.' as the port separator;
    # IPv4 uses ':'. Decide by counting colons in the segment.
    if tail.count(":") > 1:
        if "." in tail:
            addr, _, port = tail.rpartition(".")
        else:
            addr, port = tail, ""
    else:
        addr, sep, port = tail.rpartition(":")
        if not sep:  # no port present
            addr, port = tail, ""

    addr = addr.split("%")[0]  # drop route-domain suffix
    return addr, port


def _vs_status(v: dict) -> str:
    """Admin status of a virtual server. F5 returns either ``enabled: true`` or
    ``disabled: true`` (only one key present)."""
    if v.get("enabled"):
        return "enabled"
    if v.get("disabled"):
        return "disabled"
    return "unknown"


# ──────────────────────────────────────────────────────────────────────────────
#  COLLECTORS (all read-only GETs)
# ──────────────────────────────────────────────────────────────────────────────

def get_inventory(host: str, ip: str, user: str, pwd: str) -> dict:
    """Device inventory from ``cm/device`` (the local/self device)."""
    data = _get(host, "/mgmt/tm/cm/device", user, pwd)
    items = data.get("items", []) or []
    # cm/device lists every peer in the trust group; pick the local unit.
    dev = next((d for d in items if str(d.get("selfDevice")).lower() == "true"), None)
    if dev is None:
        dev = items[0] if items else {}

    hostname = dev.get("hostname") or ip
    return {
        "id": f"f5_{hostname}",
        "hostname": hostname,
        "managementIpAddress": dev.get("managementIp") or ip,
        "model": dev.get("marketingName") or dev.get("platformId") or "F5 BIG-IP",
        "platformId": "F5 BIG-IP",
        "version": dev.get("version") or "N/A",
        "edition": dev.get("edition") or "",
        "failoverState": dev.get("failoverState") or "unknown",
        "chassisId": dev.get("chassisId") or "",
        "reachabilityStatus": "Reachable",
        "source": "F5",
        "lastUpdateTime": int(time.time() * 1000),
    }


def get_self_ips(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """Self-IPs (the F5's L3 interface addresses) from ``net/self``."""
    data = _get(host, "/mgmt/tm/net/self", user, pwd)
    out = []
    for s in data.get("items", []) or []:
        out.append({
            "hostname": hostname,
            "name": _short(s.get("name")),
            "address": s.get("address"),          # "x.x.x.x/prefix"
            "vlan": _short(s.get("vlan")),
            "trafficGroup": _short(s.get("trafficGroup")),
            "floating": s.get("floating") or "disabled",
            "allowService": s.get("allowService"),  # "all"/"none"/list
        })
    return out


def get_vlans(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """VLANs (with member interfaces expanded inline)."""
    data = _get(host, "/mgmt/tm/net/vlan?expandSubcollections=true", user, pwd)
    out = []
    for v in data.get("items", []) or []:
        members = [
            _short(m.get("name"))
            for m in (v.get("interfacesReference", {}) or {}).get("items", []) or []
        ]
        out.append({
            "hostname": hostname,
            "name": _short(v.get("name")),
            "tag": v.get("tag"),
            "mtu": v.get("mtu"),
            "interfaces": ", ".join(members),
        })
    return out


def get_interfaces(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """Physical interfaces from ``net/interface``."""
    data = _get(host, "/mgmt/tm/net/interface", user, pwd)
    out = []
    for i in data.get("items", []) or []:
        out.append({
            "hostname": hostname,
            "name": _short(i.get("name")),
            "mac": i.get("macAddress"),
            "enabled": i.get("enabled"),
            "mediaActive": i.get("mediaActive") or "none",
            "mtu": i.get("mtu"),
        })
    return out


def get_virtuals(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """Virtual servers (VIPs) from ``ltm/virtual``, enriched best-effort with
    availability from ``ltm/virtual/stats`` (a single extra GET)."""
    data = _get(host, "/mgmt/tm/ltm/virtual", user, pwd)

    # Availability map keyed by short VS name (best-effort; never fatal).
    avail: dict[str, str] = {}
    try:
        stats = _get(host, "/mgmt/tm/ltm/virtual/stats", user, pwd)
        for _url, blob in (stats.get("entries", {}) or {}).items():
            entries = (blob.get("nestedStats", {}) or {}).get("entries", {}) or {}
            name = (entries.get("tmName", {}) or {}).get("description")
            state = (entries.get("status.availabilityState", {}) or {}).get("description")
            if name and state:
                avail[_short(name)] = state
    except Exception as e:
        logger.debug(f"F5 {_host(host)}: virtual stats unavailable: {e}")

    out = []
    for v in data.get("items", []) or []:
        name = _short(v.get("name"))
        vip, port = _parse_destination(v.get("destination", ""))
        out.append({
            "hostname": hostname,
            "name": name,
            "partition": v.get("partition") or "Common",
            "destination": v.get("destination", ""),
            "ip": vip,
            "port": port,
            "pool": _short(v.get("pool")) if v.get("pool") else "",
            "ipProtocol": v.get("ipProtocol") or "",
            "status": _vs_status(v),
            "availability": avail.get(name, "unknown"),
            "description": v.get("description", ""),
        })
    return out


def get_pools(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """LTM pools with their members expanded inline."""
    data = _get(host, "/mgmt/tm/ltm/pool?expandSubcollections=true", user, pwd)
    out = []
    for p in data.get("items", []) or []:
        members = []
        for m in (p.get("membersReference", {}) or {}).get("items", []) or []:
            members.append({
                "name": _short(m.get("name")),
                "address": m.get("address"),
                "state": m.get("state"),      # up / down / unchecked
                "session": m.get("session"),  # monitor-enabled / user-disabled
            })
        out.append({
            "hostname": hostname,
            "name": _short(p.get("name")),
            "partition": p.get("partition") or "Common",
            "loadBalancingMode": p.get("loadBalancingMode") or "",
            "monitor": (p.get("monitor") or "").strip(),
            "member_count": len(members),
            "members": members,
        })
    return out


def get_nodes(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """LTM nodes (the backend server IPs) from ``ltm/node``."""
    data = _get(host, "/mgmt/tm/ltm/node", user, pwd)
    out = []
    for n in data.get("items", []) or []:
        out.append({
            "hostname": hostname,
            "name": _short(n.get("name")),
            "address": n.get("address"),
            "state": n.get("state"),
            "session": n.get("session"),
        })
    return out


def get_routes(host: str, user: str, pwd: str, hostname: str) -> list[dict]:
    """Static routes from ``net/route``."""
    data = _get(host, "/mgmt/tm/net/route", user, pwd)
    out = []
    for r in data.get("items", []) or []:
        out.append({
            "hostname": hostname,
            "name": _short(r.get("name")),
            "network": r.get("network"),  # "x.x.x.x/y" or "default"
            "gw": r.get("gw") or r.get("tmInterface") or r.get("blackhole") or "",
        })
    return out


# ──────────────────────────────────────────────────────────────────────────────
#  ORCHESTRATION
# ──────────────────────────────────────────────────────────────────────────────

def collect_device(host: str, ip: str, user: str, pwd: str) -> dict:
    """Collect the full read-only bundle for one F5.

    Inventory is fetched first (and is allowed to raise — an auth failure or
    unreachable device should surface to the caller). Every other section is
    wrapped so a single failed sub-call degrades gracefully to an empty list
    rather than aborting the whole device.
    """
    inv = get_inventory(host, ip, user, pwd)
    hostname = inv["hostname"]

    def _safe(label, fn):
        try:
            return fn()
        except F5AuthError:
            raise
        except Exception as e:
            logger.warning(f"F5 {hostname}: {label} collection failed: {e}")
            return []

    return {
        "inventory":  inv,
        "self_ips":   _safe("self-ips",   lambda: get_self_ips(host, user, pwd, hostname)),
        "vlans":      _safe("vlans",       lambda: get_vlans(host, user, pwd, hostname)),
        "interfaces": _safe("interfaces", lambda: get_interfaces(host, user, pwd, hostname)),
        "virtuals":   _safe("virtuals",   lambda: get_virtuals(host, user, pwd, hostname)),
        "pools":      _safe("pools",       lambda: get_pools(host, user, pwd, hostname)),
        "nodes":      _safe("nodes",       lambda: get_nodes(host, user, pwd, hostname)),
        "routes":     _safe("routes",      lambda: get_routes(host, user, pwd, hostname)),
    }


def connectivity_check(host: str, user: str, pwd: str) -> tuple[bool, str]:
    """Return ``(ok, detail)`` — a lightweight read-only auth + version probe."""
    try:
        inv = get_inventory(host, host, user, pwd)
        return True, f"{inv['hostname']} · {inv['model']} · v{inv['version']} ({inv['failoverState']})"
    except Exception as e:
        return False, str(e)[:80]
