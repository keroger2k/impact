from fastapi.responses import HTMLResponse, Response
"""routers/firewall.py — Panorama security policy lookup endpoints."""

import asyncio
import csv
import io
import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Form, Query
from pydantic import BaseModel

import auth as auth_module
import clients.panorama as pc
from auth import SessionEntry, require_auth
from cache import cache, TTL_STANDARD

router = APIRouter()
logger = logging.getLogger(__name__)

PAN_TTL = TTL_STANDARD

class PolicyLookupRequest(BaseModel):
    src_ip:           str
    dst_ip:           str
    dst_port:         Optional[int] = None
    protocol:         str = "any"
    device_groups:    list[str] = []
    include_disabled: bool = False
    show_all:         bool = True

def _get_key(session: SessionEntry, force_refresh: bool = False) -> str:
    try:
        return auth_module.get_panorama_key_for_session(session, force_refresh=force_refresh)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Panorama authentication failed: {e}")


def _pan_loader(session: SessionEntry, op):
    """Wrap a Panorama ``op(api_key)`` as a cache loader that regenerates the
    session's API key and retries once if Panorama rejects it as stale
    (403 / Invalid Credential).

    The retry has to live *here*, inside the loader, because ``cache.get_or_set``
    swallows loader exceptions (both the cache-miss and background-refresh paths
    catch and return ``None``) — so a 403 raised by ``op`` would otherwise never
    reach the request handler to be retried, and the page would silently render
    empty until the session expired or the process restarted.
    """
    def loader():
        try:
            return op(_get_key(session))
        except pc.PanoramaAuthError:
            logger.warning("Panorama API key rejected as stale; regenerating and retrying")
            return op(_get_key(session, force_refresh=True))
    return loader

def _flatten_rules(rules_cache: dict, target_dgs: list[str] | None) -> list[dict]:
    by_dg    = rules_cache["by_dg"]
    dg_order = rules_cache["dg_order"]
    include  = set(target_dgs) if target_dgs else None
    result = []
    for r in by_dg.get("shared", []):
        if r.get("rulebase") == "pre": result.append(r)
    for dg in dg_order:
        if include and dg not in include: continue
        for r in by_dg.get(dg, []):
            if r.get("rulebase") == "pre": result.append(r)
    for dg in dg_order:
        if include and dg not in include: continue
        for r in by_dg.get(dg, []):
            if r.get("rulebase") == "post": result.append(r)
    for r in by_dg.get("shared", []):
        if r.get("rulebase") == "post": result.append(r)
    return result

from logger_config import run_with_context

@router.get("/device-groups")
async def list_device_groups(request: Request, session: SessionEntry = Depends(require_auth)):
    _get_key(session)  # fail fast on auth; loader re-fetches + auto-refreshes the key
    loop = asyncio.get_event_loop()
    dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", _pan_loader(session, pc.get_device_groups), PAN_TTL)

    if dgs is None: dgs = []

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_device_groups.html", {"items": dgs})
    return {"items": dgs, "total": len(dgs)}

async def _load_policy_context(session: SessionEntry):
    """Load device groups, address/service objects, and the rulebase via cache.

    Shared by the single-flow policy lookup and the multi-flow policy tester.
    Returns ``(all_dgs, objects, groups, svc_obj, svc_grp, rules_cache)``.
    """
    _get_key(session)  # fail fast on auth; loaders re-fetch + auto-refresh the key
    loop = asyncio.get_event_loop()
    all_dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", _pan_loader(session, pc.get_device_groups), PAN_TTL)
    if all_dgs is None: all_dgs = []

    addr_data = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_addr", _pan_loader(session, lambda key: pc.get_address_objects_and_groups(key, all_dgs)), PAN_TTL)
    objects, groups = addr_data if addr_data else ({}, {})

    svc_data = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_svc", _pan_loader(session, lambda key: pc.get_services(key, all_dgs)), PAN_TTL)
    svc_obj, svc_grp = svc_data if svc_data else ({}, {})

    def load_rules(key):
        all_rules = pc.get_all_security_rules(key, all_dgs)
        by_dg: dict[str, list] = {}
        for rule in all_rules:
            dg = rule.get("device_group", "shared")
            by_dg.setdefault(dg, []).append(rule)
        return {"dg_order": all_dgs, "by_dg": by_dg}

    rules_cache = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_rules", _pan_loader(session, load_rules), PAN_TTL)
    if not rules_cache: rules_cache = {"dg_order": [], "by_dg": {}}
    return all_dgs, objects, groups, svc_obj, svc_grp, rules_cache


@router.post("/lookup")
async def policy_lookup(req: PolicyLookupRequest, session: SessionEntry = Depends(require_auth)):
    import ipaddress
    for field, val in [("src_ip", req.src_ip), ("dst_ip", req.dst_ip)]:
        try:
            ipaddress.ip_address(val)
        except ValueError:
            raise HTTPException(400, f"'{val}' is not a valid IP address")
    all_dgs, objects, groups, svc_obj, svc_grp, rules_cache = await _load_policy_context(session)

    if req.device_groups:
        invalid = [dg for dg in req.device_groups if dg not in all_dgs]
        if invalid:
            raise HTTPException(400, f"Unknown device groups: {invalid}")

    target_dgs = req.device_groups or None
    rules = _flatten_rules(rules_cache, target_dgs)
    matches = pc.find_matching_rules(
        src_ip=req.src_ip, dst_ip=req.dst_ip, rules=rules,
        objects=objects, groups=groups, svc_obj=svc_obj, svc_grp=svc_grp,
        dst_port=req.dst_port, proto=req.protocol, include_disabled=req.include_disabled,
    )
    if not req.show_all and matches: matches = [matches[0]]
    effective = next((m for m in matches if not m.get("disabled")), None)
    for m in matches:
        resolved_src = {}
        for name in m.get("source", []):
            if name != "any": resolved_src[name] = pc.resolve_name(name, objects, groups)
        resolved_dst = {}
        for name in m.get("destination", []):
            if name != "any": resolved_dst[name] = pc.resolve_name(name, objects, groups)
        resolved_svc = {}
        for name in m.get("service", []):
            if name not in ("any", "application-default"):
                resolved_svc[name] = [{"protocol": p, "ports": pt} for p, pt in pc.resolve_service(name, svc_obj, svc_grp)]
        m["resolved_source"]      = resolved_src
        m["resolved_destination"] = resolved_dst
        m["resolved_service"]     = resolved_svc
    return {
        "src_ip": req.src_ip, "dst_ip": req.dst_ip, "dst_port": req.dst_port,
        "protocol": req.protocol, "rules_searched": len(rules),
        "match_count": len(matches), "traffic_decision": (effective or {}).get("action", "implicit-deny"),
        "matches": matches,
    }

MAX_TEST_FLOWS = 25
LIVE_TEST_CONCURRENCY = 5
# Zone/application names interpolated into the CLI string for op_via_sdk —
# conservative charset so a crafted name can't smuggle extra tokens
_CLI_NAME_RE = re.compile(r"^[\w .:/-]{1,63}$")


def _zones_for_dg(device_group: str) -> list[str]:
    """Collect known zone names for a device group from cached rules + interfaces.

    Pure cache reads (stale OK) — this feeds an autocomplete datalist, so
    last-known data beats blocking on Panorama.
    """
    zones: set[str] = set()
    rules_cache = cache.get_stale("pan_rules") or {}
    by_dg = rules_cache.get("by_dg", {})
    for dg in ("shared", device_group):
        for rule in by_dg.get(dg, []):
            for z in (rule.get("from_zones") or rule.get("from") or []):
                zones.add(z)
            for z in (rule.get("to_zones") or rule.get("to") or []):
                zones.add(z)
    for fw in cache.get_stale("pan_interfaces") or []:
        if fw.get("device_group") == device_group:
            for iface in fw.get("interfaces", []):
                if iface.get("zone"):
                    zones.add(iface["zone"])
    zones.discard("any")
    return sorted(zones, key=str.lower)


@router.get("/policy-tester", response_class=HTMLResponse)
async def policy_tester_ui(request: Request, session: SessionEntry = Depends(require_auth)):
    _get_key(session)  # fail fast on auth; loader re-fetches + auto-refreshes the key
    loop = asyncio.get_event_loop()
    dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", _pan_loader(session, pc.get_device_groups), PAN_TTL)
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/firewall_policy_tester.html", {"device_groups": dgs or []})


@router.get("/zones", response_class=HTMLResponse)
async def list_zone_options(request: Request, device_group: str = Query(""), session: SessionEntry = Depends(require_auth)):
    """Datalist <option> fragment of zone names known for a device group."""
    import html
    zones = _zones_for_dg(device_group) if device_group else []
    return HTMLResponse("".join(f'<option value="{html.escape(z, quote=True)}"></option>' for z in zones))


async def _firewalls_in_dg(session: SessionEntry, device_group: str) -> list[dict]:
    """Managed firewalls belonging to a device group.

    DG membership comes from Panorama *config* (device-group → devices, via
    get_device_to_group_mapping) — the ``device_group`` field on ``show devices
    all`` output is unreliable (often absent → "N/A"), so it's only a fallback.
    """
    _get_key(session)  # fail fast on auth; loaders re-fetch + auto-refresh the key
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_managed_devices", _pan_loader(session, pc.get_managed_devices), PAN_TTL)
    all_dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", _pan_loader(session, pc.get_device_groups), PAN_TTL)

    def load_map(key):
        return pc.get_device_to_group_mapping(key, all_dgs or [])
    mapping = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_dg_device_map", _pan_loader(session, load_map), PAN_TTL)
    mapping = mapping or {}

    return [
        d for d in (devices or [])
        if mapping.get(d.get("serial")) == device_group
        or (d.get("serial") not in mapping and d.get("device_group") == device_group)
    ]


@router.get("/firewall-options", response_class=HTMLResponse)
async def list_firewall_options(request: Request, device_group: str = Query(""), session: SessionEntry = Depends(require_auth)):
    """<option> fragment of firewalls in a device group (live-test targets).

    Connected, HA-active devices sort first; disconnected ones are shown but
    disabled — a live test needs a firewall Panorama can reach.
    """
    import html
    fws = await _firewalls_in_dg(session, device_group)

    def rank(d):
        return (
            0 if d.get("connected") is not False else 1,
            0 if (d.get("ha_state") or "").lower() == "active" else 1,
            d.get("hostname", ""),
        )
    fws.sort(key=rank)

    if not fws:
        return HTMLResponse('<option value="" selected disabled>No firewalls in this device group</option>')
    opts, selected_done = [], False
    for d in fws:
        offline = d.get("connected") is False
        bits = [b for b in (d.get("model"), f"HA {d.get('ha_state')}" if d.get("ha_enabled") else "", "disconnected" if offline else "") if b]
        label = (d.get("hostname") or d.get("serial", "")) + (f" ({', '.join(bits)})" if bits else "")
        sel = ""
        if not offline and not selected_done:
            sel, selected_done = " selected", True
        opts.append(
            f'<option value="{html.escape(d.get("serial", ""), quote=True)}"{sel}{" disabled" if offline else ""}>'
            f'{html.escape(label)}</option>'
        )
    return HTMLResponse("".join(opts))


@router.post("/policy-test")
async def policy_test(
    request: Request,
    device_group: str = Form(...),
    firewall: str = Form(...),
    src_ip:      list[str] = Form(default=[]),
    src_zone:    list[str] = Form(default=[]),
    dst_ip:      list[str] = Form(default=[]),
    dst_zone:    list[str] = Form(default=[]),
    protocol:    list[str] = Form(default=[]),
    dst_port:    list[str] = Form(default=[]),
    application: list[str] = Form(default=[]),
    session: SessionEntry = Depends(require_auth),
):
    """Run each flow as a live ``test security-policy-match`` on the selected
    firewall (proxied through Panorama) — the firewall's own policy engine is
    the verdict, no local rule matching."""
    import ipaddress
    from dev import DEV_MODE

    fws = await _firewalls_in_dg(session, device_group)
    target = next((d for d in fws if d.get("serial") == firewall), None)
    if target is None:
        raise HTTPException(400, f"Firewall {firewall} is not in device group {device_group}")
    loop = asyncio.get_event_loop()

    def _cell(values: list[str], i: int) -> str:
        return values[i].strip() if i < len(values) else ""

    results, pending = [], []
    n = min(max(len(src_ip), len(dst_ip)), MAX_TEST_FLOWS)
    for i in range(n):
        flow = {
            "src_ip":   _cell(src_ip, i),   "src_zone":    _cell(src_zone, i),
            "dst_ip":   _cell(dst_ip, i),   "dst_zone":    _cell(dst_zone, i),
            "protocol": _cell(protocol, i) or "tcp",
            "dst_port": _cell(dst_port, i), "application": _cell(application, i),
        }
        if not flow["src_ip"] and not flow["dst_ip"]:
            continue  # blank row
        row = {"index": len(results) + 1, **flow, "matched_rule": None,
               "verdict": "", "verdict_kind": "", "error": "", "cmd": ""}
        results.append(row)

        try:
            for label, val in (("source IP", flow["src_ip"]), ("destination IP", flow["dst_ip"])):
                if not val:
                    raise ValueError(f"missing {label}")
                ipaddress.ip_address(val)
            if flow["protocol"] not in ("tcp", "udp", "icmp"):
                raise ValueError(f"invalid protocol '{flow['protocol']}'")
            port = int(flow["dst_port"]) if flow["dst_port"] and flow["protocol"] != "icmp" else None
            if port is not None and not (0 < port < 65536):
                raise ValueError(f"invalid port {port}")
            for label, val in (("source zone", flow["src_zone"]), ("destination zone", flow["dst_zone"]),
                               ("application", flow["application"])):
                if val and not _CLI_NAME_RE.match(val):
                    raise ValueError(f"invalid {label} '{val}'")
        except ValueError as e:
            row["verdict"], row["verdict_kind"], row["error"] = "error", "error", str(e)
            continue
        pending.append((row, port))

    api_key = _get_key(session)
    sem = asyncio.Semaphore(LIVE_TEST_CONCURRENCY)

    async def run_one(row: dict, port: int | None) -> None:
        kwargs = dict(
            src_ip=row["src_ip"], dst_ip=row["dst_ip"], protocol=row["protocol"],
            dst_port=port, from_zone=row["src_zone"] or None,
            to_zone=row["dst_zone"] or None, application=row["application"] or None,
        )
        if DEV_MODE:
            parsed = {"ok": True, "cmd": pc.build_policy_match_cmd(**kwargs),
                      "rules": [{"name": "Mock-Rule-Allow", "action": "allow", "index": "1"}]}
        else:
            async with sem:
                parsed = await loop.run_in_executor(
                    None, run_with_context(lambda: pc.test_security_policy_match(api_key, firewall, **kwargs)))
        row["cmd"] = parsed.get("cmd", "")
        if not parsed.get("ok"):
            row["verdict"], row["verdict_kind"] = "error", "error"
            row["error"] = parsed.get("error", "live test failed")
            return
        rules = parsed.get("rules") or []
        if not rules:
            row["verdict"], row["verdict_kind"] = "no rule returned", "error"
            row["error"] = "firewall returned no matching rule"
            return
        effective = rules[0]
        row["matched_rule"] = effective
        action = effective.get("action") or "unknown"
        row["verdict"] = action
        row["verdict_kind"] = "allow" if action == "allow" else ("error" if action == "unknown" else "deny")

    await asyncio.gather(*(run_one(row, port) for row, port in pending))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_policy_test_results.html", {
            "device_group": device_group,
            "firewall": target,
            "results": results,
        })
    return {"device_group": device_group,
            "firewall": {"serial": target.get("serial"), "hostname": target.get("hostname")},
            "results": results}


# Cache management lives at POST /api/cache/refresh/panorama (routers/cache_mgmt.py,
# driven by datasets.py).

@router.get("/interfaces")
async def list_firewall_interfaces(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE
    if DEV_MODE:
        devices = [
            {
                "hostname": "FW-EAST-01",
                "serial": "SN001",
                "device": {"hostname": "FW-EAST-01"},
                "interfaces": [
                    {"name": "Ethernet1/1", "ipv4": "192.0.2.1/24", "zone": "untrust"},
                    {"name": "Ethernet1/2", "ipv4": "192.0.2.2/24", "zone": "trust"}
                ]
            }
        ]
        if request.headers.get("HX-Request"):
            from templates_module import templates
            return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})
        return {"items": devices}

    try:
        _get_key(session)  # fail fast on auth; loader re-fetches + auto-refreshes the key
        loop = asyncio.get_event_loop()
        devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_interfaces", _pan_loader(session, pc.fetch_firewall_interfaces), TTL_STANDARD)
        if devices is None:
            devices = []
    except Exception as e:
        logger.error(f"Failed to list firewall interfaces: {e}")
        raise HTTPException(500, f"Panorama Error: {str(e)}")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})
    return {"items": devices, "total": len(devices)}

@router.get("/devices")
async def list_managed_devices(request: Request, session: SessionEntry = Depends(require_auth)):
    _get_key(session)  # fail fast on auth; loader re-fetches + auto-refreshes the key
    loop = asyncio.get_event_loop()
    cached = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_managed_devices", _pan_loader(session, pc.get_managed_devices), PAN_TTL)

    if cached is None: cached = []

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_devices.html", {"items": cached})
    return {"items": cached, "total": len(cached)}

@router.get("/interfaces/search", response_class=HTMLResponse)
async def search_firewall_interfaces_ui(request: Request, ip: str = Query(...), session: SessionEntry = Depends(require_auth)):
    pan_devices = cache.get("pan_interfaces") or []
    matches = pc.search_firewall_interfaces(ip, pan_devices)
    grouped = {}
    for m in matches:
        hostname = m["device"]["hostname"]
        if hostname not in grouped:
            grouped[hostname] = {"device": m["device"], "interfaces": []}
        grouped[hostname]["interfaces"].append(m["interface"])
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": list(grouped.values())})

@router.get("/templates", response_class=HTMLResponse)
async def list_panorama_templates_ui(request: Request, session: SessionEntry = Depends(require_auth)):
    templates_list = ["Standard-Branch-Template", "HQ-DataCenter-Template", "Remote-VPN-Template"]
    from templates_module import templates
    return templates.TemplateResponse(request, "partials/firewall_templates.html", {"templates": templates_list})

@router.get("/policies/{device_group}")
async def get_device_group_policies(request: Request, device_group: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_FIREWALL_RULES

    _get_key(session)  # fail fast on auth; loaders re-fetch + auto-refresh the key
    loop = asyncio.get_event_loop()
    all_dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", _pan_loader(session, pc.get_device_groups), PAN_TTL)

    if all_dgs is None: all_dgs = []

    if device_group not in all_dgs and device_group != "shared":
        raise HTTPException(400, f"Unknown device group: {device_group}")

    if DEV_MODE:
        rules = [r for r in MOCK_FIREWALL_RULES if r.get("device_group") == device_group or r.get("device_group") == "shared"]
    else:
        def _build_rules(key):
            all_rules = pc.get_all_security_rules(key, all_dgs)
            by_dg: dict[str, list] = {}
            for rule in all_rules:
                dg = rule.get("device_group", "shared")
                by_dg.setdefault(dg, []).append(rule)
            return {"dg_order": all_dgs, "by_dg": by_dg}

        rules_cache = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_rules", _pan_loader(session, _build_rules), PAN_TTL)
        if not rules_cache: rules_cache = {"dg_order": [], "by_dg": {}}
        rules = _flatten_rules(rules_cache, [device_group])

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_policies.html", {
            "device_group": device_group,
            "items": rules
        })
    return {"items": rules, "total": len(rules), "device_group": device_group}

@router.get("/rules/export")
async def export_all_rules_csv(
    expand: bool = Query(False, description="Expand address/service object names to underlying values"),
    session: SessionEntry = Depends(require_auth),
):
    """Export every security rule across all device groups as CSV (evaluation order)."""
    from dev import DEV_MODE, MOCK_PAN_RULES_CACHE

    _get_key(session)  # fail fast on auth; loaders re-fetch + auto-refresh the key
    loop = asyncio.get_event_loop()

    all_dgs = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "pan_device_groups", _pan_loader(session, pc.get_device_groups), PAN_TTL
    )
    if all_dgs is None: all_dgs = []

    if DEV_MODE:
        rules_cache = MOCK_PAN_RULES_CACHE
    else:
        def _build_rules(key):
            all_rules = pc.get_all_security_rules(key, all_dgs)
            by_dg: dict[str, list] = {}
            for rule in all_rules:
                dg = rule.get("device_group", "shared")
                by_dg.setdefault(dg, []).append(rule)
            return {"dg_order": all_dgs, "by_dg": by_dg}
        rules_cache = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set),
            "pan_rules", _pan_loader(session, _build_rules), PAN_TTL
        )
        if not rules_cache: rules_cache = {"dg_order": [], "by_dg": {}}

    rules = _flatten_rules(rules_cache, None)

    objects: dict[str, list[str]] = {}
    groups:  dict[str, list[str]] = {}
    svc_obj: dict = {}
    svc_grp: dict = {}
    if expand and not DEV_MODE:
        addr_data = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set),
            "pan_addr", _pan_loader(session, lambda key: pc.get_address_objects_and_groups(key, all_dgs)), PAN_TTL
        )
        objects, groups = addr_data if addr_data else ({}, {})

        svc_data = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set),
            "pan_svc", _pan_loader(session, lambda key: pc.get_services(key, all_dgs)), PAN_TTL
        )
        svc_obj, svc_grp = svc_data if svc_data else ({}, {})

    def _addr_cell(names: list[str], negate: bool) -> str:
        if not names: return "any"
        if "any" in names: base = "any"
        elif expand:
            parts = []
            for n in names:
                resolved = pc.resolve_name(n, objects, groups)
                parts.append(f"{n} [{', '.join(resolved)}]" if resolved else n)
            base = "; ".join(parts)
        else:
            base = "; ".join(names)
        return f"NOT ({base})" if negate else base

    def _svc_cell(names: list[str]) -> str:
        if not names: return ""
        if expand:
            parts = []
            for n in names:
                if n in ("any", "application-default"):
                    parts.append(n)
                    continue
                resolved = pc.resolve_service(n, svc_obj, svc_grp)
                if resolved:
                    pp = ", ".join(f"{p}/{pt}" for p, pt in resolved)
                    parts.append(f"{n} [{pp}]")
                else:
                    parts.append(n)
            return "; ".join(parts)
        return "; ".join(names)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Device Group", "Rule Name", "Description",
        "Source Zone(s)", "Destination Zone(s)",
        "Source Address(es)", "Destination Address(es)",
        "Application(s)", "Service(s)", "Action",
    ])
    for r in rules:
        from_zones = r.get("from_zones") or r.get("from") or []
        to_zones   = r.get("to_zones")   or r.get("to")   or []
        writer.writerow([
            r.get("device_group", ""),
            r.get("name", ""),
            r.get("description", ""),
            "; ".join(from_zones) if from_zones else "any",
            "; ".join(to_zones)   if to_zones   else "any",
            _addr_cell(r.get("source", []),      r.get("source_negate", False)),
            _addr_cell(r.get("destination", []), r.get("dest_negate",   False)),
            "; ".join(r.get("application", [])) or "any",
            _svc_cell(r.get("service", [])),
            r.get("action", ""),
        ])

    suffix   = "expanded" if expand else "names"
    filename = f"panorama-rules-{suffix}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
