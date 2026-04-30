from fastapi.responses import HTMLResponse, Response
"""routers/firewall.py — Panorama security policy lookup endpoints."""

import asyncio
import csv
import io
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Form, Query
from pydantic import BaseModel

import auth as auth_module
import clients.panorama as pc
from auth import SessionEntry, require_auth
from cache import cache, TTL_PAN_INTERFACES

router = APIRouter()
logger = logging.getLogger(__name__)

PAN_TTL = 3600

class PolicyLookupRequest(BaseModel):
    src_ip:           str
    dst_ip:           str
    dst_port:         Optional[int] = None
    protocol:         str = "any"
    device_groups:    list[str] = []
    include_disabled: bool = False
    show_all:         bool = True

def _get_key(session: SessionEntry) -> str:
    try:
        return auth_module.get_panorama_key_for_session(session)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Panorama authentication failed: {e}")

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
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", lambda: pc.get_device_groups(key), PAN_TTL)

    if dgs is None: dgs = []

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_device_groups.html", {"items": dgs})
    return {"items": dgs, "total": len(dgs)}

@router.post("/lookup")
async def policy_lookup(req: PolicyLookupRequest, session: SessionEntry = Depends(require_auth)):
    import ipaddress
    for field, val in [("src_ip", req.src_ip), ("dst_ip", req.dst_ip)]:
        try:
            ipaddress.ip_address(val)
        except ValueError:
            raise HTTPException(400, f"'{val}' is not a valid IP address")
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    all_dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", lambda: pc.get_device_groups(key), PAN_TTL)

    if all_dgs is None: all_dgs = []

    if req.device_groups:
        invalid = [dg for dg in req.device_groups if dg not in all_dgs]
        if invalid:
            raise HTTPException(400, f"Unknown device groups: {invalid}")

    addr_data = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_addr", lambda: pc.get_address_objects_and_groups(key, all_dgs), PAN_TTL)
    objects, groups = addr_data if addr_data else ({}, {})

    svc_data = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_svc", lambda: pc.get_services(key, all_dgs), PAN_TTL)
    svc_obj, svc_grp = svc_data if svc_data else ({}, {})

    def load_rules():
        all_rules = pc.get_all_security_rules(key, all_dgs)
        by_dg: dict[str, list] = {}
        for rule in all_rules:
            dg = rule.get("device_group", "shared")
            by_dg.setdefault(dg, []).append(rule)
        return {"dg_order": all_dgs, "by_dg": by_dg}

    rules_cache = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_rules", load_rules, PAN_TTL)
    if not rules_cache: rules_cache = {"dg_order": [], "by_dg": {}}

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

@router.get("/cache/info")
async def firewall_cache_info():
    keys     = cache.keys_for_prefix("pan_")
    infos    = {k: cache.cache_info(k) for k in keys}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}

@router.post("/cache/refresh")
async def refresh_firewall_cache():
    cache.invalidate_prefix("pan_")
    return {"status": "firewall cache cleared"}

@router.get("/interfaces")
async def list_firewall_interfaces(request: Request, session: SessionEntry = Depends(require_auth)):
    from cache import TTL_PAN_INTERFACES
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
        key  = _get_key(session)
        loop = asyncio.get_event_loop()
        devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_interfaces", lambda: pc.fetch_firewall_interfaces(key), TTL_PAN_INTERFACES)
        if devices is None:
            devices = []
    except Exception as e:
        logger.error(f"Failed to list firewall interfaces: {e}")
        raise HTTPException(500, f"Panorama Error: {str(e)}")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})
    return {"items": devices, "total": len(devices)}

@router.post("/interfaces/refresh")
async def refresh_firewall_interfaces(request: Request, session: SessionEntry = Depends(require_auth)):
    from cache import TTL_PAN_INTERFACES
    cache.invalidate("pan_interfaces")
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_interfaces", lambda: pc.fetch_firewall_interfaces(key), TTL_PAN_INTERFACES)
    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})
    return {"items": devices, "total": len(devices)}

@router.get("/devices")
async def list_managed_devices(request: Request, session: SessionEntry = Depends(require_auth)):
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    cached = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_managed_devices", lambda: pc.get_managed_devices(key), PAN_TTL)

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

    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    all_dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", lambda: pc.get_device_groups(key), PAN_TTL)

    if all_dgs is None: all_dgs = []

    if device_group not in all_dgs and device_group != "shared":
        raise HTTPException(400, f"Unknown device group: {device_group}")

    if DEV_MODE:
        rules = [r for r in MOCK_FIREWALL_RULES if r.get("device_group") == device_group or r.get("device_group") == "shared"]
    else:
        def _build_rules():
            all_rules = pc.get_all_security_rules(key, all_dgs)
            by_dg: dict[str, list] = {}
            for rule in all_rules:
                dg = rule.get("device_group", "shared")
                by_dg.setdefault(dg, []).append(rule)
            return {"dg_order": all_dgs, "by_dg": by_dg}

        rules_cache = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_rules", _build_rules, PAN_TTL)
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

    key  = _get_key(session)
    loop = asyncio.get_event_loop()

    all_dgs = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "pan_device_groups", lambda: pc.get_device_groups(key), PAN_TTL
    )
    if all_dgs is None: all_dgs = []

    if DEV_MODE:
        rules_cache = MOCK_PAN_RULES_CACHE
    else:
        def _build_rules():
            all_rules = pc.get_all_security_rules(key, all_dgs)
            by_dg: dict[str, list] = {}
            for rule in all_rules:
                dg = rule.get("device_group", "shared")
                by_dg.setdefault(dg, []).append(rule)
            return {"dg_order": all_dgs, "by_dg": by_dg}
        rules_cache = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set),
            "pan_rules", _build_rules, PAN_TTL
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
            "pan_addr", lambda: pc.get_address_objects_and_groups(key, all_dgs), PAN_TTL
        )
        objects, groups = addr_data if addr_data else ({}, {})

        svc_data = await loop.run_in_executor(
            None, run_with_context(cache.get_or_set),
            "pan_svc", lambda: pc.get_services(key, all_dgs), PAN_TTL
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
