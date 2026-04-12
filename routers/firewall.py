from fastapi.responses import HTMLResponse
"""routers/firewall.py — Panorama security policy lookup endpoints."""

import asyncio
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

@router.get("/device-groups")
async def list_device_groups(request: Request, session: SessionEntry = Depends(require_auth)):
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    dgs = cache.get("pan_device_groups")
    if dgs is None:
        dgs = await loop.run_in_executor(None, pc.get_device_groups, key)
        cache.set("pan_device_groups", dgs, PAN_TTL)

    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_device_groups.html", {"items": dgs})
    return {"items": dgs}

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
    all_dgs = cache.get("pan_device_groups")
    if all_dgs is None:
        all_dgs = await loop.run_in_executor(None, pc.get_device_groups, key)
        cache.set("pan_device_groups", all_dgs, PAN_TTL)
    addr_data = cache.get("pan_addr")
    if addr_data is None:
        addr_data = await loop.run_in_executor(None, pc.get_address_objects_and_groups, key, all_dgs)
        cache.set("pan_addr", addr_data, PAN_TTL)
    objects, groups = addr_data
    svc_data = cache.get("pan_svc")
    if svc_data is None:
        svc_data = await loop.run_in_executor(None, pc.get_services, key, all_dgs)
        cache.set("pan_svc", svc_data, PAN_TTL)
    svc_obj, svc_grp = svc_data
    rules_cache = cache.get("pan_rules")
    if rules_cache is None:
        all_rules = await loop.run_in_executor(None, pc.get_all_security_rules, key, all_dgs)
        by_dg: dict[str, list] = {}
        for rule in all_rules:
            dg = rule.get("device_group", "shared")
            by_dg.setdefault(dg, []).append(rule)
        rules_cache = {"dg_order": all_dgs, "by_dg": by_dg}
        cache.set("pan_rules", rules_cache, PAN_TTL)
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
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    devices = cache.get("pan_interfaces")
    if devices is None:
        devices = await loop.run_in_executor(None, pc.fetch_firewall_interfaces, key)
        cache.set("pan_interfaces", devices, TTL_PAN_INTERFACES)

    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})
    return {"items": devices, "total": len(devices)}

@router.post("/interfaces/refresh")
async def refresh_firewall_interfaces(request: Request, session: SessionEntry = Depends(require_auth)):
    cache.invalidate("pan_interfaces")
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, pc.fetch_firewall_interfaces, key)
    cache.set("pan_interfaces", devices, TTL_PAN_INTERFACES)
    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})
    return {"items": devices, "total": len(devices)}

@router.get("/devices")
async def list_managed_devices(request: Request, session: SessionEntry = Depends(require_auth)):
    cached = cache.get("pan_managed_devices")
    if cached is None:
        key  = _get_key(session)
        loop = asyncio.get_event_loop()
        cached = await loop.run_in_executor(None, pc.get_managed_devices, key)
        cache.set("pan_managed_devices", cached, PAN_TTL)
    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_devices.html", {"items": cached})
    return {"items": cached}

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
    from main import templates
    return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": list(grouped.values())})

@router.get("/templates", response_class=HTMLResponse)
async def list_panorama_templates_ui(request: Request, session: SessionEntry = Depends(require_auth)):
    templates_list = ["Standard-Branch-Template", "HQ-DataCenter-Template", "Remote-VPN-Template"]
    return HTMLResponse(f"""
        <div class="card shadow-sm border-0 animate-fade-in">
            <div class="card-header bg-navy text-white fw-bold">Panorama Templates</div>
            <div class="card-body p-0">
                <ul class="list-group list-group-flush">
                    {"".join(f'<li class="list-group-item"><i class="fas fa-layer-group text-primary me-2"></i>{t}</li>' for t in templates_list)}
                </ul>
            </div>
        </div>
    """)
