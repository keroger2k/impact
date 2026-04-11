from fastapi.responses import HTMLResponse
"""routers/firewall.py — Panorama security policy lookup endpoints."""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Form
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
    """
    Reconstruct an ordered flat rule list from the by_dg cache structure,
    preserving Panorama evaluation order:
      shared pre → per-DG pre (in dg_order) → per-DG post (in dg_order) → shared post
    If target_dgs is provided, only include those device groups (plus shared).
    """
    by_dg    = rules_cache["by_dg"]
    dg_order = rules_cache["dg_order"]
    include  = set(target_dgs) if target_dgs else None

    result = []

    # 1. Shared pre-rules
    for r in by_dg.get("shared", []):
        if r.get("rulebase") == "pre":
            result.append(r)

    # 2. Per-DG pre-rules (in original fetch order)
    for dg in dg_order:
        if include and dg not in include:
            continue
        for r in by_dg.get(dg, []):
            if r.get("rulebase") == "pre":
                result.append(r)

    # 3. Per-DG post-rules
    for dg in dg_order:
        if include and dg not in include:
            continue
        for r in by_dg.get(dg, []):
            if r.get("rulebase") == "post":
                result.append(r)

    # 4. Shared post-rules
    for r in by_dg.get("shared", []):
        if r.get("rulebase") == "post":
            result.append(r)

    return result


@router.get("/device-groups")
async def list_device_groups(request: Request, session: SessionEntry = Depends(require_auth)):
    cached = cache.get("pan_device_groups")
    if cached is not None:
        return {"items": cached}
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    dgs  = await loop.run_in_executor(None, pc.get_device_groups, key)
    cache.set("pan_device_groups", dgs, PAN_TTL)
    return {"items": dgs}
    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_device_groups.html", {"items": dgs})


@router.post("/lookup")
async def policy_lookup(req: PolicyLookupRequest, session: SessionEntry = Depends(require_auth)):
    """
    Find all Panorama security rules matching a src/dst IP pair,
    with optional port/protocol and device-group filtering.
    """
    import ipaddress
    for field, val in [("src_ip", req.src_ip), ("dst_ip", req.dst_ip)]:
        try:
            ipaddress.ip_address(val)
        except ValueError:
            raise HTTPException(400, f"'{val}' is not a valid IP address")

    if req.dst_port is not None and not (1 <= req.dst_port <= 65535):
        raise HTTPException(400, "dst_port must be between 1 and 65535")

    key  = _get_key(session)
    loop = asyncio.get_event_loop()

    # All device groups (needed to populate the full cache)
    all_dgs = cache.get("pan_device_groups")
    if all_dgs is None:
        all_dgs = await loop.run_in_executor(None, pc.get_device_groups, key)
        cache.set("pan_device_groups", all_dgs, PAN_TTL)

    # Address objects — always fetched for ALL device groups
    addr_data = cache.get("pan_addr")
    if addr_data is None:
        addr_data = await loop.run_in_executor(None, pc.get_address_objects_and_groups, key, all_dgs)
        cache.set("pan_addr", addr_data, PAN_TTL)
    objects, groups = addr_data

    # Service objects — always fetched for ALL device groups
    svc_data = cache.get("pan_svc")
    if svc_data is None:
        svc_data = await loop.run_in_executor(None, pc.get_services, key, all_dgs)
        cache.set("pan_svc", svc_data, PAN_TTL)
    svc_obj, svc_grp = svc_data

    # Rules — fetched for ALL device groups, stored keyed by device group
    rules_cache = cache.get("pan_rules")
    if rules_cache is None:
        all_rules = await loop.run_in_executor(None, pc.get_all_security_rules, key, all_dgs)
        by_dg: dict[str, list] = {}
        for rule in all_rules:
            dg = rule.get("device_group", "shared")
            by_dg.setdefault(dg, []).append(rule)
        rules_cache = {"dg_order": all_dgs, "by_dg": by_dg}
        cache.set("pan_rules", rules_cache, PAN_TTL)

    # Filter to requested device groups (or use all)
    target_dgs = req.device_groups or None
    rules = _flatten_rules(rules_cache, target_dgs)

    # Match
    matches = pc.find_matching_rules(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        rules=rules,
        objects=objects,
        groups=groups,
        svc_obj=svc_obj,
        svc_grp=svc_grp,
        dst_port=req.dst_port,
        proto=req.protocol,
        include_disabled=req.include_disabled,
    )

    if not req.show_all and matches:
        matches = [matches[0]]

    effective = next((m for m in matches if not m.get("disabled")), None)

    # Resolve address + service objects for each match
    for m in matches:
        resolved_src = {}
        for name in m.get("source", []):
            if name != "any":
                resolved_src[name] = pc.resolve_name(name, objects, groups)
        resolved_dst = {}
        for name in m.get("destination", []):
            if name != "any":
                resolved_dst[name] = pc.resolve_name(name, objects, groups)
        resolved_svc = {}
        for name in m.get("service", []):
            if name not in ("any", "application-default"):
                resolved_svc[name] = [
                    {"protocol": p, "ports": pt}
                    for p, pt in pc.resolve_service(name, svc_obj, svc_grp)
                ]
        m["resolved_source"]      = resolved_src
        m["resolved_destination"] = resolved_dst
        m["resolved_service"]     = resolved_svc

    return {
        "src_ip":           req.src_ip,
        "dst_ip":           req.dst_ip,
        "dst_port":         req.dst_port,
        "protocol":         req.protocol,
        "rules_searched":   len(rules),
        "match_count":      len(matches),
        "traffic_decision": (effective or {}).get("action", "implicit-deny"),
        "matches":          matches,
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
    """
    Return all managed firewall interface IPs (IPv4 + IPv6) from Panorama.
    Results are cached for 7 days and persisted to disk.
    Each item contains device metadata plus a list of interface objects.
    """
    cached = cache.get("pan_interfaces")
    if cached is not None:
        return {"items": cached, "total": len(cached)}

    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, pc.fetch_firewall_interfaces, key)
    cache.set("pan_interfaces", devices, TTL_PAN_INTERFACES)
    return {"items": devices, "total": len(devices)}
    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_interfaces.html", {"items": devices})


@router.post("/interfaces/refresh")
async def refresh_firewall_interfaces(session: SessionEntry = Depends(require_auth)):
    """Bust the firewall interface inventory cache and re-fetch immediately."""
    cache.invalidate("pan_interfaces")
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, pc.fetch_firewall_interfaces, key)
    cache.set("pan_interfaces", devices, TTL_PAN_INTERFACES)
    return {"status": "ok", "total": len(devices)}


@router.get("/devices")
async def list_managed_devices(request: __import__("fastapi").Request, session: SessionEntry = Depends(require_auth)):
    """Fetch list of firewalls managed by Panorama."""
    logger.info("=== list_managed_devices endpoint called ===")
    cached = cache.get("pan_managed_devices")
    if cached is None:
        logger.info("Cache miss, fetching devices from Panorama...")
        key  = _get_key(session)
        loop = asyncio.get_event_loop()
        cached = await loop.run_in_executor(None, pc.get_managed_devices, key)
        cache.set("pan_managed_devices", cached, PAN_TTL)
    
    if request.headers.get("HX-Request"):
        from main import templates
        return templates.TemplateResponse(request, "partials/firewall_devices.html", {"items": cached})
    return {"items": cached}


@router.get("/devices/test")
async def test_devices(session: SessionEntry = Depends(require_auth)):
    """Test endpoint to verify device fetching works."""
    logger.info("=== test_devices endpoint called ===")
    try:
        key = _get_key(session)
        logger.info(f"Got API key: {key[:20]}...")
        
        loop = asyncio.get_event_loop()
        devices = await loop.run_in_executor(None, pc.get_managed_devices, key)
        logger.info(f"Raw result from get_managed_devices: {devices}")
        logger.info(f"Type: {type(devices)}, Length: {len(devices)}")
        
        return {
            "success": True,
            "device_count": len(devices),
            "devices": devices,
            "cache_key": "pan_managed_devices"
        }
    except Exception as e:
        logger.error(f"Test endpoint error: {e}", exc_info=True)
        return {"success": False, "error": str(e)}

@router.get("/device-policies/{device_serial}")
async def get_device_policies(
    device_serial: str,
    session: SessionEntry = Depends(require_auth)
):
    """Fetch security policies for a specific managed firewall device."""
    cache_key = f"pan_device_policies_{device_serial}"
    cached = cache.get(cache_key)
    if cached is not None:
        return {"serial": device_serial, "policies": cached}
    
    key  = _get_key(session)
    loop = asyncio.get_event_loop()
    
    # Get device groups for context
    all_dgs = cache.get("pan_device_groups")
    if all_dgs is None:
        all_dgs = await loop.run_in_executor(None, pc.get_device_groups, key)
        cache.set("pan_device_groups", all_dgs, PAN_TTL)
    
    # Fetch policies specific to this device
    policies = await loop.run_in_executor(
        None,
        pc.get_device_policies,
        key,
        device_serial,
        all_dgs,
    )
    
    cache.set(cache_key, policies, PAN_TTL)
    return {"serial": device_serial, "policies": policies}


@router.get("/device-vsys/{device_serial}")
async def get_device_vsys(
    device_serial: str,
    session: SessionEntry = Depends(require_auth)
):
    """Fetch list of virtual systems for a managed firewall device."""
    cache_key = f"pan_device_vsys_{device_serial}"
    cached = cache.get(cache_key)
    if cached is not None:
        return {"serial": device_serial, "vsys": cached}
    
    key = _get_key(session)
    loop = asyncio.get_event_loop()
    vsys_list = await loop.run_in_executor(None, pc.get_device_vsys, key, device_serial)
    
    cache.set(cache_key, vsys_list, PAN_TTL)
    return {"serial": device_serial, "vsys": vsys_list}


@router.get("/device-vsys-policies/{device_serial}/{vsys_name}")
async def get_device_vsys_policies(
    device_serial: str,
    vsys_name: str,
    session: SessionEntry = Depends(require_auth)
):
    """Fetch security policies for a specific vsys on a managed firewall device."""
    cache_key = f"pan_device_vsys_policies_{device_serial}_{vsys_name}"
    cached = cache.get(cache_key)
    if cached is not None:
        return {"serial": device_serial, "vsys": vsys_name, "policies": cached}
    
    key = _get_key(session)
    loop = asyncio.get_event_loop()
    
    # Fetch policies for this vsys directly (no device group lookup needed)
    policies = await loop.run_in_executor(
        None,
        pc.get_device_vsys_policies,
        key,
        device_serial,
        vsys_name,
    )
    
    cache.set(cache_key, policies, PAN_TTL)
    return {"serial": device_serial, "vsys": vsys_name, "policies": policies}



