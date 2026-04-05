"""routers/firewall.py — Panorama security policy lookup endpoints."""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import clients.panorama as pc
from cache import cache

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


def _get_key():
    key = pc.get_api_key()
    if not key:
        raise HTTPException(503, "Panorama not configured. Check PANORAMA_HOST, _USERNAME, _PASSWORD in .env")
    return key


def _dgs_key(dgs: list[str]) -> str:
    return "|".join(sorted(dgs)) if dgs else "_all_"


@router.get("/device-groups")
async def list_device_groups():
    cached = cache.get("pan_device_groups")
    if cached is not None:
        return {"items": cached}
    key  = _get_key()
    loop = asyncio.get_event_loop()
    dgs  = await loop.run_in_executor(None, pc.get_device_groups, key)
    cache.set("pan_device_groups", dgs, PAN_TTL)
    return {"items": dgs}


@router.post("/lookup")
async def policy_lookup(req: PolicyLookupRequest):
    """
    Find all Panorama security rules matching a src/dst IP pair,
    with optional port/protocol filtering.
    """
    import ipaddress
    for field, val in [("src_ip", req.src_ip), ("dst_ip", req.dst_ip)]:
        try:
            ipaddress.ip_address(val)
        except ValueError:
            raise HTTPException(400, f"'{val}' is not a valid IP address")

    if req.dst_port is not None and not (1 <= req.dst_port <= 65535):
        raise HTTPException(400, "dst_port must be between 1 and 65535")

    key  = _get_key()
    loop = asyncio.get_event_loop()

    # Resolve target device groups
    all_dgs = cache.get("pan_device_groups")
    if all_dgs is None:
        all_dgs = await loop.run_in_executor(None, pc.get_device_groups, key)
        cache.set("pan_device_groups", all_dgs, PAN_TTL)

    target_dgs = req.device_groups or all_dgs
    dk         = _dgs_key(target_dgs)

    # Load address objects (cached per device-group set)
    addr_key = f"pan_addr_{dk}"
    addr_data = cache.get(addr_key)
    if addr_data is None:
        addr_data = await loop.run_in_executor(None, pc.get_address_objects_and_groups, key, target_dgs)
        cache.set(addr_key, addr_data, PAN_TTL)
    objects, groups = addr_data

    # Load service objects
    svc_key  = f"pan_svc_{dk}"
    svc_data = cache.get(svc_key)
    if svc_data is None:
        svc_data = await loop.run_in_executor(None, pc.get_services, key, target_dgs)
        cache.set(svc_key, svc_data, PAN_TTL)
    svc_obj, svc_grp = svc_data

    # Load rules
    rules_key = f"pan_rules_{dk}"
    rules     = cache.get(rules_key)
    if rules is None:
        rules = await loop.run_in_executor(None, pc.get_all_security_rules, key, target_dgs)
        cache.set(rules_key, rules, PAN_TTL)

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
        "src_ip":          req.src_ip,
        "dst_ip":          req.dst_ip,
        "dst_port":        req.dst_port,
        "protocol":        req.protocol,
        "rules_searched":  len(rules),
        "match_count":     len(matches),
        "traffic_decision": (effective or {}).get("action", "implicit-deny"),
        "matches":         matches,
    }


@router.get("/cache/info")
async def firewall_cache_info():
    keys  = cache.keys_for_prefix("pan_")
    infos = {k: cache.cache_info(k) for k in keys}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}


@router.post("/cache/refresh")
async def refresh_firewall_cache():
    cache.invalidate_prefix("pan_")
    return {"status": "firewall cache cleared"}
