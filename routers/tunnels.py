"""routers/tunnels.py — Enterprise IPsec tunnel inventory.

Reads cached DNAC running-configs + Panorama IKE/IPsec objects and produces a
normalized tunnel inventory spanning IOS (DMVPN, sVTI, dVTI, policy-based) and
Palo Alto. Read-only.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

import auth as auth_module
import clients.dnac as dc
import clients.panorama as pc
from auth import SessionEntry, require_auth
from cache import (
    cache,
    TUNNEL_INVENTORY_CACHE_KEY,
    TTL_DNAC_ROUTER_CONFIGS,
    TTL_PAN_POLICY,
    TTL_TUNNEL_INVENTORY,
)
from logger_config import run_with_context
from utils.ipsec_parser import parse_ipsec_config
from utils.tunnel_inventory import build_inventory

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Loaders ──────────────────────────────────────────────────────────────────

async def _load_dnac_configs(session: SessionEntry, loop) -> dict[str, str]:
    """Reuse the shared dnac_device_configs cache key the IPAM engine populates."""
    devices = cache.get("devices") or []
    target_families = {"routers", "switches and hubs"}
    targets = [d for d in devices if (d.get("family") or "").lower() in target_families]

    def _fetch_all():
        dnac = auth_module.get_dnac_for_session(session) if session else None
        if not dnac:
            return {}
        results: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(dc.get_device_config, dnac, d["id"]): d["id"] for d in targets}
            for fut in futures:
                dev_id = futures[fut]
                try:
                    results[dev_id] = fut.result() or ""
                except Exception as e:
                    logger.warning(f"Config fetch failed for {dev_id}: {e}")
                    results[dev_id] = ""
        return results

    return await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "dnac_device_configs", _fetch_all, TTL_DNAC_ROUTER_CONFIGS,
    ) or {}


async def _load_palo(session: SessionEntry, loop) -> dict[str, list]:
    """Fetch Panorama IKE/IPsec objects, cached under pan_ike_* / pan_ipsec_*."""
    try:
        key = auth_module.get_panorama_key_for_session(session)
    except Exception as e:
        logger.warning(f"Panorama auth failed for tunnels: {e}")
        return {"ike_gateways": [], "ipsec_tunnels": [], "ike_profiles": [], "ipsec_profiles": []}

    ike_gw = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "pan_ike_gateways", lambda: pc.get_ike_gateways(key), TTL_PAN_POLICY,
    ) or []
    ipsec_tun = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "pan_ipsec_tunnels", lambda: pc.get_ipsec_tunnels(key), TTL_PAN_POLICY,
    ) or []
    ike_prof = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "pan_ike_crypto_profiles", lambda: pc.get_ike_crypto_profiles(key), TTL_PAN_POLICY,
    ) or []
    ipsec_prof = await loop.run_in_executor(
        None, run_with_context(cache.get_or_set),
        "pan_ipsec_crypto_profiles", lambda: pc.get_ipsec_crypto_profiles(key), TTL_PAN_POLICY,
    ) or []

    return {
        "ike_gateways":   ike_gw,
        "ipsec_tunnels":  ipsec_tun,
        "ike_profiles":   ike_prof,
        "ipsec_profiles": ipsec_prof,
    }


async def _build_inventory(session: SessionEntry) -> dict:
    loop = asyncio.get_event_loop()
    configs = await _load_dnac_configs(session, loop)

    parsed_ios: dict[str, dict] = {}
    for dev_id, cfg in (configs or {}).items():
        if not cfg:
            continue
        try:
            parsed_ios[dev_id] = parse_ipsec_config(cfg)
        except Exception as e:
            logger.warning(f"IPsec parse failed for {dev_id}: {e}")

    device_meta = {d["id"]: d for d in (cache.get("devices") or [])}
    palo = await _load_palo(session, loop)

    return build_inventory(parsed_ios=parsed_ios, device_meta=device_meta, palo=palo)


async def _get_or_build(session: SessionEntry) -> dict:
    cached = cache.get(TUNNEL_INVENTORY_CACHE_KEY)
    if cached:
        return cached
    inv = await _build_inventory(session)
    cache.set(TUNNEL_INVENTORY_CACHE_KEY, inv, TTL_TUNNEL_INVENTORY)
    return inv


# ── Endpoints ────────────────────────────────────────────────────────────────

def _filter_tunnels(
    tunnels: list[dict],
    *,
    q: str = "",
    ttype: str = "",
    platform: str = "",
) -> list[dict]:
    out = tunnels
    if ttype:
        out = [t for t in out if t["type"] == ttype]
    if platform:
        out = [t for t in out if t["platform"] == platform]
    if q:
        ql = q.lower()
        def match(t):
            if ql in t["name"].lower(): return True
            for ep in t["endpoints"]:
                if ql in (ep.get("device","") or "").lower(): return True
                if ql in (ep.get("peer_ip","") or "").lower(): return True
                if ql in (ep.get("local_ip","") or "").lower(): return True
                if ql in (ep.get("interface","") or "").lower(): return True
                if ql in (ep.get("description","") or "").lower(): return True
            for k, v in (t.get("tags") or {}).items():
                if ql in str(v).lower(): return True
            return False
        out = [t for t in out if match(t)]
    return out


@router.get("/inventory")
async def get_inventory(
    request: Request,
    q: str = "",
    type: str = "",
    platform: str = "",
    session: SessionEntry = Depends(require_auth),
):
    inv = await _get_or_build(session)
    tunnels = _filter_tunnels(inv["tunnels"], q=q, ttype=type, platform=platform)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/tunnels_list.html", {
            "tunnels": tunnels,
            "stats":   inv.get("stats", {}),
            "filtered": bool(q or type or platform),
        })

    return {
        "tunnels": tunnels,
        "stats":   inv.get("stats", {}),
        "built_at": inv.get("built_at"),
    }


@router.get("/detail/{tunnel_id}")
async def get_tunnel_detail(
    request: Request,
    tunnel_id: str,
    session: SessionEntry = Depends(require_auth),
):
    inv = await _get_or_build(session)
    tunnel = next((t for t in inv["tunnels"] if t["id"] == tunnel_id), None)
    if not tunnel:
        return HTMLResponse("<div class='alert alert-warning m-3'>Tunnel not found in current inventory. The data may have been refreshed.</div>", status_code=404)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/tunnel_detail.html", {
            "tunnel": tunnel,
        })
    return tunnel


@router.get("/stats")
async def get_stats(session: SessionEntry = Depends(require_auth)):
    inv = await _get_or_build(session)
    return {
        "built_at": inv.get("built_at"),
        "stats":    inv.get("stats", {}),
    }


@router.post("/refresh")
async def refresh_inventory(session: SessionEntry = Depends(require_auth)):
    cache.invalidate(TUNNEL_INVENTORY_CACHE_KEY)
    cache.invalidate("pan_ike_gateways")
    cache.invalidate("pan_ipsec_tunnels")
    cache.invalidate("pan_ike_crypto_profiles")
    cache.invalidate("pan_ipsec_crypto_profiles")
    inv = await _build_inventory(session)
    cache.set(TUNNEL_INVENTORY_CACHE_KEY, inv, TTL_TUNNEL_INVENTORY)
    return {"status": "ok", "stats": inv.get("stats", {}), "built_at": inv.get("built_at")}


@router.get("/export.csv")
async def export_csv(
    q: str = "",
    type: str = "",
    platform: str = "",
    session: SessionEntry = Depends(require_auth),
):
    inv = await _get_or_build(session)
    tunnels = _filter_tunnels(inv["tunnels"], q=q, ttype=type, platform=platform)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "id", "type", "platform", "name",
        "device", "interface", "role", "local_ip", "peer_ip", "shutdown", "vrf",
        "p1_protocol", "p1_encryption", "p1_integrity", "p1_dh_group", "p1_auth",
        "p2_name", "p2_encryption", "p2_integrity", "p2_pfs",
        "p2_lifetime_sec", "p2_lifetime_kb",
    ])
    for t in tunnels:
        p1 = t.get("phase1", {})
        p2 = t.get("phase2", {})
        for ep in t["endpoints"]:
            w.writerow([
                t["id"], t["type"], t["platform"], t["name"],
                ep.get("device", ""), ep.get("interface", ""), ep.get("role", ""),
                ep.get("local_ip", ""), ep.get("peer_ip", ""),
                "yes" if ep.get("shutdown") else "no", ep.get("vrf", ""),
                p1.get("protocol", ""), ",".join(p1.get("encryption", [])),
                ",".join(p1.get("integrity", [])), ",".join(p1.get("dh_group", [])),
                p1.get("auth", ""),
                p2.get("name", ""), ",".join(p2.get("encryption", [])),
                ",".join(p2.get("integrity", [])), p2.get("pfs_group", ""),
                p2.get("sa_lifetime_sec") or "", p2.get("sa_lifetime_kb") or "",
            ])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="tunnel_inventory.csv"'},
    )


@router.get("/cache/info")
async def tunnel_cache_info():
    info = cache.cache_info(TUNNEL_INVENTORY_CACHE_KEY)
    return {"key": TUNNEL_INVENTORY_CACHE_KEY, "info": info}
