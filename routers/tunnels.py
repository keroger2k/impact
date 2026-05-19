"""routers/tunnels.py — Enterprise IPsec tunnel inventory.

Reads cached DNAC running-configs + Panorama IKE/IPsec objects and produces a
normalized tunnel inventory spanning IOS (DMVPN, sVTI, dVTI, policy-based) and
Palo Alto. Read-only.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import queue
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse

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
    """Return cached inventory. Does NOT trigger a build — the build is slow
    (DNAC parse + Palo template walk can take 5+ min) and must be initiated
    explicitly via /api/tunnels/refresh-stream so the user gets progress."""
    cached = cache.get(TUNNEL_INVENTORY_CACHE_KEY)
    if cached:
        return cached
    return {"tunnels": [], "built_at": None, "stats": {"total": 0, "by_type": {}, "by_platform": {}}}


async def _get_or_build_blocking(session: SessionEntry) -> dict:
    """Non-streaming build (used by the legacy refresh endpoint + tests).
    Prefer /api/tunnels/refresh-stream for interactive use."""
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
    not_built = inv.get("built_at") is None

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/tunnels_list.html", {
            "tunnels": tunnels,
            "stats":   inv.get("stats", {}),
            "filtered": bool(q or type or platform),
            "not_built": not_built,
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


# ── Streaming refresh ────────────────────────────────────────────────────────

@router.post("/refresh-stream")
async def refresh_stream(session: SessionEntry = Depends(require_auth)):
    """Rebuild the tunnel inventory while streaming step-by-step progress as SSE.

    Event shape matches the rest of the app (/api/import/run, /api/nexus/refresh):
      {"type": "log", "level": "info|success|warn|error", "message": "..."}
      {"type": "progress", "done": N, "total": T, "step": "..."}
      {"type": "complete", "stats": {...}, "built_at": ...}
      {"type": "error", "message": "..."}
    """
    from dev import DEV_MODE
    cache.invalidate(TUNNEL_INVENTORY_CACHE_KEY)
    # In DEV_MODE the Palo cache holds mock fixtures — keep them, since there's
    # no real Panorama to re-fetch from.
    if not DEV_MODE:
        cache.invalidate("pan_ike_gateways")
        cache.invalidate("pan_ipsec_tunnels")
        cache.invalidate("pan_ike_crypto_profiles")
        cache.invalidate("pan_ipsec_crypto_profiles")

    async def generate():
        def emit(d: dict) -> str:
            return f"data: {json.dumps(d)}\n\n"

        # Cross-thread queue: the Palo fetch runs in an executor and pushes
        # progress dicts here; the async generator drains them in real time.
        q: "queue.Queue[dict | None]" = queue.Queue()
        loop = asyncio.get_event_loop()

        def progress_cb(**kwargs):
            q.put(kwargs)

        # ── Phase 1: DNAC configs ──
        yield emit({"type": "log", "level": "info", "message": "Loading DNAC running-configs…"})
        configs = await _load_dnac_configs(session, loop)
        yield emit({"type": "log", "level": "success",
                    "message": f"Loaded {len(configs)} cached device configs."})

        # ── Phase 2: parse IOS ──
        yield emit({"type": "log", "level": "info",
                    "message": f"Parsing IPsec config from {len(configs)} devices…"})
        parsed_ios: dict[str, dict] = {}
        for dev_id, cfg in (configs or {}).items():
            if not cfg:
                continue
            try:
                parsed_ios[dev_id] = parse_ipsec_config(cfg)
            except Exception as e:
                logger.warning(f"IPsec parse failed for {dev_id}: {e}")
        total_tun = sum(len(p.get("tunnel_interfaces", [])) for p in parsed_ios.values())
        total_vt  = sum(len(p.get("virtual_templates", [])) for p in parsed_ios.values())
        total_cm  = sum(len(p.get("crypto_map_entries", [])) for p in parsed_ios.values())
        yield emit({"type": "log", "level": "success",
                    "message": f"Parsed IOS: {total_tun} tunnel interfaces, "
                               f"{total_vt} virtual-templates, {total_cm} crypto-map entries."})

        # ── Phase 3: Palo (the slow one) ──
        palo = {"ike_gateways": [], "ipsec_tunnels": [], "ike_profiles": [], "ipsec_profiles": []}

        if DEV_MODE:
            # Use seeded mock data — there's no real Panorama in dev.
            palo = {
                "ike_gateways":   cache.get("pan_ike_gateways")          or [],
                "ipsec_tunnels":  cache.get("pan_ipsec_tunnels")         or [],
                "ike_profiles":   cache.get("pan_ike_crypto_profiles")   or [],
                "ipsec_profiles": cache.get("pan_ipsec_crypto_profiles") or [],
            }
            yield emit({"type": "log", "level": "info",
                        "message": f"[DEV_MODE] Using mock Panorama: "
                                   f"{len(palo['ike_gateways'])} gateways, "
                                   f"{len(palo['ipsec_tunnels'])} tunnels."})
            api_key = None
        else:
            try:
                api_key = auth_module.get_panorama_key_for_session(session)
            except Exception as e:
                api_key = None
                yield emit({"type": "log", "level": "warn",
                            "message": f"Skipping Panorama: {e}"})

        if api_key:
            yield emit({"type": "log", "level": "info", "message": "Querying Panorama…"})

            # Run the Palo fetch in an executor so its blocking I/O doesn't
            # block the event loop. The progress callback writes to `q`,
            # which we drain from this coroutine.
            future = loop.run_in_executor(
                None,
                lambda: pc.get_ipsec_inventory(api_key, progress=progress_cb),
            )
            future.add_done_callback(lambda _f: q.put(None))  # sentinel = done

            # Drain progress events as they arrive. Use a short async sleep to
            # yield control between checks.
            while True:
                try:
                    ev = q.get_nowait()
                except queue.Empty:
                    if future.done():
                        break
                    await asyncio.sleep(0.1)
                    continue

                if ev is None:  # sentinel
                    break

                # Translate the cb event into our SSE event shape.
                step = ev.get("step", "")
                status = ev.get("status", "")
                msg = ev.get("message", "")
                cur = ev.get("current")
                tot = ev.get("total")

                level = "info"
                if status == "done": level = "success"
                if status == "warn": level = "warn"

                yield emit({"type": "log", "level": level, "message": msg})
                if step == "template" and cur is not None and tot is not None:
                    yield emit({"type": "progress", "step": "palo_template",
                                "done": cur, "total": tot})

            # Propagate any exception from the Palo fetch.
            try:
                palo = future.result()
            except Exception as e:
                yield emit({"type": "log", "level": "error",
                            "message": f"Panorama fetch failed: {e}"})

            # Cache the raw Palo data for parity with the non-streaming path.
            cache.set("pan_ike_gateways",         palo["ike_gateways"],   TTL_PAN_POLICY)
            cache.set("pan_ipsec_tunnels",        palo["ipsec_tunnels"],  TTL_PAN_POLICY)
            cache.set("pan_ike_crypto_profiles",  palo["ike_profiles"],   TTL_PAN_POLICY)
            cache.set("pan_ipsec_crypto_profiles", palo["ipsec_profiles"], TTL_PAN_POLICY)

        # ── Phase 4: normalize + cache ──
        yield emit({"type": "log", "level": "info", "message": "Building normalized inventory…"})
        device_meta = {d["id"]: d for d in (cache.get("devices") or [])}
        from utils.tunnel_inventory import build_inventory
        inv = build_inventory(parsed_ios=parsed_ios, device_meta=device_meta, palo=palo)
        cache.set(TUNNEL_INVENTORY_CACHE_KEY, inv, TTL_TUNNEL_INVENTORY)

        stats = inv.get("stats", {})
        yield emit({"type": "log", "level": "success",
                    "message": f"Inventory built: {stats.get('total', 0)} tunnels "
                               f"({', '.join(f'{n} {k}' for k, n in stats.get('by_type', {}).items())})"})
        yield emit({"type": "complete", "stats": stats, "built_at": inv.get("built_at")})

    return StreamingResponse(generate(), media_type="text/event-stream")


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


# ── Debug endpoints ──────────────────────────────────────────────────────────
# These exist purely to diagnose why tunnels are landing in the wrong bucket.
# All return JSON, no UI; they read from cached configs so they don't hit DNAC.

def _shape_key(iface: dict) -> tuple:
    """A 4-tuple describing what makes a tunnel interface 'shaped' a certain way.
    Aggregating by this key surfaces the common shapes of unknown tunnels."""
    return (
        iface.get("tunnel_mode") or "(no tunnel mode line)",
        "has_nhrp" if iface.get("nhrp_network_id") is not None else "no_nhrp",
        "has_dest" if iface.get("tunnel_destination") else "no_dest",
        "has_protection" if iface.get("tunnel_protection_profile") else "no_protection",
    )


@router.get("/debug/summary")
async def debug_summary(session: SessionEntry = Depends(require_auth)):
    """Aggregate every parsed tunnel interface across the fleet by (mode, nhrp, dest,
    protection) shape and classification. Shows which shapes are landing in 'unknown'
    so we can fix the classifier."""
    from collections import Counter
    configs = cache.get("dnac_device_configs") or {}
    device_meta = {d["id"]: d for d in (cache.get("devices") or [])}

    by_classification: Counter = Counter()
    shapes_by_classification: dict[str, Counter] = {}
    examples_by_shape: dict[tuple, list[str]] = {}
    devices_parsed = 0
    devices_with_tunnels = 0

    for dev_id, cfg in configs.items():
        if not cfg:
            continue
        devices_parsed += 1
        try:
            p = parse_ipsec_config(cfg)
        except Exception:
            continue
        host = p.get("hostname") or device_meta.get(dev_id, {}).get("hostname", dev_id[:8])

        all_ifaces = (
            [("Tunnel", i) for i in p.get("tunnel_interfaces", [])]
            + [("VT",    i) for i in p.get("virtual_templates", [])]
        )
        if all_ifaces:
            devices_with_tunnels += 1

        for kind, iface in all_ifaces:
            from utils.ipsec_parser import classify_tunnel
            cls = classify_tunnel(iface)
            by_classification[cls] += 1
            shape = _shape_key(iface)
            shapes_by_classification.setdefault(cls, Counter())[shape] += 1
            ex = examples_by_shape.setdefault(shape, [])
            if len(ex) < 5:
                ex.append(f"{host}:{iface.get('name','')}")

    # Materialize counters for JSON
    return {
        "devices_parsed":       devices_parsed,
        "devices_with_tunnels": devices_with_tunnels,
        "by_classification":    dict(by_classification),
        "shapes_per_classification": {
            cls: [
                {
                    "shape": {
                        "tunnel_mode":   s[0],
                        "nhrp":          s[1],
                        "destination":   s[2],
                        "protection":    s[3],
                    },
                    "count":    n,
                    "examples": examples_by_shape.get(s, []),
                }
                for s, n in shapes.most_common()
            ]
            for cls, shapes in shapes_by_classification.items()
        },
    }


@router.get("/debug/unknowns")
async def debug_unknowns(
    limit: int = 50,
    session: SessionEntry = Depends(require_auth),
):
    """List the first N tunnel interfaces that classify as 'unknown', with their
    key fields so you can spot what shape is missing from the classifier."""
    from utils.ipsec_parser import classify_tunnel
    configs = cache.get("dnac_device_configs") or {}
    device_meta = {d["id"]: d for d in (cache.get("devices") or [])}

    out: list[dict] = []
    for dev_id, cfg in configs.items():
        if not cfg or len(out) >= limit:
            continue
        try:
            p = parse_ipsec_config(cfg)
        except Exception:
            continue
        host = p.get("hostname") or device_meta.get(dev_id, {}).get("hostname", dev_id[:8])

        for iface in p.get("tunnel_interfaces", []) + p.get("virtual_templates", []):
            if classify_tunnel(iface) != "unknown":
                continue
            out.append({
                "device":         host,
                "device_id":      dev_id,
                "interface":      iface.get("name", ""),
                "tunnel_mode":    iface.get("tunnel_mode") or "(missing)",
                "tunnel_destination": iface.get("tunnel_destination") or "",
                "tunnel_protection_profile": iface.get("tunnel_protection_profile") or "",
                "nhrp_network_id": iface.get("nhrp_network_id"),
                "nhrp_nhs":       iface.get("nhrp_nhs", []),
                "ip_address":     iface.get("ip_address") or iface.get("ip_unnumbered") or "",
                "description":    iface.get("description", ""),
                "shutdown":       iface.get("shutdown", False),
            })
            if len(out) >= limit:
                break
    return {"limit": limit, "count": len(out), "unknowns": out}


@router.get("/debug/device/{device_query}")
async def debug_device(
    device_query: str,
    session: SessionEntry = Depends(require_auth),
):
    """Full parser output for a single device. `device_query` can be either the
    DNAC device id or the hostname (case-insensitive substring match)."""
    from utils.ipsec_parser import classify_tunnel, dmvpn_role
    configs = cache.get("dnac_device_configs") or {}
    devices = cache.get("devices") or []

    # Resolve hostname or id
    dev_id = None
    if device_query in configs:
        dev_id = device_query
    else:
        ql = device_query.lower()
        for d in devices:
            if ql in (d.get("hostname", "") or "").lower():
                dev_id = d["id"]
                break

    if not dev_id:
        return {"error": f"No device matching '{device_query}'. Try a hostname substring."}

    cfg = configs.get(dev_id)
    if not cfg:
        return {"error": f"No cached config for device {dev_id}. Run a DNAC refresh first."}

    try:
        p = parse_ipsec_config(cfg)
    except Exception as e:
        return {"error": f"Parse failed: {e}", "config_length": len(cfg)}

    tunnels_with_classification = []
    for iface in p.get("tunnel_interfaces", []):
        tunnels_with_classification.append({
            "name":          iface.get("name"),
            "tunnel_mode":   iface.get("tunnel_mode"),
            "tunnel_destination": iface.get("tunnel_destination"),
            "tunnel_protection_profile": iface.get("tunnel_protection_profile"),
            "nhrp_network_id": iface.get("nhrp_network_id"),
            "nhrp_nhs":      iface.get("nhrp_nhs"),
            "tunnel_key":    iface.get("tunnel_key"),
            "shutdown":      iface.get("shutdown"),
            "classification": classify_tunnel(iface),
            "dmvpn_role":    dmvpn_role(iface),
            "description":   iface.get("description"),
        })

    return {
        "device_id":       dev_id,
        "hostname":        p.get("hostname", ""),
        "config_length":   len(cfg),
        "config_first_120": cfg[:120],
        "counts": {
            "isakmp_policies":  len(p.get("isakmp_policies", [])),
            "ikev2_proposals":  len(p.get("ikev2_proposals", [])),
            "ikev2_profiles":   len(p.get("ikev2_profiles", [])),
            "ipsec_profiles":   len(p.get("ipsec_profiles", [])),
            "transform_sets":   len(p.get("transform_sets", [])),
            "tunnel_interfaces": len(p.get("tunnel_interfaces", [])),
            "virtual_templates": len(p.get("virtual_templates", [])),
            "crypto_map_entries": len(p.get("crypto_map_entries", [])),
        },
        "tunnels":           tunnels_with_classification,
        "ikev2_proposals":   p.get("ikev2_proposals"),
        "ikev2_profiles":    p.get("ikev2_profiles"),
        "ipsec_profiles":    p.get("ipsec_profiles"),
        "transform_sets":    p.get("transform_sets"),
        "isakmp_policies":   p.get("isakmp_policies"),
    }
