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
import xml.etree.ElementTree as ET
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
from utils.tunnel_inventory import build_inventory, resolve_ip

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
    device_site_map = cache.get("device_site_map") or {}
    dnac_interfaces = cache.get("dnac_interfaces") or []
    pan_interfaces  = cache.get("pan_interfaces") or []
    palo = await _load_palo(session, loop)

    return build_inventory(
        parsed_ios=parsed_ios, device_meta=device_meta, palo=palo,
        device_site_map=device_site_map, dnac_interfaces=dnac_interfaces,
        pan_interfaces=pan_interfaces,
    )


async def _get_or_build(session: SessionEntry) -> dict:
    """Return cached inventory. Does NOT trigger a build — the build is slow
    (DNAC parse + Palo template walk can take 5+ min) and must be initiated
    explicitly via /api/tunnels/refresh-stream so the user gets progress.
    Serves the last-built inventory even past its TTL (rebuild is explicit), so
    the page shows data rather than an empty list once the 24h TTL rolls over."""
    cached = cache.get_stale(TUNNEL_INVENTORY_CACHE_KEY)
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

def _flatten_dmvpn(tunnels: list[dict]) -> list[dict]:
    """Explode each DMVPN cloud into one row per endpoint.

    The default inventory collapses all spokes of a cloud into a single row
    (good for fleet-wide overview). Flattening yields one row per spoke,
    matching the per-device view operators are used to from `show crypto
    session` output. Non-DMVPN tunnels are left untouched.
    """
    import hashlib
    out: list[dict] = []
    for t in tunnels:
        if t["type"] != "dmvpn" or len(t["endpoints"]) <= 1:
            out.append(t)
            continue
        for ep in t["endpoints"]:
            flat = {
                **t,
                "endpoints": [ep],
                "name":      f"{ep.get('device','?')}:{ep.get('interface','?')}",
                # Append device id to keep flat row ids stable + unique.
                "id": hashlib.sha256(
                    f"{t['id']}|{ep.get('device_id','')}|{ep.get('interface','')}".encode()
                ).hexdigest()[:16],
                "tags": {**(t.get("tags") or {}), "cloud_id": t["id"]},
            }
            out.append(flat)
    return out


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
    flatten: bool = False,
    session: SessionEntry = Depends(require_auth),
):
    inv = await _get_or_build(session)
    tunnels = inv["tunnels"]
    if flatten:
        tunnels = _flatten_dmvpn(tunnels)
    tunnels = _filter_tunnels(tunnels, q=q, ttype=type, platform=platform)
    not_built = inv.get("built_at") is None

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/tunnels_list.html", {
            "tunnels": tunnels,
            "stats":   inv.get("stats", {}),
            "filtered": bool(q or type or platform),
            "not_built": not_built,
            "flatten":  flatten,
        })

    return {
        "tunnels": tunnels,
        "stats":   inv.get("stats", {}),
        "built_at": inv.get("built_at"),
        "flatten":  flatten,
    }


@router.get("/detail/{tunnel_id}")
async def get_tunnel_detail(
    request: Request,
    tunnel_id: str,
    session: SessionEntry = Depends(require_auth),
):
    inv = await _get_or_build(session)
    tunnel = next((t for t in inv["tunnels"] if t["id"] == tunnel_id), None)
    if tunnel is None:
        # Could be a flattened-view id (synthesized per-endpoint). Look there.
        flat = _flatten_dmvpn(inv["tunnels"])
        tunnel = next((t for t in flat if t["id"] == tunnel_id), None)
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


# ── Live status (on-demand, never cached) ────────────────────────────────────

LIVE_FETCH_TIMEOUT_SEC = 20
PALO_LIVE_PARALLEL     = 5


@router.get("/live/{tunnel_id}/{endpoint_idx}")
async def get_live_status(
    request: Request,
    tunnel_id: str,
    endpoint_idx: int,
    session: SessionEntry = Depends(require_auth),
):
    """Fetch real-time IPsec state for ONE endpoint of a tunnel. Never cached —
    every click is a fresh device query. Returns an HTML fragment for htmx to
    swap into the row immediately below the endpoint."""
    from templates_module import templates

    def err(msg: str) -> HTMLResponse:
        return HTMLResponse(
            f"<div class='alert alert-warning small mb-0 m-2'>"
            f"<i class='ph ph-warning'></i> {msg}</div>",
        )

    inv = await _get_or_build(session)
    tunnel = next((t for t in inv["tunnels"] if t["id"] == tunnel_id), None)
    if tunnel is None:
        flat = _flatten_dmvpn(inv["tunnels"])
        tunnel = next((t for t in flat if t["id"] == tunnel_id), None)
    if not tunnel:
        return err("Tunnel not in current inventory (try refreshing).")

    endpoints = tunnel.get("endpoints") or []
    if endpoint_idx < 0 or endpoint_idx >= len(endpoints):
        return err(f"Endpoint #{endpoint_idx} out of range.")
    endpoint = endpoints[endpoint_idx]

    loop     = asyncio.get_event_loop()
    platform = tunnel.get("platform", "")

    try:
        if platform == "ios":
            state = await loop.run_in_executor(
                None, run_with_context(_fetch_ios_live),
                session, tunnel, endpoint,
            )
        elif platform == "palo":
            state = await loop.run_in_executor(
                None, run_with_context(_fetch_palo_live),
                session, tunnel, endpoint,
            )
        else:
            return err(f"Live status not supported for platform '{platform}'.")
    except Exception as e:
        logger.exception("live-fetch failed for %s/%d", tunnel_id, endpoint_idx)
        return err(f"Fetch failed: {type(e).__name__}: {str(e)[:200]}")

    # Walk every peer IP in the live state through the inventory's IP index so
    # the UI can render device/site alongside the raw IP. The index is built
    # once during inventory refresh and lives inside the inventory cache.
    _annotate_live_state(state, inv.get("ip_index") or {})

    return templates.TemplateResponse(request, "partials/tunnel_live.html", {
        "tunnel":   tunnel,
        "endpoint": endpoint,
        "state":    state,
    })


def _palo_traffic_score(state: dict) -> int:
    """Heuristic score for ranking which firewall is actually carrying
    traffic on a tunnel that's present on multiple firewalls (HA pair,
    anycast, template-stack with multiple devices).

    Prefer packets when reported, fall back to IPsec sequence numbers when
    pkt counters are zero (PAN-OS sometimes reports 0 packets even on the
    active node, but sequence numbers always increment with real traffic).
    """
    pkts = (state.get("encap_pkts") or 0) + (state.get("decap_pkts") or 0)
    if pkts:
        return pkts
    seq = 0
    for s in (state.get("sessions") or []):
        seq += (s.get("seq_send") or 0) + (s.get("seq_recv") or 0)
    return seq


def _annotate_live_state(state: dict, ip_index: dict[str, list[dict]]) -> None:
    """Attach `peer_match` / `nbma_match` / `tunnel_match` to live state rows.

    Each annotation is a list of resolution candidates (usually 0 or 1, but
    can be >1 when the same RFC1918 IP exists on multiple devices). The
    template renders the device/site alongside the IP. Mutates state in-place.
    """
    if not ip_index:
        return

    # Top-level peer IP (single-session case)
    if state.get("peer_ip"):
        state["peer_match"] = resolve_ip(state["peer_ip"], ip_index)

    for s in state.get("sessions") or []:
        s["peer_match"] = resolve_ip(s.get("peer") or "", ip_index)

    for p in state.get("dmvpn_peers") or []:
        p["nbma_match"]   = resolve_ip(p.get("nbma") or "", ip_index)
        p["tunnel_match"] = resolve_ip(p.get("tunnel") or "", ip_index)


def _fetch_ios_live(session: SessionEntry, tunnel: dict, endpoint: dict) -> dict:
    """Run a set of show commands on the IOS device, tailored to tunnel type.
    Parses each into the normalized state shape from utils.ipsec_live."""
    from dev import DEV_MODE
    from utils.ipsec_live import (
        merge_ios_state,
        parse_show_crypto_session, parse_show_dmvpn, parse_show_interface,
        parse_show_ikev2_sa, parse_show_isakmp_sa,
    )

    iface = endpoint.get("interface", "")
    peer  = (endpoint.get("peer_ip") or "").split(",")[0].strip()
    ttype = tunnel.get("type", "")

    # Use the bare forms — `show crypto session detail interface X` is
    # rejected on some IOS variants ("% Invalid input"). The parser filters
    # to the right block client-side via target_iface.
    commands: list[tuple[str, str]] = []
    if ttype == "dmvpn":
        commands.append(("show dmvpn",           "show dmvpn detail"))
        commands.append(("show crypto session",  "show crypto session detail"))
        commands.append(("show crypto ikev2 sa", "show crypto ikev2 sa"))
        if iface:
            commands.append(("show interface", f"show interface {iface}"))
    elif ttype in ("svti", "dvti"):
        commands.append(("show crypto session",  "show crypto session detail"))
        if iface:
            commands.append(("show interface", f"show interface {iface}"))
        commands.append(("show crypto ikev2 sa", "show crypto ikev2 sa"))
    else:
        commands.append(("show crypto session",  "show crypto session detail"))
        commands.append(("show crypto isakmp sa", "show crypto isakmp sa"))

    ip = endpoint.get("device_ip", "")
    if not ip:
        return _live_error("device IP missing for this endpoint")

    if DEV_MODE:
        return _mock_ios_state(tunnel, endpoint)

    from routers.commands import guess_device_type
    device_meta = {d["id"]: d for d in (cache.get("devices") or [])}
    meta = device_meta.get(endpoint.get("device_id", "")) or {}
    device_type = guess_device_type(meta.get("platformId", ""))

    raw: dict[str, str] = {}
    try:
        from netmiko import ConnectHandler
        with ConnectHandler(
            device_type=device_type,
            host=ip,
            username=session.username,
            password=session.password,
            timeout=LIVE_FETCH_TIMEOUT_SEC,
            conn_timeout=LIVE_FETCH_TIMEOUT_SEC,
            fast_cli=False,
        ) as conn:
            for label, cmd in commands:
                try:
                    raw[label] = conn.send_command(cmd, read_timeout=LIVE_FETCH_TIMEOUT_SEC) or ""
                except Exception as e:
                    raw[label] = f"!! {type(e).__name__}: {e}"
    except Exception as e:
        return _live_error(f"SSH to {ip} failed: {type(e).__name__}: {str(e)[:200]}")

    crypto_session  = parse_show_crypto_session(raw.get("show crypto session", ""), iface)
    dmvpn_state     = parse_show_dmvpn(raw.get("show dmvpn", ""), iface) if "show dmvpn" in raw else {}
    interface_state = parse_show_interface(raw.get("show interface", "")) if "show interface" in raw else {}
    ikev2_sa        = parse_show_ikev2_sa(raw.get("show crypto ikev2 sa", ""), peer)
    isakmp_sa       = parse_show_isakmp_sa(raw.get("show crypto isakmp sa", ""), peer)

    return merge_ios_state(crypto_session, ikev2_sa, isakmp_sa, interface_state, dmvpn_state, raw)


def _fetch_palo_live(session: SessionEntry, tunnel: dict, endpoint: dict) -> dict:
    """For Palo, the inventory only knows template/scope — not which managed
    firewall actually runs the tunnel. Fan out to managed firewalls in parallel
    and keep whichever ones report a matching vpn flow entry."""
    from dev import DEV_MODE
    import clients.panorama as pc
    from utils.ipsec_live import (
        merge_palo_state,
        parse_pan_vpn_flow, parse_pan_ipsec_sa, parse_pan_ike_sa,
        parse_pan_vpn_flow_one, parse_pan_ipsec_sa_one,
        list_pan_flow_names,
    )

    if DEV_MODE:
        return _mock_palo_state(tunnel, endpoint)

    # PAN-OS `show vpn flow name X` / `show vpn ipsec-sa tunnel X` both match
    # against the *IPsec tunnel configuration name* (the `entry name=` under
    # /network/tunnel/ipsec) — NOT the tunnel.N interface name. tunnel["name"]
    # is that config name; endpoint["interface"] is the tunnel interface and
    # would silently return zero matches.
    tunnel_name = (tunnel.get("name") or endpoint.get("interface") or "").strip()
    if not tunnel_name:
        return _live_error("Palo tunnel has no name to query")

    try:
        api_key = auth_module.get_panorama_key_for_session(session)
    except Exception as e:
        return _live_error(f"Panorama auth failed: {e}")

    devices = cache.get("pan_managed_devices") or pc.get_managed_devices(api_key)
    if not devices:
        return _live_error("No managed firewalls available to query")

    total = len(devices)
    # Only filter EXPLICITLY disconnected. Treat unknown (None) as "include
    # and let the query fail naturally" so a missing/odd `<connected>` field
    # doesn't silently hide the one firewall that has the tunnel.
    candidates = [d for d in devices if d.get("connected") is not False]
    skipped_disconnected = total - len(candidates)
    if not candidates:
        return _live_error(f"All {total} managed firewalls report disconnected from Panorama")

    # Two-phase fetch.
    #
    # Phase 1: `show vpn flow` returns a SUMMARY only (name, state, peer,
    # interfaces). No counters, no SPIs, no TS, no lifetimes. But it's cheap,
    # works without knowing exact proxy-ID names, and tells us which firewall
    # has SAs matching our tunnel.
    #
    # Phase 2 (on the matched firewall, in parallel): for EVERY match, run
    # `show vpn flow name "FULL_NAME"` and `show vpn ipsec-sa tunnel
    # "FULL_NAME"` to pull the rich per-SA detail (counters, SPIs, lifetimes,
    # TS). We previously skipped "inactive" matches as an optimization, but
    # PAN-OS reports `state=""` or `"inactive"` on the umbrella (bare-name)
    # entry of multi-proxy-ID tunnels even when proxies are flowing traffic
    # — skipping them was hiding counters on a whole class of tunnels.
    # max_workers=8 caps the fanout, so the cost of "enrich everything" is
    # bounded even on a 42-proxy-ID tunnel.
    flow_cmd = 'show vpn flow'
    ike_cmd  = 'show vpn ike-sa'

    # Per-device probe outcomes — surfaced in the error when no match found,
    # so the user can see whether a specific firewall was queried-and-empty,
    # errored, or filtered out.
    probe_log: list[str] = []

    def query_one(d: dict) -> Optional[dict]:
        serial = d.get("serial", "")
        host = d.get("hostname", serial)
        if not serial:
            probe_log.append(f"{host}: no serial")
            return None
        flow_xml = pc.op_via_sdk(flow_cmd, api_key, serial)
        if flow_xml is None:
            probe_log.append(f"{host} ({serial}): op failed or returned no result")
            return None
        flow = parse_pan_vpn_flow(flow_xml, tunnel_name)
        if not flow.get("found"):
            names = list_pan_flow_names(flow_xml)
            if names:
                # Cap the per-device name list so a hub with 200 spokes doesn't
                # bury the diagnostic.
                shown = ", ".join(names[:8])
                more = f" (+{len(names) - 8} more)" if len(names) > 8 else ""
                probe_log.append(f"{host}: has {len(names)} flows but none named '{tunnel_name}' — saw: {shown}{more}")
            else:
                probe_log.append(f"{host}: no IPSec flows at all")
            return None
        # Phase 2: enrich EVERY match with rich per-SA detail. The summary's
        # `state` field is unreliable on the umbrella (bare-name) entry of
        # multi-proxy-ID tunnels — it's often blank/"inactive" even when
        # proxies are flowing traffic — so we can't filter on it.
        def fetch_detail(m: dict) -> dict:
            full_name = m.get("name", "")
            f_xml = pc.op_via_sdk(f'show vpn flow name "{full_name}"', api_key, serial)
            s_xml = pc.op_via_sdk(f'show vpn ipsec-sa tunnel "{full_name}"', api_key, serial)
            return {
                "name":     full_name,
                "flow_xml": f_xml,
                "sa_xml":   s_xml,
                "detail":   parse_pan_vpn_flow_one(f_xml, full_name),
                "sa":       parse_pan_ipsec_sa_one(s_xml, full_name),
            }

        raw_details: dict[str, str] = {}
        if flow["matches"]:
            with ThreadPoolExecutor(max_workers=min(len(flow["matches"]), 8)) as ex:
                details = list(ex.map(fetch_detail, flow["matches"]))
            # Build a {name -> detail-record} index for fast merge.
            by_name = {d["name"]: d for d in details}
            for m in flow["matches"]:
                rec = by_name.get(m.get("name", ""))
                if not rec:
                    continue
                if rec["detail"]:
                    # Overlay the rich fields into the summary entry — preserve
                    # proxy_id and any summary-only fields not overwritten.
                    pid = m.get("proxy_id", "")
                    m.update(rec["detail"])
                    m["proxy_id"] = pid
                if rec["sa"]:
                    # Carry the per-SA crypto/SPI info on the match for the
                    # per-proxy session row.
                    m["_sa"] = rec["sa"]
                raw_details[f"{host}: show vpn flow name {m['name']}"]  = _et_text(rec["flow_xml"])
                raw_details[f"{host}: show vpn ipsec-sa {m['name']}"]   = _et_text(rec["sa_xml"])

            # Reclassify status from traffic counters. Older PAN-OS reports
            # state="init" / state="inactive" on SAs that are passing real
            # traffic (billions of packets). The <state> field then says
            # the whole tunnel is DOWN even though it's clearly up. If pkt
            # counters > 0 OR sequence numbers are advancing, this SA is
            # flowing — call it up regardless of what PAN-OS says.
            for m in flow["matches"]:
                pkts = (m.get("encap_pkts") or 0) + (m.get("decap_pkts") or 0)
                seq  = (m.get("seq_send")   or 0) + (m.get("seq_recv")   or 0)
                if pkts > 0 or seq > 0:
                    m["status"] = "up"

            # Refresh `primary` to point at the now-enriched bare-name match
            # (if any), otherwise the most-active match. Prefer flowing
            # traffic over a generic "first up" — operator wants headline
            # numbers to come from the SA they actually care about.
            new_primary = None
            for m in flow["matches"]:
                if not m.get("proxy_id"):
                    new_primary = m; break
            if not new_primary:
                active = [m for m in flow["matches"] if m.get("status") == "up"]
                if active:
                    new_primary = max(
                        active,
                        key=lambda m: (m.get("encap_pkts") or 0) + (m.get("decap_pkts") or 0),
                    )
            if new_primary:
                flow["primary"] = new_primary

        # Build the SA-aggregate shape merge_palo_state expects, from the
        # primary match's enriched _sa (if any).
        primary_sa = (flow.get("primary") or {}).get("_sa") or {}
        sa = {
            "matches": [m.get("_sa") for m in flow["matches"] if m.get("_sa")],
            "primary": primary_sa,
            "phase2": {
                "encryption":             primary_sa.get("encryption", ""),
                "integrity":              primary_sa.get("integrity", ""),
                "pfs":                    primary_sa.get("pfs", ""),
                "spi_in":                 primary_sa.get("spi_in", ""),
                "spi_out":                primary_sa.get("spi_out", ""),
                "lifetime_sec":           primary_sa.get("lifetime_sec"),
                "lifetime_remaining_sec": primary_sa.get("lifetime_remaining_sec"),
                "lifetime_kb":            primary_sa.get("lifetime_kb", ""),
            } if primary_sa else {},
        }

        ike_xml = pc.op_via_sdk(ike_cmd, api_key, serial)
        prim = flow.get("primary") or {}
        ike = parse_pan_ike_sa(ike_xml, prim.get("peer_ip", ""), prim.get("gwid", ""))
        # Fallback: `show vpn ike-sa` (unfiltered) sometimes returns empty on
        # HA peers or particular versions. The per-SA detail carries the IKE
        # gateway name (e.g. CAL_IKE_GTWY) — retry against that gateway
        # explicitly if the unfiltered query gave us nothing.
        if not ike and primary_sa.get("gateway"):
            gw_name = primary_sa["gateway"]
            ike_xml2 = pc.op_via_sdk(f'show vpn ike-sa gateway "{gw_name}"', api_key, serial)
            if ike_xml2 is not None:
                ike = parse_pan_ike_sa(ike_xml2, prim.get("peer_ip", ""), prim.get("gwid", ""))
                if ike:
                    raw_details[f"{host}: show vpn ike-sa gateway {gw_name}"] = _et_text(ike_xml2)

        raw = {
            f"{host}: show vpn flow (summary)": _et_text(flow_xml),
            f"{host}: show vpn ike-sa":         _et_text(ike_xml),
            **raw_details,
        }
        state = merge_palo_state(flow, sa, ike, raw)
        state["__firewall"] = host
        return state

    matches: list[dict] = []
    with ThreadPoolExecutor(max_workers=PALO_LIVE_PARALLEL) as ex:
        for result in ex.map(query_one, candidates):
            if result is not None:
                matches.append(result)

    if not matches:
        err = _live_error(
            f"Tunnel '{tunnel_name}' not running on any of {len(candidates)} queried firewalls "
            f"({total} total, {skipped_disconnected} skipped as disconnected)"
        )
        # Cap the probe log so we don't blow up the UI on huge fleets.
        for line in probe_log[:40]:
            err["errors"].append(line)
        if len(probe_log) > 40:
            err["errors"].append(f"… and {len(probe_log) - 40} more firewalls queried")
        return err

    # Rank matches so the HA-active firewall (the one actually carrying
    # traffic) becomes the primary display, not whichever fanout finished
    # first. Standby members report state=active with all-zero counters,
    # which previously hijacked the panel and made the live view show "0
    # encap/decap" while Panorama showed millions on the active node.
    matches.sort(key=_palo_traffic_score, reverse=True)

    if len(matches) == 1:
        return matches[0]

    primary = next((m for m in matches if m.get("status") == "up"), matches[0])
    primary["__additional"] = [m for m in matches if m is not primary]
    return primary


def _et_text(elem) -> str:
    if elem is None:
        return "(no response)"
    try:
        return ET.tostring(elem, encoding="unicode")
    except Exception:
        return str(elem)


def _live_error(msg: str) -> dict:
    from utils.ipsec_live import empty_state
    s = empty_state()
    s["errors"].append(msg)
    return s


def _mock_ios_state(tunnel: dict, endpoint: dict) -> dict:
    from utils.ipsec_live import empty_state
    s = empty_state()
    iface = endpoint.get("interface", "Tunnel?")
    # Simulate a small DMVPN hub with mixed peer health. Peer IPs are mock
    # spoke management IPs from dev.py — the inventory's IP index resolves
    # them to real (mock) devices/sites so the resolution column populates.
    sessions = [
        {"peer": "10.20.1.1", "uptime": "00:00:07", "status": "up",
         "phase1": {"protocol": "ikev2", "state": "active"},
         "encap_pkts": 1, "encap_drops": 0, "decap_pkts": 2, "decap_drops": 0,
         "p2_lifetime_sec": 3593, "p2_lifetime_kb": 4607999},
        {"peer": "10.30.1.1", "uptime": "19:48:29", "status": "up",
         "phase1": {"protocol": "ikev2", "state": "active"},
         "encap_pkts": 6273, "encap_drops": 0, "decap_pkts": 4363880, "decap_drops": 0,
         "p2_lifetime_sec": 3042, "p2_lifetime_kb": 4607443},
        {"peer": "10.40.1.1", "uptime": "00:48:06", "status": "up",
         "phase1": {"protocol": "ikev2", "state": "active"},
         "encap_pkts": 26839981, "encap_drops": 0, "decap_pkts": 84465744, "decap_drops": 151765,
         "p2_lifetime_sec": 2203, "p2_lifetime_kb": 4187641},
        {"peer": "10.50.1.1", "uptime": "00:48:23", "status": "up",
         "phase1": {"protocol": "ikev2", "state": "active"},
         "encap_pkts": 110886733, "encap_drops": 0, "decap_pkts": 126221088, "decap_drops": 2314542,
         "p2_lifetime_sec": 1985, "p2_lifetime_kb": 4394965},
        # Intentionally external (Internet-side) peer to exercise the
        # "(external)" branch in the resolution column.
        {"peer": "203.0.113.42", "uptime": "00:12:11", "status": "up",
         "phase1": {"protocol": "ikev2", "state": "active"},
         "encap_pkts": 412, "encap_drops": 0, "decap_pkts": 388, "decap_drops": 0,
         "p2_lifetime_sec": 3501, "p2_lifetime_kb": 4607999},
    ]
    # NHRP cache mirrors the sessions list — NBMA = the spoke's WAN IP
    # (mock = mgmt IP), Tunnel = the spoke's overlay IP (172.16.x.1 in
    # dev mocks). Both should resolve through the IP index.
    dmvpn_peers = [
        {"nbma": "10.20.1.1", "tunnel": "172.16.2.1", "state": "UP",
         "uptime": "19:48:29", "attrb": "S"},
        {"nbma": "10.30.1.1", "tunnel": "172.16.3.1", "state": "UP",
         "uptime": "00:48:06", "attrb": "S"},
        {"nbma": "10.40.1.1", "tunnel": "172.16.4.1", "state": "UP",
         "uptime": "00:48:23", "attrb": "S"},
        {"nbma": "10.50.1.1", "tunnel": "172.16.5.1", "state": "UP",
         "uptime": "00:00:07", "attrb": "S"},
    ]
    s.update({
        "status": "up",
        "uptime": sessions[0]["uptime"],
        "sessions": sessions,
        "session_count": len(sessions),
        "dmvpn_peers": dmvpn_peers,
        "peers_up": len(sessions),
        "peers_down": 0,
        "encap_pkts":  sum(x["encap_pkts"]  for x in sessions),
        "decap_pkts":  sum(x["decap_pkts"]  for x in sessions),
        "encap_drops": sum(x["encap_drops"] for x in sessions),
        "decap_drops": sum(x["decap_drops"] for x in sessions),
        "phase1": {"protocol": "ikev2", "state": "ready",
                   "encryption": "AES-CBC-256", "integrity": "SHA256",
                   "dh_group": "14", "lifetime_remaining_sec": 73215},
        "phase2": {"lifetime_remaining_sec": min(x["p2_lifetime_sec"] for x in sessions),
                   "lifetime_remaining_kb":  min(x["p2_lifetime_kb"]  for x in sessions)},
        "interface_state": {"line": "up", "protocol": "up",
                            "last_input": "00:00:01", "last_output": "00:00:00",
                            "input_errors": 0, "output_errors": 0,
                            "input_rate_bps": 4321, "output_rate_bps": 5678},
        "raw": {
            "show crypto session": f"[DEV_MODE] mock output for {iface}\n"
                                   f"4 peer sessions simulated\n",
            "show interface":      f"[DEV_MODE] mock interface {iface}\n"
                                   f"{iface} is up, line protocol is up\n",
        },
    })
    return s


def _mock_palo_state(tunnel: dict, endpoint: dict) -> dict:
    from utils.ipsec_live import empty_state
    s = empty_state()
    s.update({
        "status": "up",
        "peer_ip": endpoint.get("peer_ip", "192.0.2.99"),
        "encap_pkts": 9001, "decap_pkts": 8999,
        "encap_bytes": 9876543, "decap_bytes": 9876521,
        "phase1": {"protocol": "ikev2", "state": "established",
                   "encryption": "aes-256", "integrity": "sha256", "dh_group": "14",
                   "lifetime_remaining_sec": 21345},
        "phase2": {"encryption": "aes-256-cbc", "integrity": "sha256", "pfs": "14",
                   "spi_in": "0x11223344", "spi_out": "0x44332211",
                   "lifetime_remaining_sec": 2940},
        "raw": {"[DEV_MODE] show vpn flow":
                "<entry><name>mock</name><state>active</state></entry>"},
    })
    return s


# ── Streaming refresh ────────────────────────────────────────────────────────

@router.post("/refresh-stream")
async def refresh_stream(
    source: str = "all",
    session: SessionEntry = Depends(require_auth),
):
    """Rebuild the tunnel inventory while streaming step-by-step progress as SSE.

    Event shape matches the rest of the app (/api/import/run, /api/nexus/refresh):
      {"type": "log", "level": "info|success|warn|error", "message": "..."}
      {"type": "progress", "done": N, "total": T, "step": "..."}
      {"type": "phase",    "phase": "dnac|parse|palo|build", "status": "running|done|skipped", "summary": "..."}
      {"type": "complete", "stats": {...}, "built_at": ...}
      {"type": "error",    "message": "..."}

    ``source`` controls which underlying caches get invalidated and re-fetched:
      - "all"  — full rebuild: re-pull DNAC configs and Panorama
      - "dnac" — refresh DNAC configs only; reuse cached Panorama data
      - "palo" — refresh Panorama only; reuse cached DNAC configs
    """
    from dev import DEV_MODE
    source = (source or "all").lower()
    if source not in ("all", "dnac", "palo"):
        source = "all"

    cache.invalidate(TUNNEL_INVENTORY_CACHE_KEY)
    if source in ("all", "dnac"):
        cache.invalidate("dnac_device_configs")
    # In DEV_MODE the Palo cache holds mock fixtures — keep them, since there's
    # no real Panorama to re-fetch from.
    if source in ("all", "palo") and not DEV_MODE:
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

        # Tell the UI which phases will actually run this time.
        yield emit({"type": "meta", "source": source})

        # ── Phase 1: DNAC configs ──
        yield emit({"type": "phase", "phase": "dnac", "status": "running"})
        if source == "palo":
            yield emit({"type": "log", "level": "info",
                        "message": "Reusing cached DNAC running-configs (Palo-only refresh)…"})
        else:
            yield emit({"type": "log", "level": "info", "message": "Loading DNAC running-configs…"})
        configs = await _load_dnac_configs(session, loop)
        yield emit({"type": "log", "level": "success",
                    "message": f"Loaded {len(configs)} cached device configs."})
        yield emit({"type": "phase", "phase": "dnac", "status": "done",
                    "summary": f"{len(configs)} configs"})

        # ── Phase 2: parse IOS ──
        yield emit({"type": "phase", "phase": "parse", "status": "running"})
        yield emit({"type": "log", "level": "info",
                    "message": f"Parsing IPsec config from {len(configs)} devices…"})
        parsed_ios: dict[str, dict] = {}
        parse_failed = 0
        empty_configs = 0
        device_meta = {d["id"]: d for d in (cache.get("devices") or [])}
        for dev_id, cfg in (configs or {}).items():
            if not cfg:
                empty_configs += 1
                continue
            try:
                parsed_ios[dev_id] = parse_ipsec_config(cfg)
            except Exception as e:
                parse_failed += 1
                logger.warning(f"IPsec parse failed for {dev_id}: {e}")

        total_tun = sum(len(p.get("tunnel_interfaces", [])) for p in parsed_ios.values())
        total_vt  = sum(len(p.get("virtual_templates", [])) for p in parsed_ios.values())
        total_cm  = sum(len(p.get("crypto_map_entries", [])) for p in parsed_ios.values())
        yield emit({"type": "log", "level": "success",
                    "message": f"Parsed IOS from {len(parsed_ios)} devices: {total_tun} tunnel ifaces, "
                               f"{total_vt} virtual-templates, {total_cm} crypto-map entries "
                               f"({empty_configs} empty configs, {parse_failed} parse failures)."})

        # ── Phase 2.5: classification breakdown (helps explain inventory totals) ──
        from utils.ipsec_parser import classify_tunnel as _classify, dmvpn_role as _drole
        from collections import Counter

        iface_class: Counter = Counter()
        examples: dict[str, list[str]] = {}
        dmvpn_keys: Counter = Counter()       # (nhrp_id, tunnel_key, profile) -> count
        dmvpn_no_key: list[str] = []          # DMVPN tunnels with NULL nhrp_id or tunnel_key
        per_iface_name: Counter = Counter()   # Tunnel5000, Tunnel201, ... distribution

        for dev_id, parsed in parsed_ios.items():
            host = parsed.get("hostname") or device_meta.get(dev_id, {}).get("hostname", dev_id[:8])
            for iface in parsed.get("tunnel_interfaces", []):
                cls = _classify(iface)
                iface_class[cls] += 1
                per_iface_name[iface.get("name", "?")] += 1
                ex = examples.setdefault(cls, [])
                if len(ex) < 8:
                    ex.append(f"{host}:{iface.get('name','')}")
                if cls == "dmvpn":
                    key = (iface.get("nhrp_network_id"),
                           iface.get("tunnel_key"),
                           iface.get("tunnel_protection_profile") or "")
                    dmvpn_keys[key] += 1
                    if key[0] is None or key[1] is None:
                        if len(dmvpn_no_key) < 8:
                            dmvpn_no_key.append(f"{host}:{iface.get('name','')}")

        yield emit({"type": "log", "level": "info",
                    "message": "── IOS classification breakdown ──"})
        for cls, n in iface_class.most_common():
            sample = ", ".join(examples.get(cls, [])[:4])
            yield emit({"type": "log", "level": "info",
                        "message": f"  {cls}: {n}   (sample: {sample})"})

        if dmvpn_no_key:
            yield emit({"type": "log", "level": "warn",
                        "message": f"  DMVPN with missing nhrp-id or tunnel-key (won't group cleanly): "
                                   f"{', '.join(dmvpn_no_key)}"})

        # Top interface names — gives the user a feel for fleet shape.
        top_names = per_iface_name.most_common(8)
        if top_names:
            yield emit({"type": "log", "level": "info",
                        "message": "  Top interface names: " +
                                   ", ".join(f"{name} ({n})" for name, n in top_names)})

        # Preview the DMVPN groups that will be created.
        yield emit({"type": "log", "level": "info",
                    "message": f"  DMVPN distinct (nhrp_id, tunnel_key, profile) groups: {len(dmvpn_keys)}"})
        for key, n in dmvpn_keys.most_common(20):
            yield emit({"type": "log", "level": "info",
                        "message": f"    nhrp-{key[0]}/key-{key[1]}/{key[2] or '(no-profile)'}: "
                                   f"{n} endpoints"})
        if len(dmvpn_keys) > 20:
            yield emit({"type": "log", "level": "info",
                        "message": f"    … and {len(dmvpn_keys) - 20} more groups"})

        yield emit({"type": "phase", "phase": "parse", "status": "done",
                    "summary": f"{len(parsed_ios)} devices · {total_tun} ifaces"})

        # ── Phase 3: Palo (the slow one) ──
        palo = {"ike_gateways": [], "ipsec_tunnels": [], "ike_profiles": [], "ipsec_profiles": []}

        if source == "dnac":
            # DNAC-only refresh: reuse whatever's cached so the build step has
            # something for the Palo half. If nothing cached, the build emits zero
            # Palo rows — that's fine, the user explicitly asked for DNAC-only.
            palo = {
                "ike_gateways":   cache.get("pan_ike_gateways")          or [],
                "ipsec_tunnels":  cache.get("pan_ipsec_tunnels")         or [],
                "ike_profiles":   cache.get("pan_ike_crypto_profiles")   or [],
                "ipsec_profiles": cache.get("pan_ipsec_crypto_profiles") or [],
            }
            yield emit({"type": "phase", "phase": "palo", "status": "skipped",
                        "summary": f"using cache · {len(palo['ipsec_tunnels'])} tunnels"})
            yield emit({"type": "log", "level": "info",
                        "message": f"Skipping Panorama (DNAC-only refresh). "
                                   f"Reusing cached: {len(palo['ike_gateways'])} gateways, "
                                   f"{len(palo['ipsec_tunnels'])} tunnels."})
            api_key = None
        elif DEV_MODE:
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
            yield emit({"type": "phase", "phase": "palo", "status": "done",
                        "summary": f"[mock] {len(palo['ipsec_tunnels'])} tunnels"})
            api_key = None
        else:
            yield emit({"type": "phase", "phase": "palo", "status": "running"})
            try:
                api_key = auth_module.get_panorama_key_for_session(session)
            except Exception as e:
                api_key = None
                yield emit({"type": "log", "level": "warn",
                            "message": f"Skipping Panorama: {e}"})
                yield emit({"type": "phase", "phase": "palo", "status": "failed",
                            "summary": "auth failed"})

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
                if step in ("template", "stack", "firewall") and cur is not None and tot is not None:
                    yield emit({"type": "progress",
                                "step": f"palo_{step}",
                                "done": cur, "total": tot})

            # Propagate any exception from the Palo fetch.
            try:
                palo = future.result()
            except Exception as e:
                yield emit({"type": "log", "level": "error",
                            "message": f"Panorama fetch failed: {e}"})

            # ── Per-scope Palo breakdown — shows where tunnels actually live ──
            yield emit({"type": "log", "level": "info",
                        "message": "── Panorama scope breakdown ──"})
            scope_counts: dict[str, dict[str, int]] = {}
            for kind, items in (("gateways", palo["ike_gateways"]),
                                ("tunnels",  palo["ipsec_tunnels"]),
                                ("ike_prof", palo["ike_profiles"]),
                                ("ipsec_prof", palo["ipsec_profiles"])):
                for it in items:
                    scope = it.get("scope") or "?"
                    scope_counts.setdefault(scope, {"gateways": 0, "tunnels": 0,
                                                     "ike_prof": 0, "ipsec_prof": 0})
                    scope_counts[scope][kind] += 1

            # Sort: shared first, then templates with the most tunnels
            def _scope_sort_key(item):
                s, v = item
                return (0 if s == "shared" else 1, -v["tunnels"], s)
            for scope, counts in sorted(scope_counts.items(), key=_scope_sort_key)[:30]:
                yield emit({"type": "log", "level": "info",
                            "message": f"  {scope}: {counts['gateways']} gw, "
                                       f"{counts['tunnels']} tun, "
                                       f"{counts['ike_prof']} ike-prof, "
                                       f"{counts['ipsec_prof']} ipsec-prof"})
            if len(scope_counts) > 30:
                yield emit({"type": "log", "level": "info",
                            "message": f"  … and {len(scope_counts) - 30} more scopes"})

            yield emit({"type": "log", "level": "success",
                        "message": f"Panorama totals: {len(palo['ike_gateways'])} gateways, "
                                   f"{len(palo['ipsec_tunnels'])} tunnels, "
                                   f"{len(palo['ike_profiles'])} IKE profiles, "
                                   f"{len(palo['ipsec_profiles'])} IPsec profiles "
                                   f"across {len(scope_counts)} scopes."})

            # Diagnostic if the count is suspiciously low: check whether we
            # found ZERO tunnels in templates (only shared) — symptom of either
            # a template structure we don't understand, or templates that
            # genuinely don't carry network config.
            tpl_tunnels = sum(s["tunnels"] for k, s in scope_counts.items() if k != "shared")
            if len(palo["ipsec_tunnels"]) > 0 and tpl_tunnels == 0:
                yield emit({"type": "log", "level": "warn",
                            "message": "  ⚠ All Palo tunnels came from 'shared' scope only — "
                                       "no template returned any. May indicate template-stack "
                                       "config (different XPath needed) or templates without "
                                       "network/tunnel/ipsec entries."})

            # Cache the raw Palo data for parity with the non-streaming path.
            cache.set("pan_ike_gateways",         palo["ike_gateways"],   TTL_PAN_POLICY)
            cache.set("pan_ipsec_tunnels",        palo["ipsec_tunnels"],  TTL_PAN_POLICY)
            cache.set("pan_ike_crypto_profiles",  palo["ike_profiles"],   TTL_PAN_POLICY)
            cache.set("pan_ipsec_crypto_profiles", palo["ipsec_profiles"], TTL_PAN_POLICY)

            yield emit({"type": "phase", "phase": "palo", "status": "done",
                        "summary": f"{len(palo['ipsec_tunnels'])} tunnels · "
                                   f"{len(palo['ike_gateways'])} gateways"})

        # ── Phase 4: normalize + cache ──
        yield emit({"type": "phase", "phase": "build", "status": "running"})
        yield emit({"type": "log", "level": "info", "message": "Building normalized inventory…"})
        from utils.tunnel_inventory import build_inventory
        device_site_map = cache.get("device_site_map") or {}
        dnac_interfaces = cache.get("dnac_interfaces") or []
        pan_interfaces  = cache.get("pan_interfaces") or []
        inv = build_inventory(
            parsed_ios=parsed_ios, device_meta=device_meta, palo=palo,
            device_site_map=device_site_map, dnac_interfaces=dnac_interfaces,
            pan_interfaces=pan_interfaces,
        )
        cache.set(TUNNEL_INVENTORY_CACHE_KEY, inv, TTL_TUNNEL_INVENTORY)

        stats = inv.get("stats", {})

        # ── Phase-2 resolution check: how many IOS tunnels actually got their
        # ipsec profile body resolved (not just the name echoed back)? ──
        ios_tunnels = [t for t in inv["tunnels"] if t.get("platform") == "ios"]
        with_p2_body = sum(
            1 for t in ios_tunnels
            if t["phase2"].get("encryption") or t["phase2"].get("transform_sets")
        )
        unresolved = [
            t for t in ios_tunnels
            if (t["phase2"].get("name") and not (t["phase2"].get("encryption") or t["phase2"].get("transform_sets")))
        ]
        if ios_tunnels:
            yield emit({"type": "log", "level": "info",
                        "message": f"Phase 2 resolution: {with_p2_body}/{len(ios_tunnels)} IOS tunnels "
                                   f"have transform-set details resolved."})
            if unresolved:
                sample_names = ", ".join(t["phase2"]["name"] for t in unresolved[:5])
                yield emit({"type": "log", "level": "warn",
                            "message": f"  {len(unresolved)} tunnels reference a profile we couldn't resolve "
                                       f"(sample: {sample_names}). Check that 'crypto ipsec profile <name>' "
                                       f"is present in at least one cached config."})

        # ── IP → device/site resolver coverage ──
        # Surface enough state that "every endpoint site is empty" or "every
        # SA peer is external" become diagnosable from the refresh log alone,
        # without me having to ask which of device_site_map / dnac_interfaces
        # the user is missing.
        ip_index = inv.get("ip_index") or {}
        sources_count: dict[str, int] = {}
        for matches in ip_index.values():
            for m in matches:
                src = m.get("source", "?")
                sources_count[src] = sources_count.get(src, 0) + 1

        endpoints_total = sum(len(t["endpoints"]) for t in inv["tunnels"])
        with_site   = sum(1 for t in inv["tunnels"] for ep in t["endpoints"] if ep.get("local_site"))
        peers_attempted = 0
        peers_resolved  = 0
        for t in inv["tunnels"]:
            for ep in t["endpoints"]:
                for pm in ep.get("peer_matches", []):
                    peers_attempted += 1
                    if pm.get("matches"):
                        peers_resolved += 1

        yield emit({"type": "log", "level": "info",
                    "message": "── IP → device/site resolver coverage ──"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  device_site_map:  {len(device_site_map):,} device→site entries "
                               f"({'EMPTY — site column will be blank everywhere' if not device_site_map else 'OK'})"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  dnac_interfaces:  {len(dnac_interfaces):,} interfaces "
                               f"({'EMPTY — NBMA peers in live view will all show (external)' if not dnac_interfaces else 'OK'})"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  pan_interfaces:   {len(pan_interfaces):,} firewalls "
                               f"({'EMPTY — Palo↔Palo peer IPs will not resolve' if not pan_interfaces else 'OK'})"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  ip_index built:   {len(ip_index):,} distinct IPs · " +
                               ", ".join(f"{k}={v}" for k, v in sorted(sources_count.items()))})
        yield emit({"type": "log", "level": "info",
                    "message": f"  endpoints w/site: {with_site}/{endpoints_total}"})
        if peers_attempted:
            yield emit({"type": "log", "level": "info",
                        "message": f"  peer IPs resolved: {peers_resolved}/{peers_attempted} "
                                   f"({100*peers_resolved//max(1,peers_attempted)}%) — unresolved peers "
                                   f"are external (Internet/3rd-party) or not in DNAC inventory."})

        # ── Per-DMVPN-cloud member counts (helps explain "I expected 100s") ──
        dmvpn_tunnels = [t for t in inv["tunnels"] if t["type"] == "dmvpn"]
        if dmvpn_tunnels:
            yield emit({"type": "log", "level": "info",
                        "message": f"── DMVPN clouds ({len(dmvpn_tunnels)} total) ──"})
            for t in sorted(dmvpn_tunnels, key=lambda t: -len(t["endpoints"]))[:25]:
                hubs = sum(1 for ep in t["endpoints"] if ep.get("role") == "hub")
                spokes = sum(1 for ep in t["endpoints"] if ep.get("role") == "spoke")
                unk = len(t["endpoints"]) - hubs - spokes
                yield emit({"type": "log", "level": "info",
                            "message": f"  {t['name']}: {len(t['endpoints'])} endpoints "
                                       f"({hubs} hub, {spokes} spoke, {unk} unknown)"})
            if len(dmvpn_tunnels) > 25:
                yield emit({"type": "log", "level": "info",
                            "message": f"  … and {len(dmvpn_tunnels) - 25} more clouds"})

        # ── Final summary block — formatted for copy/paste ──
        total_dmvpn_endpoints = sum(len(t["endpoints"]) for t in dmvpn_tunnels)
        yield emit({"type": "log", "level": "info", "message": "════════ SUMMARY ════════"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  DNAC devices loaded:    {len(configs)}"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  IOS configs parsed:     {len(parsed_ios)} "
                               f"({empty_configs} empty, {parse_failed} failed)"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Tunnel interfaces seen: {total_tun}"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Virtual-templates seen: {total_vt}"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Crypto-map entries seen:{total_cm}"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Classifications:        " +
                               ", ".join(f"{k}={n}" for k, n in iface_class.most_common())})
        yield emit({"type": "log", "level": "info",
                    "message": f"  DMVPN clouds:           {len(dmvpn_tunnels)} "
                               f"(collapsing {total_dmvpn_endpoints} spoke/hub endpoints)"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Palo gateways:          {len(palo['ike_gateways'])}"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Palo IPsec tunnels:     {len(palo['ipsec_tunnels'])}"})
        yield emit({"type": "log", "level": "info",
                    "message": f"  Inventory rows total:   {stats.get('total', 0)} "
                               f"(" + ", ".join(f"{n} {k}" for k, n in stats.get('by_type', {}).items()) + ")"})
        yield emit({"type": "log", "level": "info", "message": "═════════════════════════"})

        yield emit({"type": "log", "level": "success",
                    "message": f"Inventory built: {stats.get('total', 0)} tunnels "
                               f"({', '.join(f'{n} {k}' for k, n in stats.get('by_type', {}).items())})"})
        yield emit({"type": "phase", "phase": "build", "status": "done",
                    "summary": f"{stats.get('total', 0)} tunnels"})
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
        "device", "site", "interface", "role", "local_ip",
        "peer_ip", "peer_device", "peer_site",
        "shutdown", "vrf",
        "p1_protocol", "p1_encryption", "p1_integrity", "p1_dh_group", "p1_auth",
        "p2_name", "p2_encryption", "p2_integrity", "p2_pfs",
        "p2_lifetime_sec", "p2_lifetime_kb",
    ])
    for t in tunnels:
        p1 = t.get("phase1", {})
        p2 = t.get("phase2", {})
        for ep in t["endpoints"]:
            # Flatten peer_matches (a list of {ip, matches}) into pipe-separated
            # "device|device|…" / "site|site|…" columns so a row stays one row
            # even when an endpoint has multiple peers or candidates.
            peer_devices, peer_sites = [], []
            for pm in ep.get("peer_matches", []):
                for m in pm.get("matches", []):
                    if m.get("device"): peer_devices.append(m["device"])
                    if m.get("site"):   peer_sites.append(m["site"])
            w.writerow([
                t["id"], t["type"], t["platform"], t["name"],
                ep.get("device", ""), ep.get("local_site", ""),
                ep.get("interface", ""), ep.get("role", ""),
                ep.get("local_ip", ""),
                ep.get("peer_ip", ""),
                "|".join(peer_devices), "|".join(peer_sites),
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


@router.get("/debug/resolution")
async def debug_resolution(
    ip: str = "",
    session: SessionEntry = Depends(require_auth),
):
    """Diagnostic for the IP → device/site resolver. Returns:
      - whether device_site_map / dnac_interfaces / tunnel inventory are present,
      - size of each, plus a sample row,
      - per-source breakdown of the live ip_index,
      - and an end-to-end resolve() for one or more IPs passed via `?ip=` (comma-separated).

    Use this when site columns are empty or every peer is "(external)" — the
    output names the missing input in one shot.
    """
    devices         = cache.get("devices") or []
    device_site_map = cache.get("device_site_map") or {}
    dnac_interfaces = cache.get("dnac_interfaces") or []
    inv             = cache.get(TUNNEL_INVENTORY_CACHE_KEY) or {}
    ip_index        = inv.get("ip_index") or {}

    # Per-source breakdown of the ip_index
    sources: dict[str, int] = {}
    for matches in ip_index.values():
        for m in matches:
            src = m.get("source", "?")
            sources[src] = sources.get(src, 0) + 1

    # Sanity-check device_site_map keys against the devices cache. A mismatch
    # is what produces "I have a site map but no endpoint has a site": the
    # tunnel inventory keys endpoints by DNAC instanceUuid (d["id"]), and
    # device_site_map MUST be keyed by that same id.
    device_ids = {d.get("id") for d in devices if d.get("id")}
    site_keys  = set(device_site_map.keys())
    overlap = len(device_ids & site_keys)

    out: dict = {
        "device_site_map": {
            "size":     len(device_site_map),
            "ok":       len(device_site_map) > 0,
            "sample":   dict(list(device_site_map.items())[:3]),
            "key_overlap_with_devices_cache": f"{overlap}/{len(device_ids)} device ids appear in device_site_map",
        },
        "dnac_interfaces": {
            "size":   len(dnac_interfaces),
            "ok":     len(dnac_interfaces) > 0,
            "sample": [
                {"deviceName": i.get("deviceName"), "portName": i.get("portName"),
                 "ipv4Address": i.get("ipv4Address")}
                for i in dnac_interfaces[:3]
            ],
        },
        "ip_index": {
            "distinct_ips":     len(ip_index),
            "ok":               len(ip_index) > 0,
            "by_source":        sources,
            "built_at":         inv.get("built_at"),
            "needs_rebuild":    inv.get("built_at") is None or "ip_index" not in inv,
        },
        "hint": (
            "If `device_site_map.size` is 0 — refresh DNAC Sites in Cache Management (or visit the Devices page once). "
            "If `dnac_interfaces.size` is 0 — refresh DNAC Interfaces. "
            "If both are non-zero but `ip_index.needs_rebuild` is true — click Refresh on the Tunnels page so the new annotation pass runs."
        ),
    }

    if ip:
        from utils.tunnel_inventory import resolve_ip
        targets = [s.strip() for s in ip.split(",") if s.strip()]
        out["resolve"] = {
            t: resolve_ip(t, ip_index) for t in targets
        }
    return out


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


@router.get("/debug/raw/{device_query}")
async def debug_raw_config(
    device_query: str,
    section: str = "",
    lines: int = 80,
    session: SessionEntry = Depends(require_auth),
):
    """Dump what _iter_blocks actually sees for a device's cached config.

    Optional `section` greps the iter_blocks output for the first match of the
    given substring (case-insensitive) and returns lines around it.
    `lines` caps the response (default 80).

    Returns:
        {
            "device_id": ..., "hostname": ...,
            "config_length": N,
            "total_lines_iter": M,    # lines after iter_blocks filters !-comments + blanks
            "lines": [{"indent": int, "stripped": str, "raw_repr": str}, ...]
        }
    """
    from utils.ipsec_parser import _iter_blocks
    configs = cache.get("dnac_device_configs") or {}
    devices = cache.get("devices") or []

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
        return {"error": f"No device matching '{device_query}'."}
    cfg = configs.get(dev_id)
    if not cfg:
        return {"error": f"No cached config for {dev_id}."}

    iter_out = list(_iter_blocks(cfg))
    rows = [
        {"indent": ind, "stripped": stripped, "raw_repr": repr(raw)}
        for ind, stripped, raw in iter_out
    ]

    if section:
        sl = section.lower()
        hit = next((i for i, r in enumerate(rows) if sl in r["stripped"].lower()), None)
        if hit is None:
            return {"error": f"section '{section}' not found", "total_lines_iter": len(iter_out)}
        start = max(0, hit - 3)
        end = min(len(rows), hit + lines)
        rows = rows[start:end]

    return {
        "device_id":         dev_id,
        "hostname":          next((d.get("hostname") for d in devices if d["id"] == dev_id), ""),
        "config_length":     len(cfg),
        "total_lines_iter":  len(iter_out),
        "lines":             rows[:lines],
    }


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
