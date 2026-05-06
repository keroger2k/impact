"""routers/ise.py — ISE read-only API endpoints."""

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

import auth as auth_module
import clients.ise as ic
from auth import SessionEntry, require_auth
from cache import cache, TTL_ISE_POLICIES as ISE_TTL
from logger_config import run_with_context

router = APIRouter()
logger = logging.getLogger(__name__)

ISE_CACHE_KEYS = [
    "ise_nads", "ise_nad_groups", "ise_endpoint_groups", "ise_identity_groups",
    "ise_users", "ise_sgts", "ise_sgacls", "ise_egress_matrix",
    "ise_policy_sets", "ise_authz_profiles", "ise_allowed_protocols",
    "ise_profiling_policies", "ise_deployment_nodes",
]


def _get_ise(session: SessionEntry):
    try:
        return auth_module.get_ise_for_session(session)
    except Exception as e:
        raise HTTPException(503, f"ISE connection failed: {e}")


def _cached(key: str, loader, ttl: int = ISE_TTL):
    """Generic cached fetch helper — synchronous, call via run_in_executor."""
    return cache.get_or_set(key, loader, ttl)


async def _get_mapping_dicts(ise, loop):
    """Fetch and return mapping dictionaries for endpoint groups and profiler profiles."""
    groups = await loop.run_in_executor(None, run_with_context(_cached), "ise_endpoint_groups",
                 lambda: ic.get_endpoint_groups(ise))
    profiles = await loop.run_in_executor(None, run_with_context(_cached), "ise_profiling_policies",
                   lambda: ic.get_profiling_policies(ise))

    group_map = {g.get("id"): g.get("name") for g in groups if g.get("id") and g.get("name")}
    profile_map = {p.get("id"): p.get("name") for p in profiles if p.get("id") and p.get("name")}
    return group_map, profile_map


# ── Cache management ──────────────────────────────────────────────────────────

@router.get("/cache/info")
async def ise_cache_info():
    infos = {k: cache.cache_info(k) for k in ISE_CACHE_KEYS}
    valid_ts = [v["set_at"] for v in infos.values() if v]
    return {"oldest_at": min(valid_ts) if valid_ts else None, "keys": infos}


@router.post("/cache/refresh")
async def refresh_ise_cache():
    cache.invalidate_prefix("ise_")
    return {"status": "ise cache cleared"}


# ── Network Access Devices ────────────────────────────────────────────────────

@router.get("/nads")
async def list_nads(request: Request, search: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_NADS
    if DEV_MODE:
        nads = MOCK_NADS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        nads = await loop.run_in_executor(None, run_with_context(_cached), "ise_nads",
                   lambda: ic.get_network_devices(ise, ""))

    if search:
        s = search.lower()
        nads = [n for n in nads if s in json.dumps(n).lower()]

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_nads.html", {"total": len(nads), "items": nads})
    return {"total": len(nads), "items": nads}


@router.get("/nads/{nad_id}")
async def get_nad(nad_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_NADS
    if DEV_MODE:
        match = next((n for n in MOCK_NADS if n["id"] == nad_id), None)
        if not match:
            raise HTTPException(404, "NAD not found")
        return match
    ise    = _get_ise(session)
    loop   = asyncio.get_event_loop()
    detail = await loop.run_in_executor(None, run_with_context(ic.get_network_device_detail), ise, nad_id)
    if not detail:
        raise HTTPException(404, "NAD not found")
    return detail


@router.get("/device-groups")
async def list_device_groups(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_NAD_GROUPS
    if DEV_MODE:
        groups = MOCK_NAD_GROUPS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        groups = await loop.run_in_executor(None, run_with_context(_cached), "ise_nad_groups",
                     lambda: ic.get_network_device_groups(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_nad_groups.html", {"total": len(groups), "items": groups})
    return {"total": len(groups), "items": groups}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/endpoints")
async def search_endpoints(request: Request, mac: str = Query(..., min_length=2), session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_ENDPOINTS
    if DEV_MODE:
        s = mac.upper().replace(":", "").replace("-", "").replace(".", "")
        endpoints = [e for e in MOCK_ENDPOINTS if s in e.get("mac", "").upper().replace(":", "")]
    else:
        ise = _get_ise(session)
        loop = asyncio.get_event_loop()
        endpoints = await loop.run_in_executor(None, run_with_context(ic.get_endpoints), ise, mac)

        # Map IDs to names
        group_map, profile_map = await _get_mapping_dicts(ise, loop)
        for ep in endpoints:
            if not ep.get("groupName") and ep.get("groupId") in group_map:
                ep["groupName"] = group_map[ep["groupId"]]
            if not ep.get("profileName") and ep.get("profileId") in profile_map:
                ep["profileName"] = profile_map[ep["profileId"]]

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_endpoint_results.html",
            {"total": len(endpoints), "items": endpoints, "mac_query": mac})
    return {"total": len(endpoints), "items": endpoints}


@router.get("/endpoints/{ep_id}")
async def get_endpoint(request: Request, ep_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_ENDPOINTS
    if DEV_MODE:
        raw_detail = next((e for e in MOCK_ENDPOINTS if e["id"] == ep_id), None)
        if not raw_detail:
            raise HTTPException(404, "Endpoint not found")
        detail = raw_detail.copy()

        from dev import MOCK_ACTIVE_SESSIONS, MOCK_AUTH_HISTORY
        mac = detail.get("name") or detail.get("mac")
        s = mac.upper().replace(":", "").replace("-", "").replace(".", "")
        live_sess = next((sess for sess in MOCK_ACTIVE_SESSIONS if s == sess.get("calling_station_id", "").upper().replace(":", "").replace("-", "")), None)
        history = [ev for ev in MOCK_AUTH_HISTORY if s == ev.get("calling_station_id", "").upper().replace(":", "").replace("-", "")]

        if live_sess:
            for k in ["nas_ip_address", "network_device_name", "nas_port_id", "endpoint_profile",
                      "identity_store", "identity_group", "ise_node", "auth_method", "vlan", "sgt"]:
                if live_sess.get(k):
                    detail[k] = live_sess[k]
            if live_sess.get("framed_ip_address"):
                detail["ipAddress"] = live_sess["framed_ip_address"]
            if live_sess.get("network_device_name") and live_sess.get("nas_port_id"):
                detail["connectedToDevice"] = f"{live_sess['network_device_name']} ({live_sess['nas_port_id']})"

        if history and not detail.get("lastAuthTime"):
            detail["lastAuthTime"] = history[0].get("timestamp")
    else:
        ise = _get_ise(session)
        loop = asyncio.get_event_loop()
        detail = await loop.run_in_executor(None, run_with_context(ic.get_endpoint_detail), ise, ep_id)
        if not detail:
            raise HTTPException(404, "Endpoint not found")

        # Map IDs to names
        group_map, profile_map = await _get_mapping_dicts(ise, loop)
        if not detail.get("groupName") and detail.get("groupId") in group_map:
            detail["groupName"] = group_map[detail["groupId"]]
        if not detail.get("profileName") and detail.get("profileId") in profile_map:
            detail["profileName"] = profile_map[detail["profileId"]]

        # Enrich with live session and auth history
        mac = detail.get("name") or detail.get("mac")
        if mac:
            tasks = [
                loop.run_in_executor(None, run_with_context(ic.get_session_by_mac), mac, session.username, session.password),
                loop.run_in_executor(None, run_with_context(ic.get_auth_history_by_mac), mac, 86400, 5, session.username, session.password)
            ]
            live_sess, history = await asyncio.gather(*tasks)

            # Prioritize live session IP
            if live_sess and live_sess.get("framed_ip_address"):
                detail["ipAddress"] = live_sess["framed_ip_address"]

            # Merge live session attributes
            if live_sess:
                # Map specific MNT names
                mnt_mapping = {
                    "psn_name": "ise_node",
                    "authentication_method": "auth_method",
                    "auth_acs_timestamp": "lastAuthTime"
                }
                for src, dst in mnt_mapping.items():
                    if live_sess.get(src):
                        live_sess[dst] = live_sess[src]

                for k in ["nas_ip_address", "network_device_name", "nas_port_id", "endpoint_profile",
                          "identity_store", "identity_group", "ise_node", "auth_method", "vlan", "sgt"]:
                    if live_sess.get(k):
                        detail[k] = live_sess[k]

                # Fix 'defaultnetworkdevice'
                nw_dev = detail.get("network_device_name", "")
                if not nw_dev or nw_dev.lower() in ("default", "defaultnetworkdevice"):
                    nas_ip = live_sess.get("nas_ip_address")
                    if nas_ip:
                        resolved = await loop.run_in_executor(None, run_with_context(ic.get_network_device_by_ip), ise, nas_ip)
                        if resolved and resolved.get("name"):
                            detail["network_device_name"] = resolved["name"]

                if detail.get("network_device_name") and live_sess.get("nas_port_id"):
                    detail["connectedToDevice"] = f"{detail['network_device_name']} ({live_sess['nas_port_id']})"
                elif live_sess.get("nas_ip_address"):
                    detail["connectedToDevice"] = live_sess["nas_ip_address"]

            # Fallback for "Connected To", "Last Auth", and Auth Metadata using history
            if history and isinstance(history, list) and len(history) > 0:
                latest = history[0]
                # Fallback for Auth Metadata
                for k in ["authentication_method", "vlan", "sgt", "auth_acs_timestamp"]:
                    target_k = "auth_method" if k == "authentication_method" else ("lastAuthTime" if k == "auth_acs_timestamp" else k)
                    if not detail.get(target_k) and latest.get(k):
                        detail[target_k] = latest[k]

                if not detail.get("connectedToDevice"):
                    dev_name = latest.get("network_device_name")
                    port = latest.get("nas_port_id")
                    if dev_name and port:
                        detail["connectedToDevice"] = f"{dev_name} ({port}) [stale]"
                    elif dev_name or latest.get("nas_ip_address"):
                        detail["connectedToDevice"] = f"{dev_name or latest.get('nas_ip_address')} [stale]"

                if not detail.get("lastAuthTime"):
                    detail["lastAuthTime"] = latest.get("timestamp")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_endpoint_detail.html", {"ep": detail})
    return detail


@router.get("/endpoint-groups")
async def list_endpoint_groups(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_ENDPOINT_GROUPS
    if DEV_MODE:
        groups = MOCK_ENDPOINT_GROUPS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        groups = await loop.run_in_executor(None, run_with_context(_cached), "ise_endpoint_groups",
                     lambda: ic.get_endpoint_groups(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_endpoint_groups.html", {"total": len(groups), "items": groups})
    return {"total": len(groups), "items": groups}


# ── Active Sessions (MNT API — not cached, always live) ───────────────────────

@router.get("/sessions/active")
async def get_active_sessions(request: Request, mac: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_ACTIVE_SESSIONS
    if DEV_MODE:
        sessions = MOCK_ACTIVE_SESSIONS
        if mac:
            s = mac.upper().replace(":", "").replace("-", "").replace(".", "")
            sessions = [sess for sess in sessions if s in sess.get("calling_station_id", "").upper().replace(":", "").replace("-", "")]
    else:
        loop = asyncio.get_event_loop()
        if mac:
            result = await loop.run_in_executor(None, run_with_context(ic.get_session_by_mac), mac, session.username, session.password)
            sessions = [result] if result else []
        else:
            sessions = await loop.run_in_executor(None, run_with_context(ic.get_active_sessions), 200, session.username, session.password)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_active_sessions.html",
            {"total": len(sessions), "items": sessions, "mac_filter": mac})
    return {"total": len(sessions), "items": sessions}


@router.get("/sessions/auth-history")
async def get_auth_history(request: Request, mac: str = Query(..., min_length=4), session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_AUTH_HISTORY
    if DEV_MODE:
        events = MOCK_AUTH_HISTORY
    else:
        loop = asyncio.get_event_loop()
        # Use Session History API as requested
        events = await loop.run_in_executor(None, run_with_context(ic.get_session_history_by_mac), mac, 86400, session.username, session.password)
        if not events:
            # Fallback to Auth Status if Session History is empty
            events = await loop.run_in_executor(None, run_with_context(ic.get_auth_history_by_mac), mac, 86400, 50, session.username, session.password)

        # Normalize fields for template compatibility
        for e in events:
            if not e.get("timestamp"):
                e["timestamp"] = e.get("auth_acs_timestamp") or e.get("acct_start_time") or "—"
            if not e.get("authentication_method"):
                e["authentication_method"] = e.get("auth_method") or "—"

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_auth_history.html",
            {"total": len(events), "items": events, "mac": mac})
    return {"total": len(events), "items": events}


@router.get("/sessions/recent")
async def get_recent_auth(request: Request, minutes: int = 5, session: SessionEntry = Depends(require_auth)):
    """Live auth feed — recent authentication events. Intended for HTMX polling (every 30s)."""
    from dev import DEV_MODE, MOCK_RECENT_AUTH_EVENTS
    if DEV_MODE:
        events = MOCK_RECENT_AUTH_EVENTS
    else:
        loop = asyncio.get_event_loop()
        events = await loop.run_in_executor(None, run_with_context(ic.get_recent_auth_events), minutes * 60, session.username, session.password)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_live_auth.html",
            {"total": len(events), "items": events, "minutes": minutes})
    return {"total": len(events), "items": events}


# ── Identity ──────────────────────────────────────────────────────────────────

@router.get("/identity-groups")
async def list_identity_groups(session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_IDENTITY_GROUPS
    if DEV_MODE:
        groups = MOCK_IDENTITY_GROUPS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        groups = await loop.run_in_executor(None, run_with_context(_cached), "ise_identity_groups",
                     lambda: ic.get_identity_groups(ise))
    return {"total": len(groups), "items": groups}


@router.get("/users/{user_id}")
async def get_user_detail(request: Request, user_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_USERS
    if DEV_MODE:
        user = next((u for u in MOCK_USERS if u["id"] == user_id), None)
        if not user: raise HTTPException(404, "User not found")
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        user = await loop.run_in_executor(None, run_with_context(ic.get_internal_user_detail), ise, user_id)
        if not user:
            raise HTTPException(404, "User not found")

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_user_detail.html", {"u": user})
    return user


@router.get("/users")
async def list_users(request: Request, search: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_USERS
    if DEV_MODE:
        users = MOCK_USERS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        users = await loop.run_in_executor(None, run_with_context(_cached), "ise_users",
                    lambda: ic.get_internal_users(ise, ""))

    if search:
        s = search.lower()
        users = [u for u in users if s in json.dumps(u).lower()]

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_users.html", {"total": len(users), "items": users})
    return {"total": len(users), "items": users}


# ── TrustSec ──────────────────────────────────────────────────────────────────

@router.get("/sgts")
async def list_sgts(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_SGTS
    if DEV_MODE:
        raw = MOCK_SGTS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        raw  = await loop.run_in_executor(None, run_with_context(_cached), "ise_sgts",
                   lambda: ic.get_sgts(ise))

    rows = []
    for s in raw:
        name  = s.get("name",  "—") if isinstance(s, dict) else getattr(s, "name",  "—")
        value = s.get("value", "—") if isinstance(s, dict) else getattr(s, "value", "—")
        desc  = s.get("description", "") if isinstance(s, dict) else getattr(s, "description", "")
        prop  = s.get("propagateToApic", s.get("propogateToApic", False)) if isinstance(s, dict) else getattr(s, "propogateToApic", False)
        rows.append({"name": name, "value": value, "description": desc, "propagateToApic": prop})
    rows.sort(key=lambda r: int(str(r["value"])) if str(r["value"]).isdigit() else 9999)

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_sgts.html", {"total": len(rows), "items": rows})
    return {"total": len(rows), "items": rows}


@router.get("/sgacls")
async def list_sgacls(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_SGACLS
    if DEV_MODE:
        sgacls = MOCK_SGACLS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        sgacls = await loop.run_in_executor(None, run_with_context(_cached), "ise_sgacls",
                     lambda: ic.get_sgacls(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_sgacls.html", {"total": len(sgacls), "items": sgacls})
    return {"total": len(sgacls), "items": sgacls}


@router.get("/egress-matrix")
async def egress_matrix(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_EGRESS_MATRIX, MOCK_SGTS
    if DEV_MODE:
        cells = MOCK_EGRESS_MATRIX
        sgts  = MOCK_SGTS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        cells = await loop.run_in_executor(None, run_with_context(_cached), "ise_egress_matrix",
                    lambda: ic.get_egress_matrix(ise))
        sgts  = await loop.run_in_executor(None, run_with_context(_cached), "ise_sgts",
                    lambda: ic.get_sgts(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_egress_matrix.html",
            {"total": len(cells), "items": cells, "sgts": sgts})
    return {"total": len(cells), "items": cells}


# ── Policy ────────────────────────────────────────────────────────────────────

@router.get("/policy-sets")
async def list_policy_sets(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_POLICY_SETS
    if DEV_MODE:
        sets = MOCK_POLICY_SETS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        sets = await loop.run_in_executor(None, run_with_context(_cached), "ise_policy_sets",
                   lambda: ic.get_policy_sets(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_policy_sets.html", {"total": len(sets), "items": sets})
    return {"total": len(sets), "items": sets}


@router.get("/policy-sets/{policy_id}/auth-rules")
async def get_auth_rules(request: Request, policy_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_AUTH_RULES
    if DEV_MODE:
        rules = MOCK_AUTH_RULES
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        rules = await loop.run_in_executor(None, run_with_context(_cached), f"ise_auth_rules_{policy_id}",
                    lambda: ic.get_auth_rules(ise, policy_id))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_auth_rules.html", {"total": len(rules), "items": rules})
    return {"total": len(rules), "items": rules}


@router.get("/policy-sets/{policy_id}/authz-rules")
async def get_authz_rules(request: Request, policy_id: str, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_AUTHZ_RULES
    if DEV_MODE:
        rules = MOCK_AUTHZ_RULES
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        rules = await loop.run_in_executor(None, run_with_context(_cached),
            f"ise_authz_rules_{policy_id}", lambda: ic.get_authz_rules(ise, policy_id))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_authz_rules.html",
            {"total": len(rules), "items": rules})
    return {"total": len(rules), "items": rules}


@router.get("/authz-profiles")
async def list_authz_profiles(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_AUTHZ_PROFILES
    if DEV_MODE:
        profiles = MOCK_AUTHZ_PROFILES
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        profiles = await loop.run_in_executor(None, run_with_context(_cached), "ise_authz_profiles",
                       lambda: ic.get_authz_profiles(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_authz_profiles.html",
            {"total": len(profiles), "items": profiles})
    return {"total": len(profiles), "items": profiles}


@router.get("/allowed-protocols")
async def list_allowed_protocols(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_ALLOWED_PROTOCOLS
    if DEV_MODE:
        protocols = MOCK_ALLOWED_PROTOCOLS
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        protocols = await loop.run_in_executor(None, run_with_context(_cached), "ise_allowed_protocols",
                        lambda: ic.get_allowed_protocols(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_allowed_protocols.html",
            {"total": len(protocols), "items": protocols})
    return {"total": len(protocols), "items": protocols}


# ── Profiling & Admin ─────────────────────────────────────────────────────────

@router.get("/profiling-policies")
async def list_profiling_policies(request: Request, search: Optional[str] = None, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_PROFILING_POLICIES
    if DEV_MODE:
        policies = MOCK_PROFILING_POLICIES
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        policies = await loop.run_in_executor(None, run_with_context(_cached), "ise_profiling_policies",
                       lambda: ic.get_profiling_policies(ise))

    if search:
        s = search.lower()
        policies = [p for p in policies if s in (p.get("name", "") + p.get("description", "")).lower()]

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_profiling_policies.html",
            {"total": len(policies), "items": policies})
    return {"total": len(policies), "items": policies}


@router.get("/deployment-nodes")
async def list_deployment_nodes(request: Request, session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE, MOCK_DEPLOYMENT_NODES
    if DEV_MODE:
        nodes = MOCK_DEPLOYMENT_NODES
    else:
        ise  = _get_ise(session)
        loop = asyncio.get_event_loop()
        nodes = await loop.run_in_executor(None, run_with_context(_cached), "ise_deployment_nodes",
                    lambda: ic.get_deployment_nodes(ise))

    if request.headers.get("HX-Request"):
        from templates_module import templates
        return templates.TemplateResponse(request, "partials/ise_deployment_nodes.html",
            {"total": len(nodes), "items": nodes})
    return {"total": len(nodes), "items": nodes}
