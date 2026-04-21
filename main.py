from fastapi import Request
from fastapi.responses import HTMLResponse
"""
main.py — IMPACT II Network Operations Platform
FastAPI backend + Jinja2/HTMX rendering.

Run:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import logging
import asyncio
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from templates_module import templates

import auth as auth_module
from auth import require_auth, SessionEntry
from routers import dnac, ise, firewall, aci, commands, import_, auth as auth_router, pages, routing, nexus, cache_mgmt, ipam
from logger_config import setup_logging, set_correlation_id, run_with_context

setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from dev import DEV_MODE, seed_cache, create_dev_session
    from cache import cache

    # Generate correlation ID for the startup lifecycle
    set_correlation_id(f"startup-{uuid.uuid4().hex[:8]}")

    if DEV_MODE:
        seed_cache(cache)
        create_dev_session()
        logger.info("DEV_MODE enabled — mock data loaded, LDAP bypassed.")
    else:
        # Initial warm-up for production using service credentials
        # Each warm cycle should have its own ID
        asyncio.create_task(cache.warm())

    logger.info("IMPACT II starting up.")
    yield
    logger.info("IMPACT II shutting down.")


app = FastAPI(
    title="IMPACT II Network Operations",
    description="TSA Catalyst Center + ISE + Panorama unified operations platform",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    # Try to get correlation ID from header, otherwise generate new one
    cid = request.headers.get("X-Correlation-ID") or f"req-{uuid.uuid4().hex[:8]}"
    set_correlation_id(cid)

    response = await call_next(request)
    response.headers["X-Correlation-ID"] = cid
    return response

# ── API routers ────────────────────────────────────────────────────────────────
_auth_dep = {"dependencies": [Depends(require_auth)]}

app.include_router(auth_router.router, prefix="/api/auth",     tags=["Auth"])
app.include_router(dnac.router,      prefix="/api/dnac",     tags=["DNAC"],     **_auth_dep)
app.include_router(ise.router,       prefix="/api/ise",      tags=["ISE"],      **_auth_dep)
app.include_router(firewall.router,  prefix="/api/firewall", tags=["Firewall"], **_auth_dep)
app.include_router(aci.router,       prefix="/api/aci",      tags=["ACI"],      **_auth_dep)
app.include_router(commands.router,  prefix="/api/commands", tags=["Commands"], **_auth_dep)
app.include_router(import_.router,   prefix="/api/import",   tags=["Import"],   **_auth_dep)
app.include_router(routing.router,   prefix="/api/routing",  tags=["Routing"],  **_auth_dep)
app.include_router(nexus.router,     prefix="/api/nexus",    tags=["Nexus"],    **_auth_dep)
app.include_router(cache_mgmt.router, prefix="/api/cache",    tags=["Cache"],    **_auth_dep)
app.include_router(ipam.router,       prefix="/api/ipam",     tags=["IPAM"],     **_auth_dep)

# ── Page router ────────────────────────────────────────────────────────────────
app.include_router(pages.router)

# ── Dev mode info ─────────────────────────────────────────────────────────────
@app.get("/api/dev-mode")
async def dev_mode_info():
    from dev import DEV_MODE, DEV_TOKEN, DEV_USER
    if not DEV_MODE:
        return {"enabled": False}
    return {"enabled": True, "token": DEV_TOKEN, "username": DEV_USER}


# ── Post-login cache warm ──────────────────────────────────────────────────────
@app.post("/api/warm")
async def warm_cache(session: SessionEntry = Depends(require_auth)):
    """Stream cache warm-up progress after login using the user's credentials."""
    from fastapi.responses import StreamingResponse
    import asyncio
    import json
    import clients.dnac as dc
    import clients.ise as ic
    import clients.panorama as pc
    from cache import cache, TTL_DEVICES, TTL_SITES
    from routers.firewall import PAN_TTL
    from dev import DEV_MODE, MOCK_DEVICES

    # Generate a single correlation ID for the entire warm cycle
    warm_cid = f"warm-{uuid.uuid4().hex[:8]}"
    set_correlation_id(warm_cid)
    logger.info(f"Starting post-login cache warm cycle", extra={"action": "CACHE_WARM_START"})

    async def _background_warm_ise(ise_client):
        loop = asyncio.get_event_loop()
        from cache import TTL_ISE_POLICIES
        key_loaders = [
            ("ise_nads",               lambda: ic.get_network_devices(ise_client, "")),
            ("ise_nad_groups",         lambda: ic.get_network_device_groups(ise_client)),
            ("ise_endpoint_groups",    lambda: ic.get_endpoint_groups(ise_client)),
            ("ise_identity_groups",    lambda: ic.get_identity_groups(ise_client)),
            ("ise_users",              lambda: ic.get_internal_users(ise_client, "")),
            ("ise_sgts",               lambda: ic.get_sgts(ise_client)),
            ("ise_sgacls",             lambda: ic.get_sgacls(ise_client)),
            ("ise_egress_matrix",      lambda: ic.get_egress_matrix(ise_client)),
            ("ise_policy_sets",        lambda: ic.get_policy_sets(ise_client)),
            ("ise_authz_profiles",     lambda: ic.get_authz_profiles(ise_client)),
            ("ise_allowed_protocols",  lambda: ic.get_allowed_protocols(ise_client)),
            ("ise_profiling_policies", lambda: ic.get_profiling_policies(ise_client)),
            ("ise_deployment_nodes",   lambda: ic.get_deployment_nodes(ise_client)),
        ]
        for key, loader in key_loaders:
            if cache.get(key) is None:
                try:
                    await loop.run_in_executor(None, run_with_context(cache.get_or_set), key, loader, TTL_ISE_POLICIES)
                except Exception as e:
                    logger.warning(f"Background ISE warm failed for {key}: {e}")

    async def _background_warm_panorama(pan_key):
        loop = asyncio.get_event_loop()
        try:
            all_dgs = await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_device_groups", lambda: pc.get_device_groups(pan_key), PAN_TTL)
            await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_managed_devices", lambda: pc.get_managed_devices(pan_key), PAN_TTL)
            await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_addr", lambda: pc.get_address_objects_and_groups(pan_key, all_dgs), PAN_TTL)
            await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_svc", lambda: pc.get_services(pan_key, all_dgs), PAN_TTL)

            def _build_rules():
                all_rules = pc.get_all_security_rules(pan_key, all_dgs)
                by_dg: dict[str, list] = {}
                for rule in all_rules:
                    dg = rule.get("device_group", "shared")
                    by_dg.setdefault(dg, []).append(rule)
                return {"dg_order": all_dgs, "by_dg": by_dg}

            await loop.run_in_executor(None, run_with_context(cache.get_or_set), "pan_rules", _build_rules, PAN_TTL)
        except Exception as e:
            logger.warning(f"Background Panorama warm failed: {e}")

    async def _background_warm_ipam():
        try:
            from utils.ipam_engine import IPAMEngine
            loop = asyncio.get_event_loop()
            engine = IPAMEngine()
            await engine.discover_all(session, loop, sources=None, yield_progress=None)
            engine.build_tree()
            cache.set("ipam_tree", engine.get_tree(), ttl=3600 * 24)
            logger.info("Background IPAM warm complete")
        except Exception as e:
            logger.warning(f"Background IPAM warm failed: {e}")

    async def generate():
        set_correlation_id(warm_cid) # Re-set in the generator for safety in async streaming
        loop = asyncio.get_event_loop()

        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        # ── DEV_MODE: skip all real connections ────────────────────────────────
        if DEV_MODE:
            n = len(MOCK_DEVICES)
            yield emit({"step": "devices",  "status": "cached", "message": f"{n} devices (mock)"})
            yield emit({"step": "sites",    "status": "cached", "message": "5 sites (mock)"})
            yield emit({"step": "sitemap",  "status": "cached", "message": f"{n} devices mapped (mock)"})
            yield emit({"step": "ise",      "status": "done",   "message": "ISE connected (mock)"})
            yield emit({"step": "panorama", "status": "done",   "message": "Panorama connected (mock)"})
            yield emit({"step": "aci",      "status": "done",   "message": "ACI connected (mock)"})

            from routers.nexus import get_cached_nexus_inventory, init_nexus_collection
            await init_nexus_collection(username=session.username, password=session.password)
            nexus_data = get_cached_nexus_inventory()
            yield emit({"step": "nexus", "status": "done", "message": f"{len(nexus_data)} Nexus devices (mock)"})

            yield emit({"step": "done"})
            return

        # ── DNAC client ────────────────────────────────────────────────────────
        try:
            dnac = auth_module.get_dnac_for_session(session)
        except Exception as e:
            yield emit({"step": "devices", "status": "error", "message": f"DNAC connection failed: {str(e)[:80]}"})
            yield emit({"step": "done"})
            return

        # ── Devices ────────────────────────────────────────────────────────────
        devices = cache.get("devices")
        if devices is not None:
            yield emit({"step": "devices", "status": "cached",
                        "message": f"{len(devices):,} devices (from cache)"})
        else:
            yield emit({"step": "devices", "status": "loading",
                        "message": "Loading devices from Catalyst Center…"})
            try:
                devices = await loop.run_in_executor(None, run_with_context(dc.get_all_devices, dnac))
                cache.set("devices", devices, TTL_DEVICES)
                yield emit({"step": "devices", "status": "done",
                            "message": f"{len(devices):,} devices loaded from Catalyst Center"})
            except Exception as e:
                yield emit({"step": "devices", "status": "error",
                            "message": f"Devices failed: {str(e)[:80]}"})
                devices = []

        # ── Sites ──────────────────────────────────────────────────────────────
        sites = cache.get("sites")
        if sites is not None:
            yield emit({"step": "sites", "status": "cached",
                        "message": f"{len(sites):,} sites (from cache)"})
        else:
            yield emit({"step": "sites", "status": "loading", "message": "Loading sites…"})
            try:
                sites = await loop.run_in_executor(None, run_with_context(dc.get_site_cache, dnac))
                cache.set("sites", sites, TTL_SITES)
                yield emit({"step": "sites", "status": "done",
                            "message": f"{len(sites):,} sites loaded"})
            except Exception as e:
                yield emit({"step": "sites", "status": "error",
                            "message": f"Sites failed: {str(e)[:80]}"})
                sites = []

        # ── Device → Site map ──────────────────────────────────────────────────
        dev_site_map = cache.get("device_site_map")
        if dev_site_map is not None:
            yield emit({"step": "sitemap", "status": "cached",
                        "message": f"Device-to-site map ({len(dev_site_map):,} entries, from cache)"})
        else:
            yield emit({"step": "sitemap", "status": "loading",
                        "message": "Building device-to-site map (this may take a minute)…"})
            try:
                dev_site_map = await loop.run_in_executor(
                    None, run_with_context(dc.build_device_site_map, dnac, sites or [])
                )
                cache.set("device_site_map", dev_site_map, TTL_SITES)
                yield emit({"step": "sitemap", "status": "done",
                            "message": f"Site map built — {len(dev_site_map):,} devices mapped"})
            except Exception as e:
                yield emit({"step": "sitemap", "status": "error",
                            "message": f"Site map failed: {str(e)[:80]}"})

        # Fire IPAM warm in background — depends on devices/sites being cached
        if cache.get("ipam_tree") is None:
            asyncio.create_task(_background_warm_ipam())

        # ── ISE ────────────────────────────────────────────────────────────────
        yield emit({"step": "ise", "status": "loading", "message": "Connecting to Cisco ISE…"})
        ise = None
        try:
            ise = auth_module.get_ise_for_session(session)
            ok  = await loop.run_in_executor(None, run_with_context(ic.connectivity_check, ise))
            yield emit({"step": "ise", "status": "done" if ok else "error",
                        "message": "ISE connected" if ok else "ISE unreachable"})
        except Exception as e:
            yield emit({"step": "ise", "status": "error", "message": f"ISE: {str(e)[:80]}"})

        # Fire ISE stable-list warm in background
        if ise is not None:
            asyncio.create_task(_background_warm_ise(ise))

        # ── Panorama ───────────────────────────────────────────────────────────
        yield emit({"step": "panorama", "status": "loading", "message": "Connecting to Panorama…"})
        pan_key = None
        try:
            pan_key  = auth_module.get_panorama_key_for_session(session)
            ok, detail = await loop.run_in_executor(None, run_with_context(pc.connectivity_check_with_key, pan_key))
            yield emit({"step": "panorama", "status": "done" if ok else "error",
                        "message": detail if ok else f"Panorama: {detail}"})
        except Exception as e:
            yield emit({"step": "panorama", "status": "error",
                        "message": f"Panorama: {str(e)[:80]}"})

        # Fire Panorama data warm in background
        if pan_key is not None:
            asyncio.create_task(_background_warm_panorama(pan_key))

        # ── ACI ────────────────────────────────────────────────────────────────
        yield emit({"step": "aci", "status": "loading", "message": "Connecting to Cisco ACI…"})
        try:
            aci_client = auth_module.get_aci_for_session(session)
            import clients.aci as ac
            ok = await loop.run_in_executor(None, run_with_context(ac.connectivity_check, aci_client))
            yield emit({"step": "aci", "status": "done" if ok else "error",
                        "message": "ACI connected" if ok else "ACI login failed"})
        except Exception as e:
            yield emit({"step": "aci", "status": "error", "message": f"ACI: {str(e)[:80]}"})

        # ── Nexus ───────────────────────────────────────────────────────────────
        from routers.nexus import get_cached_nexus_inventory, init_nexus_collection
        nexus_data = get_cached_nexus_inventory()
        if nexus_data:
            yield emit({"step": "nexus", "status": "cached", "message": f"{len(nexus_data)} Nexus devices (from cache)"})
        else:
            yield emit({"step": "nexus", "status": "loading", "message": "Collecting Nexus switch data (SSH)…"})
            try:
                # Pass user credentials for initial collection during warm-up
                await init_nexus_collection(username=session.username, password=session.password)
                nexus_data = get_cached_nexus_inventory()
                yield emit({"step": "nexus", "status": "done", "message": f"{len(nexus_data)} Nexus devices collected"})
            except Exception as e:
                yield emit({"step": "nexus", "status": "error", "message": f"Nexus failed: {str(e)[:80]}"})

        yield emit({"step": "done"})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── System status ──────────────────────────────────────────────────────────────
@app.get("/api/status")
async def status(session: SessionEntry = Depends(require_auth)):
    """Live connectivity check for all three systems using the user's credentials."""
    from dev import DEV_MODE
    if DEV_MODE:
        return {
            "dnac":     {"ok": True, "detail": "25 devices (mock)"},
            "ise":      {"ok": True, "detail": "Connected (mock)"},
            "panorama": {"ok": True, "detail": "Connected (mock)"},
            "aci":      {"ok": True, "detail": "Connected (mock)"},
        }

    import asyncio
    loop = asyncio.get_event_loop()

    async def check_dnac():
        try:
            dnac = auth_module.get_dnac_for_session(session)
            result = await loop.run_in_executor(
                None,
                run_with_context(lambda: dnac.custom_caller.call_api("GET", "/dna/intent/api/v1/network-device/count"))
            )
            count = getattr(result, "response", 0)
            return {"ok": True, "detail": f"{count:,} devices"}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    async def check_ise():
        try:
            # Check cache for status first to avoid redundant API calls every 60s
            from cache import cache, TTL_STATUS
            cached_status = cache.get("status_ise_live")
            if cached_status is not None:
                return cached_status

            import clients.ise as ic
            ise = auth_module.get_ise_for_session(session)
            ok  = await loop.run_in_executor(None, run_with_context(ic.connectivity_check, ise))
            res = {"ok": ok, "detail": "Connected" if ok else "Unreachable"}
            cache.set("status_ise_live", res, TTL_STATUS)
            return res
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    async def check_panorama():
        try:
            from cache import cache, TTL_STATUS
            cached_status = cache.get("status_pan_live")
            if cached_status is not None:
                return cached_status

            import clients.panorama as pc
            key = auth_module.get_panorama_key_for_session(session)
            ok, detail = await loop.run_in_executor(None, run_with_context(pc.connectivity_check_with_key, key))
            res = {"ok": ok, "detail": detail}
            cache.set("status_pan_live", res, TTL_STATUS)
            return res
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    async def check_aci():
        try:
            from cache import cache, TTL_STATUS
            cached_status = cache.get("status_aci")
            if cached_status is not None:
                return cached_status
            from routers.aci import _get_processed_nodes
            aci_client = auth_module.get_aci_for_session(session)
            processed, _ = await _get_processed_nodes(aci_client, loop)
            if processed:
                up = len([n for n in processed if n.get('status') == 'active'])
                res = {"ok": True, "detail": f"{up}/{len(processed)} Nodes"}
            else:
                res = {"ok": False, "detail": "No nodes found"}
            cache.set("status_aci", res, TTL_STATUS)
            return res
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    dnac_r, ise_r, pan_r, aci_r = await asyncio.gather(check_dnac(), check_ise(), check_panorama(), check_aci())
    return {"dnac": dnac_r, "ise": ise_r, "panorama": pan_r, "aci": aci_r}

# ── Static assets ──────────────────────────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/partials/status", response_class=HTMLResponse)
async def get_status_partial(request: Request, session: SessionEntry = Depends(require_auth)):
    current_status = await status(session)
    return templates.TemplateResponse(request, "partials/status.html", current_status)
