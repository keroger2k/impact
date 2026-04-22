import logging
import asyncio
import os
import uuid
import json
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import Depends, FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from templates_module import templates
from utils.csrf import CSRFMiddleware
import auth as auth_module
from auth import require_auth, SessionEntry
from routers import dnac, ise, firewall, aci, commands, import_, auth as auth_router, pages, routing, nexus, cache_mgmt, ipam
from logger_config import setup_logging, set_correlation_id, run_with_context

setup_logging()
logger = logging.getLogger(__name__)

# Concurrent SSE connections tracker
sse_limit_tracker = {} # (session_token, path) -> count

@asynccontextmanager
async def lifespan(app: FastAPI):
    from dev import DEV_MODE, seed_cache, create_dev_session
    from cache import cache
    set_correlation_id(f"startup-{uuid.uuid4().hex[:8]}")
    if os.getenv("IMPACT_VERIFY_SSL", "false").lower() != "true":
        logger.warning("SSL verification is globally disabled")
    if DEV_MODE:
        seed_cache(cache)
        create_dev_session()
    else:
        ldap_url = os.getenv("AD_LDAP_URL", "")
        if not ldap_url or not ldap_url.startswith("ldaps://"):
            raise RuntimeError("LDAP misconfigured: AD_LDAP_URL must use ldaps://")
        asyncio.create_task(cache.warm())

    # C8: Background GC
    asyncio.create_task(auth_module.session_gc_task())

    yield
    logger.info("IMPACT II shutting down.")

app = FastAPI(
    title="IMPACT II Network Operations",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if os.getenv("DEV_MODE", "false").lower() == "true" else None,
    redoc_url="/api/redoc" if os.getenv("DEV_MODE", "false").lower() == "true" else None,
    openapi_url="/openapi.json" if os.getenv("DEV_MODE", "false").lower() == "true" else None,
)

CORS_ORIGINS = os.getenv("IMPACT_ALLOWED_ORIGINS", "").split(",") if os.getenv("IMPACT_ALLOWED_ORIGINS") else []
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(CSRFMiddleware)

@app.middleware("http")
async def sse_rate_limit(request: Request, call_next):
    if request.url.path in ["/api/warm", "/api/ipam/refresh", "/api/commands/run", "/api/import/run"]:
        token = request.cookies.get("impact_token")
        if token:
            key = (token, request.url.path)
            if sse_limit_tracker.get(key, 0) >= 2:
                raise HTTPException(429, "Too many concurrent stream connections")
            sse_limit_tracker[key] = sse_limit_tracker.get(key, 0) + 1
            try:
                return await call_next(request)
            finally:
                sse_limit_tracker[key] = max(0, sse_limit_tracker.get(key, 0) - 1)
    return await call_next(request)

@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    cid = request.headers.get("X-Correlation-ID") or f"req-{uuid.uuid4().hex[:8]}"
    set_correlation_id(cid)
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = cid
    return response

_auth_dep = {"dependencies": [Depends(require_auth)]}
app.include_router(auth_router.router, prefix="/api/auth", tags=["Auth"])
app.include_router(dnac.router, prefix="/api/dnac", tags=["DNAC"], **_auth_dep)
app.include_router(ise.router, prefix="/api/ise", tags=["ISE"], **_auth_dep)
app.include_router(firewall.router, prefix="/api/firewall", tags=["Firewall"], **_auth_dep)
app.include_router(aci.router, prefix="/api/aci", tags=["ACI"], **_auth_dep)
app.include_router(commands.router, prefix="/api/commands", tags=["Commands"], **_auth_dep)
app.include_router(import_.router, prefix="/api/import", tags=["Import"], **_auth_dep)
app.include_router(routing.router, prefix="/api/routing", tags=["Routing"], **_auth_dep)
app.include_router(nexus.router, prefix="/api/nexus", tags=["Nexus"], **_auth_dep)
app.include_router(cache_mgmt.router, prefix="/api/cache", tags=["Cache"], **_auth_dep)
app.include_router(ipam.router, prefix="/api/ipam", tags=["IPAM"], **_auth_dep)
app.include_router(pages.router)

# C2: Consolidate SSE warm
@app.post("/api/warm")
async def warm_cache(session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE
    from cache import cache, TTL_DEVICES, TTL_SITES
    import clients.dnac as dc
    import clients.ise as ic
    import clients.panorama as pc
    import clients.aci as ac
    from routers.nexus import init_nexus_collection, get_cached_nexus_inventory

    async def generate():
        loop = asyncio.get_event_loop()
        def emit(d): return f"data: {json.dumps(d)}\n\n"

        warmers = [
            ("dnac", lambda: dc.get_all_devices(auth_module.get_dnac_for_session(session)), "DNAC Inventory", TTL_DEVICES, "devices"),
            ("ise", lambda: ic.connectivity_check(auth_module.get_ise_for_session(session)), "ISE Connection", 3600, None),
            ("panorama", lambda: pc.connectivity_check_with_key(auth_module.get_panorama_key_for_session(session)), "Panorama Connection", 3600, None),
            ("aci", lambda: ac.connectivity_check(auth_module.get_aci_for_session(session)), "ACI Connection", 3600, None),
            ("nexus", lambda: init_nexus_collection(username=session.username, password=session.password), "Nexus Collection", 3600, None)
        ]

        for name, func, label, ttl, cache_key in warmers:
            try:
                if DEV_MODE:
                    yield emit({"step": name, "status": "done", "message": f"{label} (mock)"})
                    continue

                yield emit({"step": name, "status": "loading", "message": f"Warming {label}..."})
                res = await loop.run_in_executor(None, run_with_context(func))
                if cache_key: cache.set(cache_key, res, ttl)
                yield emit({"step": name, "status": "done", "message": f"{label} complete"})
            except Exception as e:
                yield emit({"step": name, "status": "error", "message": f"{label} failed: {str(e)[:50]}"})

        yield emit({"step": "done"})

    return StreamingResponse(generate(), media_type="text/event-stream")

@app.get("/api/status")
async def status(session: SessionEntry = Depends(require_auth)):
    from utils.system_status import get_system_status
    return await get_system_status(session)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/partials/status", response_class=HTMLResponse)
async def get_status_partial(request: Request, session: SessionEntry = Depends(require_auth)):
    current_status = await status(session)
    return templates.TemplateResponse(request, "partials/status.html", current_status)
