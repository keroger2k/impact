import logging
import asyncio
import os
import uuid
import json
import warnings
from contextlib import asynccontextmanager

# diskcache opens a sqlite3 connection per thread; ThreadPoolExecutor workers
# die during normal operation and their connections get GC'd without close().
warnings.filterwarnings("ignore", category=ResourceWarning, module="sqlite3")
from pathlib import Path
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from templates_module import templates
from utils.csrf import CSRFMiddleware
import auth as auth_module
from auth import require_auth, SessionEntry
from clients import verify_ssl
from routers import dnac, ise, firewall, aci, commands, import_, auth as auth_router, pages, routing, nexus, cache_mgmt, ipam, tunnels, ipv6_registry, ip_registry, site, f5, reports, swim, config_diff
from logger_config import setup_logging, set_correlation_id, run_with_context

setup_logging()
logger = logging.getLogger(__name__)

# Concurrent SSE connections tracker
sse_limit_tracker = {} # (session_token, path) -> count

# Strong references to fire-and-forget background tasks: the event loop keeps
# only a weak reference to tasks (per the asyncio.create_task docs), so an
# unreferenced task — notably session_gc_task, which purges expired sessions
# holding plaintext AD passwords — can be garbage-collected mid-flight.
_background_tasks: set[asyncio.Task] = set()

def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task

@asynccontextmanager
async def lifespan(app: FastAPI):
    from dev import DEV_MODE, seed_cache, create_dev_session
    from cache import cache
    set_correlation_id(f"startup-{uuid.uuid4().hex[:8]}")
    if not verify_ssl():
        logger.warning("SSL verification is globally disabled")

    # Purge legacy ACI cache keys
    cache.cleanup_old_aci_keys()

    # IP registry: ensure SQLite schema exists before any request hits the API
    from clients import ipv6_registry, ip_registry
    ipv6_registry.init_schema()
    ip_registry.init_schema()

    # SWIM job registry: same reasoning — schema must exist before any
    # /api/swim/jobs request lands.
    from clients import swim_jobs
    swim_jobs.init_schema()

    if DEV_MODE:
        seed_cache(cache)
        create_dev_session()
    else:
        ldap_url = os.getenv("AD_LDAP_URL", "")
        if not ldap_url or not ldap_url.startswith("ldaps://"):
            raise RuntimeError("LDAP misconfigured: AD_LDAP_URL must use ldaps://")
        auth_module.restore_sessions()
        _spawn(cache.warm())

    # C8: Background GC
    _spawn(auth_module.session_gc_task())

    yield
    logger.info("IMPACT II shutting down.")
    import auth_persist
    cache._refresh_pool.shutdown(wait=False)
    cache._cache.close()
    if auth_persist._store is not None:
        auth_persist._store.close()

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

SSE_LIMITED_PATHS = {"/api/warm", "/api/ipam/refresh", "/api/commands/run",
                     "/api/commands/config-run", "/api/import/run",
                     "/api/tunnels/refresh-stream", "/api/registry/audit/stream",
                     "/api/nexus/refresh", "/api/f5/refresh",
                     "/api/reports/maintenance-mode/schedule",
                     "/api/swim/jobs/start"}

@app.middleware("http")
async def sse_rate_limit(request: Request, call_next):
    if request.url.path not in SSE_LIMITED_PATHS:
        return await call_next(request)
    # Key on the session cookie, falling back to the Authorization header so a
    # Bearer-authed client (which carries no cookie) can't sidestep the cap.
    token = request.cookies.get("impact_token") or request.headers.get("Authorization")
    if not token:
        return await call_next(request)

    key = (token, request.url.path)
    # The check-and-increment runs without an await in between, so under asyncio's
    # single thread it is atomic — no lock needed.
    if sse_limit_tracker.get(key, 0) >= 2:
        return JSONResponse(status_code=429,
                            content={"detail": "Too many concurrent stream connections"})
    sse_limit_tracker[key] = sse_limit_tracker.get(key, 0) + 1

    def _release():
        n = sse_limit_tracker.get(key, 0) - 1
        if n <= 0:
            sse_limit_tracker.pop(key, None)
        else:
            sse_limit_tracker[key] = n

    try:
        response = await call_next(request)
    except Exception:
        _release()
        raise

    # The body of a StreamingResponse is sent *after* call_next returns, so we
    # must release the slot when the body iterator is exhausted/closed — not here
    # — otherwise the cap never actually bounds concurrent streams.
    orig_iter = getattr(response, "body_iterator", None)
    if orig_iter is None:
        _release()
        return response

    async def _counted():
        try:
            async for chunk in orig_iter:
                yield chunk
        finally:
            _release()

    response.body_iterator = _counted()
    return response

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
app.include_router(f5.router, prefix="/api/f5", tags=["F5"], **_auth_dep)
app.include_router(cache_mgmt.router, prefix="/api/cache", tags=["Cache"], **_auth_dep)
app.include_router(ipam.router, prefix="/api/ipam", tags=["IPAM"], **_auth_dep)
app.include_router(tunnels.router, prefix="/api/tunnels", tags=["Tunnels"], **_auth_dep)
app.include_router(ipv6_registry.router, prefix="/api/ipv6", tags=["IPv6Registry"], **_auth_dep)
app.include_router(ip_registry.router, prefix="/api/registry", tags=["Registry"], **_auth_dep)
app.include_router(site.router, prefix="/api/site", tags=["Site"], **_auth_dep)
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"], **_auth_dep)
app.include_router(swim.router, prefix="/api/swim", tags=["SWIM"], **_auth_dep)
app.include_router(config_diff.router, prefix="/api/config-diff", tags=["ConfigDiff"], **_auth_dep)
app.include_router(pages.router)

# C2: Consolidate SSE warm
@app.post("/api/warm")
async def warm_cache(session: SessionEntry = Depends(require_auth)):
    from dev import DEV_MODE
    from cache import cache, TTL_STANDARD
    import clients.dnac as dc
    import clients.ise as ic
    import clients.panorama as pc
    import clients.aci as ac
    from routers.nexus import init_nexus_collection
    from routers.f5 import init_f5_collection

    async def generate():
        loop = asyncio.get_event_loop()
        def emit(d): return f"data: {json.dumps(d)}\n\n"

        warmers = [
            ("dnac", lambda: dc.get_all_devices(auth_module.get_dnac_for_session(session)), "DNAC Inventory", TTL_STANDARD, "devices"),
            ("ise", lambda: ic.connectivity_check(auth_module.get_ise_for_session(session)), "ISE Connection", 3600, None),
            ("panorama", lambda: pc.connectivity_check_with_key(auth_module.get_panorama_key_for_session(session)), "Panorama Connection", 3600, None),
            ("aci", lambda: ac.connectivity_check(auth_module.get_aci_for_session(session)), "ACI Connection", 3600, None),
            ("nexus", lambda: init_nexus_collection(username=session.username, password=session.password), "Nexus Collection", 3600, None),
            ("f5", lambda: init_f5_collection(username=session.username, password=session.password), "F5 Collection", 3600, None)
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

class NoCacheStaticFiles(StaticFiles):
    """StaticFiles serves no Cache-Control header by default, so a browser's
    own heuristic caching can keep serving an old cached copy of a JS/CSS
    file for hours or days after it's changed on disk — confirmed in
    production: a returning browser served a stale report-charts.js and hit
    a "not a function" error on a renderer that had just been added to that
    file, even though the new file was live on disk. `no-cache` forces a
    conditional revalidation (If-None-Match /
    If-Modified-Since) on every request rather than trusting a local
    heuristic — still a fast 304 when nothing changed, but a code change is
    never silently invisible to an already-open browser tab. No build step
    or content-hashed filenames exist in this app to do this the "proper"
    versioned-asset way, so this is the proportionate fix.
    """
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


static_dir = Path(__file__).parent / "static"
app.mount("/static", NoCacheStaticFiles(directory=static_dir), name="static")

@app.get("/partials/status", response_class=HTMLResponse)
async def get_status_partial(request: Request, session: SessionEntry = Depends(require_auth)):
    current_status = await status(session)
    return templates.TemplateResponse(request, "partials/status.html", current_status)


if __name__ == "__main__":
    # `python main.py` as an alternative to ./run.sh (which is the better entry
    # point — it finds the venv for you). Same IMPACT_HOST/PORT/RELOAD knobs.
    # Uvicorn needs the app as an import string, not the object, or --reload
    # has no way to re-import it.
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("IMPACT_HOST", "0.0.0.0"),
        port=int(os.getenv("IMPACT_PORT", "8000")),
        reload=os.getenv("IMPACT_RELOAD", "true").lower() == "true",
    )
