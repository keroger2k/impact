"""
main.py — IMPACT II Network Operations Platform
FastAPI backend + static file serving for the SPA frontend.

Run:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import auth as auth_module
from auth import require_auth, SessionEntry
from cache import AppCache
from routers import dnac, ise, firewall, commands, import_, auth as auth_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
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

# ── API routers ────────────────────────────────────────────────────────────────
_auth_dep = {"dependencies": [__import__("fastapi").Depends(require_auth)]}

app.include_router(auth_router.router, prefix="/api/auth",     tags=["Auth"])
app.include_router(dnac.router,      prefix="/api/dnac",     tags=["DNAC"],     **_auth_dep)
app.include_router(ise.router,       prefix="/api/ise",      tags=["ISE"],      **_auth_dep)
app.include_router(firewall.router,  prefix="/api/firewall", tags=["Firewall"], **_auth_dep)
app.include_router(commands.router,  prefix="/api/commands", tags=["Commands"], **_auth_dep)
app.include_router(import_.router,   prefix="/api/import",   tags=["Import"],   **_auth_dep)

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

    async def generate():
        loop = asyncio.get_event_loop()

        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

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
                devices = await loop.run_in_executor(None, dc.get_all_devices, dnac)
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
                sites = await loop.run_in_executor(None, dc.get_site_cache, dnac)
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
                    None, dc.build_device_site_map, dnac, sites or []
                )
                cache.set("device_site_map", dev_site_map, TTL_SITES)
                yield emit({"step": "sitemap", "status": "done",
                            "message": f"Site map built — {len(dev_site_map):,} devices mapped"})
            except Exception as e:
                yield emit({"step": "sitemap", "status": "error",
                            "message": f"Site map failed: {str(e)[:80]}"})

        # ── ISE ────────────────────────────────────────────────────────────────
        yield emit({"step": "ise", "status": "loading", "message": "Connecting to Cisco ISE…"})
        try:
            ise = auth_module.get_ise_for_session(session)
            ok  = await loop.run_in_executor(None, ic.connectivity_check, ise)
            yield emit({"step": "ise", "status": "done" if ok else "error",
                        "message": "ISE connected" if ok else "ISE unreachable"})
        except Exception as e:
            yield emit({"step": "ise", "status": "error", "message": f"ISE: {str(e)[:80]}"})

        # ── Panorama ───────────────────────────────────────────────────────────
        yield emit({"step": "panorama", "status": "loading", "message": "Connecting to Panorama…"})
        try:
            key      = auth_module.get_panorama_key_for_session(session)
            ok, detail = await loop.run_in_executor(None, pc.connectivity_check_with_key, key)
            yield emit({"step": "panorama", "status": "done" if ok else "error",
                        "message": detail if ok else f"Panorama: {detail}"})
        except Exception as e:
            yield emit({"step": "panorama", "status": "error",
                        "message": f"Panorama: {str(e)[:80]}"})

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
    import asyncio
    loop = asyncio.get_event_loop()

    async def check_dnac():
        try:
            dnac = auth_module.get_dnac_for_session(session)
            result = await loop.run_in_executor(
                None,
                lambda: dnac.custom_caller.call_api("GET", "/dna/intent/api/v1/network-device/count")
            )
            count = getattr(result, "response", 0)
            return {"ok": True, "detail": f"{count:,} devices"}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    async def check_ise():
        try:
            import clients.ise as ic
            ise = auth_module.get_ise_for_session(session)
            ok  = await loop.run_in_executor(None, ic.connectivity_check, ise)
            return {"ok": ok, "detail": "Connected" if ok else "Unreachable"}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    async def check_panorama():
        try:
            import clients.panorama as pc
            key = auth_module.get_panorama_key_for_session(session)
            ok, detail = await loop.run_in_executor(None, pc.connectivity_check_with_key, key)
            return {"ok": ok, "detail": detail}
        except Exception as e:
            return {"ok": False, "detail": str(e)[:80]}

    dnac_r, ise_r, pan_r = await asyncio.gather(check_dnac(), check_ise(), check_panorama())
    return {"dnac": dnac_r, "ise": ise_r, "panorama": pan_r}

# ── Static frontend ────────────────────────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
@app.get("/{full_path:path}")
async def serve_spa(full_path: str = ""):
    """Serve the SPA for all non-API routes (client-side routing)."""
    if full_path.startswith("api/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    return FileResponse(static_dir / "index.html")
