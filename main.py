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
    logger.info("IMPACT II starting up — warming cache...")
    # Pre-warm DNAC device and site cache in the background
    try:
        from cache import cache
        await cache.warm()
    except Exception as e:
        logger.warning(f"Cache warm-up failed (non-fatal): {e}")
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
