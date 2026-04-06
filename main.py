"""
main.py — IMPACT II Network Operations Platform
FastAPI backend + static file serving for the SPA frontend.

Run:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from auth import require_auth
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
async def status():
    """Live connectivity check for all three systems."""
    from cache import cache
    results = await cache.check_all_systems()
    return results

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
