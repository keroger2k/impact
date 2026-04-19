import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from auth import require_auth, SessionEntry
from cache import cache

router = APIRouter()

def _fmt_time(ts: float | None) -> str:
    if not ts: return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

@router.get("/status", response_class=HTMLResponse)
async def get_cache_status(request: Request, session: SessionEntry = Depends(require_auth)):
    from templates_module import templates

    # Inspection logic
    def get_info(key, title, icon, color, refresh_url, sse=False):
        info = cache.cache_info(key)
        count = 0
        data = cache.get(key)
        if isinstance(data, list):
            count = len(data)
        elif isinstance(data, dict):
            count = len(data)

        return {
            "key": key,
            "title": title,
            "icon": icon,
            "color": color,
            "set_at": _fmt_time(info["set_at"]) if info else "Empty",
            "is_expired": info["is_expired"] if info else False,
            "count": count,
            "refresh_url": refresh_url,
            "sse": sse
        }

    cards = [
        get_info("devices", "DNAC Inventory", "fas fa-network-wired", "primary", "/api/dnac/cache/refresh"),
        get_info("sites", "DNAC Sites", "fas fa-map-marker-alt", "secondary", "/api/dnac/cache/refresh"),
        get_info("pan_interfaces", "Firewall Interfaces", "fas fa-shield-alt", "danger", "/api/firewall/interfaces/refresh"),
        get_info("nexus_inventory", "Nexus Switch Inventory", "fas fa-server", "success", "/api/nexus/refresh", sse=True),
        get_info("nexus_interfaces", "Nexus Interface Cache", "fas fa-ethernet", "info", "/api/nexus/refresh", sse=True),
    ]

    return templates.TemplateResponse(request, "partials/cache_cards.html", {"cards": cards})

@router.post("/refresh/{category}")
async def refresh_specific_cache(category: str, session: SessionEntry = Depends(require_auth)):
    if category in ("devices", "dnac"):
        cache.invalidate("devices")
        cache.invalidate("device_site_map")
    elif category == "sites":
        cache.invalidate("sites")
        cache.invalidate("device_site_map")
    elif category in ("nexus", "nexus_inventory", "nexus_interfaces"):
        cache.invalidate("nexus_inventory")
        cache.invalidate("nexus_interfaces")
    elif category in ("pan_interfaces", "firewall"):
        cache.invalidate_prefix("pan_")
    elif category == "ise":
        cache.invalidate_prefix("ise_")

    return HTMLResponse(f"""
        <div class="alert alert-success alert-dismissible fade show mb-0" role="alert">
            <strong>Success!</strong> {category.replace('_', ' ').title()} cache invalidated.
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    """)
