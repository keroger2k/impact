import os
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Depends, Form, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from templates_module import templates
import auth as auth_module
from auth import SessionEntry, verify_ldap_or_mock
from cache import IPAM_TREE_CACHE_KEY
import logging

logger = logging.getLogger(__name__)

router = APIRouter(include_in_schema=False)

async def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("impact_token")
    if not token:
        return None
    return auth_module.get_session(token)

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse(request, "login.html", {"error": error, "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true"})

@router.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else ""
    if auth_module.login_throttled(ip, username):
        return RedirectResponse(
            url="/login?error=Too many failed attempts. Please wait a few minutes and try again.",
            status_code=303)

    user_creds = verify_ldap_or_mock(username, password)
    if not user_creds:
        auth_module.record_login_failure(ip, username)
        return RedirectResponse(url="/login?error=Invalid credentials", status_code=303)
    auth_module.record_login_success(ip, username)

    token = auth_module.create_session(user_creds[0], user_creds[1])
    response = RedirectResponse(url="/dashboard", status_code=303)
    cookie_kwargs = auth_module.session_cookie_kwargs()
    response.set_cookie("impact_token", token, **cookie_kwargs)
    # impact_user is cosmetic (topbar display name); it need not be httponly but
    # gets the same secure/samesite/lifetime scoping.
    response.set_cookie("impact_user", username,
                        secure=cookie_kwargs["secure"], samesite="strict",
                        max_age=cookie_kwargs["max_age"])

    from utils.csrf import set_csrf_cookie
    set_csrf_cookie(response)

    return response

@router.get("/")
async def root(user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user:
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/dashboard")

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from routers.dnac import device_stats

    # Only the cheap, cached pieces are computed inline: device stats (cached
    # inventory) and connectivity status (cached + probed in parallel). The
    # expensive widgets — recent issues and live ACI health/faults — load lazily
    # via /api/dnac/dashboard-activity so the page paints immediately.
    stats = await device_stats(user)

    from utils.system_status import get_system_status
    current_status = await get_system_status(user)

    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "dashboard",
        "username": user.username,
        "stats": stats,
        "systems_online": len([s for s in current_status.values() if s.get("ok")]),
        "systems_total": len(current_status),
        **current_status
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/dashboard_content.html", context)
    return templates.TemplateResponse(request, "dashboard.html", context)

@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    # The inventory is fetched client-side via /api/dnac/devices (cached) so the
    # page swap stays small; no need to render the full device list inline.
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "devices",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/devices_content.html", context)
    return templates.TemplateResponse(request, "devices.html", context)

@router.get("/routing/bgp", response_class=HTMLResponse)
async def bgp_dashboard_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "routing",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/routing_content.html", context)
    return templates.TemplateResponse(request, "routing.html", context)

@router.get("/path-trace", response_class=HTMLResponse)
async def path_trace_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "path-trace",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/path_trace_content.html", context)
    return templates.TemplateResponse(request, "path_trace.html", context)

@router.get("/ise", response_class=HTMLResponse)
async def ise_page_render(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "ise",
        "username": user.username
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/ise_content.html", context)
    return templates.TemplateResponse(request, "ise.html", context)

@router.get("/firewall", response_class=HTMLResponse)
async def firewall_page_render(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "firewall",
        "username": user.username
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/firewall_content.html", context)
    return templates.TemplateResponse(request, "firewall.html", context)

@router.get("/aci", response_class=HTMLResponse)
async def aci_page_render(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "aci",
        "username": user.username
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/aci_content.html", context)
    return templates.TemplateResponse(request, "aci.html", context)

@router.get("/nexus", response_class=HTMLResponse)
async def nexus_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "nexus",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/nexus_content.html", context)
    return templates.TemplateResponse(request, "nexus.html", context)

@router.get("/nexus/{hostname}", response_class=HTMLResponse)
async def nexus_device_page(request: Request, hostname: str, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "nexus",
        "hostname": hostname,
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/nexus_device_content.html", context)
    return templates.TemplateResponse(request, "nexus_device.html", context)

@router.get("/f5", response_class=HTMLResponse)
async def f5_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "f5",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/f5_content.html", context)
    return templates.TemplateResponse(request, "f5.html", context)

@router.get("/f5/{hostname}", response_class=HTMLResponse)
async def f5_device_page(request: Request, hostname: str, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "f5",
        "hostname": hostname,
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/f5_device_content.html", context)
    return templates.TemplateResponse(request, "f5_device.html", context)

@router.get("/command-runner", response_class=HTMLResponse)
async def command_runner_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    if os.getenv("COMMANDS_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Command execution is disabled")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "config_changes_enabled": os.getenv("CONFIG_CHANGES_ENABLED", "false").lower() == "true",
        "active_page": "command-runner",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/command_runner_content.html", context)
    return templates.TemplateResponse(request, "command_runner.html", context)

@router.get("/import", response_class=HTMLResponse)
async def import_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "import",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/import_content.html", context)
    return templates.TemplateResponse(request, "import.html", context)

@router.get("/config-search", response_class=HTMLResponse)
async def config_search_page(request: Request, response: Response, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from utils.csrf import set_csrf_cookie
    set_csrf_cookie(response)
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "config-search",
        "username": user.username,
        "query": request.query_params.get("q", "")
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/config_search_content.html", context)
    return templates.TemplateResponse(request, "config_search.html", context)

@router.get("/ip-lookup", response_class=HTMLResponse)
async def ip_lookup_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "ip-lookup",
        "username": user.username
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/ip_lookup_content.html", context)
    return templates.TemplateResponse(request, "ip_lookup.html", context)

@router.get("/ipam", response_class=HTMLResponse)
async def ipam_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from cache import cache
    # Read-only display: prefer last-known tree over a blank page when the TTL
    # has rolled over (the tree is rebuilt explicitly via the IPAM refresh SSE).
    ipam_tree = cache.get_stale(IPAM_TREE_CACHE_KEY)

    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "ipam",
        "username": user.username,
        "initial_ipam_tree": ipam_tree
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/ipam_content.html", context)
    return templates.TemplateResponse(request, "ipam.html", context)

@router.get("/ipv6-registry", response_class=HTMLResponse)
async def ipv6_registry_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from clients import ipv6_registry as registry
    sites = registry.list_sites()
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "ipv6-registry",
        "username": user.username,
        "sites": sites,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/ipv6_registry_content.html", context)
    return templates.TemplateResponse(request, "ipv6_registry.html", context)


@router.get("/registry", response_class=HTMLResponse)
async def registry_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from clients import ip_registry as registry
    sites = registry.list_sites()
    prefixes = registry.list_prefixes()
    by_site: dict = {}
    for p in prefixes:
        if p["site_id"] is not None:
            by_site.setdefault(p["site_id"], []).append(p)
    items = [{
        **s,
        "v4_count": sum(1 for p in by_site.get(s["id"], []) if p["family"] == 4),
        "v6_count": sum(1 for p in by_site.get(s["id"], []) if p["family"] == 6),
        "prefix_count": len(by_site.get(s["id"], [])),
    } for s in sites]
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "registry",
        "username": user.username,
        "sites": items,
        "v6_site_prefixes": [p for p in prefixes if p["family"] == 6 and not (p["site_id"] is None and p.get("role") == "container")],
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/registry_content.html", context)
    return templates.TemplateResponse(request, "registry.html", context)


@router.get("/tunnels", response_class=HTMLResponse)
async def tunnels_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "tunnels",
        "username": user.username,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/tunnels_content.html", context)
    return templates.TemplateResponse(request, "tunnels.html", context)


@router.get("/site", response_class=HTMLResponse)
async def site_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "site",
        "username": user.username,
        "initial_code": None,
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/site_content.html", context)
    return templates.TemplateResponse(request, "site.html", context)


@router.get("/site/{code}", response_class=HTMLResponse)
async def site_page_with_code(request: Request, code: str, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "site",
        "username": user.username,
        "initial_code": code.upper(),
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/site_content.html", context)
    return templates.TemplateResponse(request, "site.html", context)


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, response: Response, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from utils.csrf import set_csrf_cookie
    set_csrf_cookie(response)
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "reports",
        "username": user.username,
        "default_report_date": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"),
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/reports_content.html", context)
    return templates.TemplateResponse(request, "reports.html", context)

@router.get("/cache-mgmt", response_class=HTMLResponse)
async def cache_mgmt_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "cache-mgmt",
        "username": user.username
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/cache_management_content.html", context)
    return templates.TemplateResponse(request, "cache_management.html", context)
