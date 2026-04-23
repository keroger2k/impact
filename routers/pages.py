import os
from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from templates_module import templates
import auth as auth_module
from auth import SessionEntry, verify_ldap_or_mock
from logger_config import run_with_context
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
    user_creds = verify_ldap_or_mock(username, password)
    if not user_creds:
        return RedirectResponse(url="/login?error=Invalid credentials", status_code=303)

    token = auth_module.create_session(user_creds[0], user_creds[1])
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="impact_token", value=token)
    response.set_cookie(key="impact_user", value=username)

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
    from routers.dnac import device_stats, _get_dnac
    import clients.dnac as dc
    import asyncio

    loop = asyncio.get_event_loop()
    dnac = _get_dnac(user)

    stats = await device_stats(user)
    issues = await loop.run_in_executor(None, run_with_context(dc.get_recent_issues), dnac)

    # Status check is live
    from utils.system_status import get_system_status
    current_status = await get_system_status(user)

    # Fetch ACI health and faults for dashboard if ACI is online
    aci_health = None
    aci_faults = []
    if current_status.get("aci", {}).get("ok"):
        from routers.aci import get_health_summary, list_faults
        try:
            aci_health = await get_health_summary(user)
            faults_resp = await list_faults(request, severity=None, session=user)
            aci_faults = faults_resp.get("items", []) if isinstance(faults_resp, dict) else []
        except Exception as e:
            logger.warning(f"Failed to fetch ACI dashboard data: {e}")

    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "dashboard",
        "username": user.username,
        "stats": stats,
        "issues": issues,
        "aci_health": aci_health,
        "aci_faults": aci_faults,
        "systems_online": len([s for s in current_status.values() if s.get("ok")]),
        **current_status
    }
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "pages/dashboard_content.html", context)
    return templates.TemplateResponse(request, "dashboard.html", context)

@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    from routers.dnac import get_devices_data
    devices_resp = await get_devices_data(session=user, limit=5000)
    devices = devices_resp.get("items", [])

    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "devices",
        "username": user.username,
        "initial_devices": devices
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

@router.get("/command-runner", response_class=HTMLResponse)
async def command_runner_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    if os.getenv("COMMANDS_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Command execution is disabled")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
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
async def config_search_page(request: Request, user: SessionEntry = Depends(get_current_user_from_cookie)):
    if not user: return RedirectResponse(url="/login")
    context = {
        "debug_enabled": os.getenv("CONSOLE_LOG_LEVEL", "INFO") == "DEBUG" or os.getenv("DEV_MODE", "false").lower() == "true",
        "commands_enabled": os.getenv("COMMANDS_ENABLED", "false").lower() == "true",
        "active_page": "config-search",
        "username": user.username
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
    ipam_tree = cache.get("ipam_tree")

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
