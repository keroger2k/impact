from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import os
import secrets

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # GET, HEAD, OPTIONS are always exempt
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)

        # Skip CSRF for Bearer authed requests (API clients)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return await call_next(request)

        path = request.url.path
        # Hard-coded exemptions for login and static
        if path == "/login" or path == "/api/auth/login" or path.startswith("/static/"):
            return await call_next(request)

        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("X-CSRF-Token")

        if not csrf_cookie or csrf_cookie != csrf_header:
            return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})

        return await call_next(request)

def set_csrf_cookie(response):
    # Double-submit token: must stay readable by JS (httponly=False) so the
    # htmx configRequest handler can echo it in the X-CSRF-Token header. Mirror
    # the session cookie's secure flag so it isn't sent over plaintext HTTP.
    secure = os.getenv("IMPACT_SECURE_COOKIES", "true").lower() == "true"
    if os.getenv("DEV_MODE", "false").lower() == "true" and os.getenv("IMPACT_SECURE_COOKIES") is None:
        secure = False
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=False,
        secure=secure,
        samesite="strict",
    )
    return token
