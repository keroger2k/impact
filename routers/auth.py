"""routers/auth.py — Login / logout / session check endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

import auth as auth_module

router = APIRouter()
logger = logging.getLogger(__name__)


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(req: LoginRequest, response: Response):
    if not req.username or not req.password:
        raise HTTPException(400, "Username and password are required")

    ok = await _run_sync(auth_module.validate_ldap, req.username, req.password)
    if not ok:
        raise HTTPException(401, "Invalid credentials — check your username and password")

    token = auth_module.create_session(req.username, req.password)

    # Set impact_token cookie with proper flags
    from os import getenv
    from dev import DEV_MODE
    secure_cookies = getenv("IMPACT_SECURE_COOKIES", "true").lower() == "true"
    if DEV_MODE and getenv("IMPACT_SECURE_COOKIES") is None:
        secure_cookies = False

    response.set_cookie(
        key="impact_token",
        value=token,
        httponly=True,
        secure=secure_cookies,
        samesite="strict",
        max_age=int(auth_module.SESSION_TTL),
    )

    from utils.csrf import set_csrf_cookie
    set_csrf_cookie(response)

    return {"token": token, "username": req.username}


@router.post("/logout")
async def logout(response: Response, session: auth_module.SessionEntry = Depends(auth_module.require_auth)):
    # Delete the cookie
    response.delete_cookie("impact_token")

    # We pass session so require_auth already validated it; destroy by username match
    import auth as a
    with a._store_lock:
        tokens = [t for t, s in a._sessions.items() if s.username == session.username]
    for t in tokens:
        a.destroy_session(t)
    return {"status": "logged out"}


@router.get("/me")
async def me(session: auth_module.SessionEntry = Depends(auth_module.require_auth)):
    return {"username": session.username}


async def _run_sync(fn, *args):
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)
