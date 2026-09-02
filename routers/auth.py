"""routers/auth.py — Login / logout / session check endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

import auth as auth_module

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(req: LoginRequest, request: Request, response: Response):
    if not req.username or not req.password:
        raise HTTPException(400, "Username and password are required")

    ip = request.client.host if request.client else ""
    if auth_module.login_throttled(ip, req.username):
        raise HTTPException(429, "Too many failed attempts. Please wait a few minutes and try again.")

    ok = await _run_sync(auth_module.validate_ldap, req.username, req.password)
    if not ok:
        auth_module.record_login_failure(ip, req.username)
        raise HTTPException(401, "Invalid credentials — check your username and password")
    auth_module.record_login_success(ip, req.username)

    token = auth_module.create_session(req.username, req.password)

    # Shared cookie security flags (see auth.session_cookie_kwargs).
    response.set_cookie("impact_token", token, **auth_module.session_cookie_kwargs())

    from utils.csrf import set_csrf_cookie
    set_csrf_cookie(response)

    # The token travels only in the httponly cookie — returning it in the
    # JSON body too would hand it to any script that can read a login
    # response, defeating httponly. No frontend code reads it (checked), and
    # a headless Bearer client can be given a token out of band if ever needed.
    return {"username": req.username}


@router.post("/logout")
async def logout(response: Response, session: auth_module.SessionEntry = Depends(auth_module.require_auth)):
    # Delete the cookie
    response.delete_cookie("impact_token")

    # Deliberate: destroy EVERY session for this username (all browsers/
    # devices), not just this token — "log out" here means "this account is
    # done", matching how shared-workstation operators use the app.
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
