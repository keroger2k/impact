"""
auth.py — In-memory session management and AD authentication for IMPACT II.
"""
import logging
import os
import secrets
import threading
import time
import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)
SESSION_TTL = float(os.getenv("SESSION_TTL_HOURS", "8")) * 3600  # seconds
PURGE_INTERVAL = 60

@dataclass
class SessionEntry:
    username:     str
    password:     str
    expires_at:   float
    dnac_client:  Any = field(default=None, repr=False)
    ise_client:   Any = field(default=None, repr=False)
    aci_client:   Any = field(default=None, repr=False)
    panorama_key: str | None = field(default=None, repr=False)
    _lock:        Any = field(default_factory=threading.Lock, repr=False)

_sessions: dict[str, SessionEntry] = {}
_store_lock = threading.Lock()

def _purge_expired():
    now = time.monotonic()
    with _store_lock:
        expired = [t for t, s in _sessions.items() if s.expires_at <= now]
        for t in expired:
            del _sessions[t]
        if expired:
            logger.info(f"Purged {len(expired)} expired sessions")

async def session_gc_task():
    """Background task to purge expired sessions."""
    while True:
        try:
            _purge_expired()
        except Exception as e:
            logger.error(f"Session GC error: {e}")
        await asyncio.sleep(PURGE_INTERVAL)

def create_session(username: str, password: str) -> str:
    token = secrets.token_urlsafe(32)
    entry = SessionEntry(
        username   = username,
        password   = password,
        expires_at = time.monotonic() + SESSION_TTL,
    )
    with _store_lock:
        _sessions[token] = entry
    logger.info(f"Session created for {username}")
    return token

def get_session(token: str) -> SessionEntry | None:
    with _store_lock:
        entry = _sessions.get(token)
    if entry is None:
        return None
    if time.monotonic() > entry.expires_at:
        return None
    return entry

def destroy_session(token: str):
    with _store_lock:
        entry = _sessions.pop(token, None)
    if entry:
        logger.info(f"Session destroyed for {entry.username}")

def validate_ldap(username: str, password: str) -> bool:
    from dev import DEV_MODE
    if DEV_MODE: return True
    ldap_url = os.getenv("AD_LDAP_URL", "")
    if not ldap_url or not ldap_url.lower().startswith("ldaps://"):
        logger.error("AD_LDAP_URL must use ldaps:// protocol for security")
        return False
    try:
        from ldap3 import Connection, Server, SIMPLE, SYNC, ALL
        server = Server(ldap_url, get_info=ALL, connect_timeout=5)
        conn   = Connection(server, user=username, password=password, authentication=SIMPLE, client_strategy=SYNC, raise_exceptions=False)
        bound = conn.bind()
        conn.unbind()
        return bound
    except Exception as e:
        logger.warning(f"LDAP error for {username}: {e}")
        return False

def get_dnac_for_session(session: SessionEntry):
    with session._lock:
        if session.dnac_client is None:
            import clients.dnac as dc
            session.dnac_client = dc.create_user_client(session.username, session.password)
    return session.dnac_client

def get_ise_for_session(session: SessionEntry):
    from dev import DEV_MODE
    if DEV_MODE:
        class MockISE:
            def __init__(self):
                self.custom_caller = type('CC', (), {'call_api': lambda *a, **k: None})
        return MockISE()
    with session._lock:
        if session.ise_client is None:
            import clients.ise as ic
            session.ise_client = ic.create_user_client(session.username, session.password)
    return session.ise_client

def get_panorama_key_for_session(session: SessionEntry) -> str:
    from dev import DEV_MODE
    if DEV_MODE: return "mock-pan-key"
    with session._lock:
        if session.panorama_key is None:
            import clients.panorama as pc
            session.panorama_key = pc.get_user_api_key(session.username, session.password)
    if not session.panorama_key:
        raise HTTPException(503, "Panorama authentication failed")
    return session.panorama_key

def get_aci_for_session(session: SessionEntry):
    from dev import DEV_MODE
    if DEV_MODE:
        import clients.aci as ac
        return ac.ACIClient("https://mock-apic", session.username, session.password)
    with session._lock:
        if session.aci_client is None:
            import clients.aci as ac
            url = os.getenv("ACI_URL")
            domain = os.getenv("ACI_DOMAIN")
            session.aci_client = ac.ACIClient(url, session.username, session.password, domain)
            session.aci_client.login()
    return session.aci_client

_bearer = HTTPBearer(auto_error=False)

def require_auth(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> SessionEntry:
    token = credentials.credentials if credentials else request.cookies.get("impact_token")
    if not token: raise HTTPException(401, "Not authenticated")
    session = get_session(token)
    if not session: raise HTTPException(401, "Session expired or invalid")
    with _store_lock:
        session.expires_at = time.monotonic() + SESSION_TTL
    return session

def verify_ldap_or_mock(username: str, password: str) -> tuple[str, str] | None:
    from dev import DEV_MODE
    if DEV_MODE: return username, password
    if validate_ldap(username, password): return username, password
    return None
