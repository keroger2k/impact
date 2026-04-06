"""
auth.py — In-memory session management and AD authentication for IMPACT II.

Sessions are stored entirely in memory and are never written to disk.
Vendor clients (DNAC, ISE, Panorama) are created lazily per session
using the logged-in user's own credentials.
"""

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

SESSION_TTL = float(os.getenv("SESSION_TTL_HOURS", "8")) * 3600  # seconds

# ── In-memory session store ────────────────────────────────────────────────────

@dataclass
class SessionEntry:
    username:      str
    password:      str          # never logged, never persisted
    expires_at:    float
    dnac_client:   Any = field(default=None, repr=False)
    ise_client:    Any = field(default=None, repr=False)
    panorama_key:  str | None = field(default=None, repr=False)
    _lock:         Any = field(default_factory=threading.Lock, repr=False)


_sessions: dict[str, SessionEntry] = {}
_store_lock = threading.Lock()


def _purge_expired():
    now = time.monotonic()
    with _store_lock:
        expired = [t for t, s in _sessions.items() if s.expires_at <= now]
        for t in expired:
            del _sessions[t]


def create_session(username: str, password: str) -> str:
    _purge_expired()
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
    _purge_expired()
    with _store_lock:
        entry = _sessions.get(token)
    if entry is None:
        return None
    if time.monotonic() > entry.expires_at:
        destroy_session(token)
        return None
    return entry


def destroy_session(token: str):
    with _store_lock:
        entry = _sessions.pop(token, None)
    if entry:
        logger.info(f"Session destroyed for {entry.username}")


# ── LDAP authentication ────────────────────────────────────────────────────────

def validate_ldap(username: str, password: str) -> bool:
    """Attempt an LDAP simple bind to verify AD credentials.

    Requires AD_LDAP_URL env var, e.g.:
        ldaps://network.ad.tsa.gov:636
        ldap://dc01.network.ad.tsa.gov:389
    """
    ldap_url = os.getenv("AD_LDAP_URL", "")
    if not ldap_url:
        logger.warning("AD_LDAP_URL not set — auth will always fail")
        return False

    # Accept bare username or user@domain; build UPN if needed
    if "@" not in username:
        domain = _extract_domain(ldap_url)
        bind_user = f"{username}@{domain}" if domain else username
    else:
        bind_user = username

    try:
        from ldap3 import Connection, Server, SIMPLE, SYNC, ALL
        server = Server(ldap_url, get_info=ALL, connect_timeout=5)
        conn   = Connection(
            server,
            user          = bind_user,
            password      = password,
            authentication= SIMPLE,
            client_strategy=SYNC,
            raise_exceptions=False,
        )
        bound = conn.bind()
        conn.unbind()
        if not bound:
            logger.info(f"LDAP bind failed for {bind_user}: {conn.result}")
        return bound
    except Exception as e:
        logger.warning(f"LDAP error for {username}: {e}")
        return False


def _extract_domain(ldap_url: str) -> str:
    """Pull the domain from ldap(s)://host or ldap(s)://host:port."""
    host = ldap_url.split("://")[-1].split(":")[0]
    # Strip the first component (dc01.domain.com → domain.com)
    parts = host.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else host


# ── Lazy vendor client helpers ─────────────────────────────────────────────────

def get_dnac_for_session(session: SessionEntry):
    """Return (or create) the DNAC client for this session."""
    with session._lock:
        if session.dnac_client is None:
            import clients.dnac as dc
            session.dnac_client = dc.create_user_client(session.username, session.password)
    return session.dnac_client


def get_ise_for_session(session: SessionEntry):
    """Return (or create) the ISE client for this session."""
    with session._lock:
        if session.ise_client is None:
            import clients.ise as ic
            session.ise_client = ic.create_user_client(session.username, session.password)
    return session.ise_client


def get_panorama_key_for_session(session: SessionEntry) -> str:
    """Return (or generate) the Panorama API key for this session."""
    with session._lock:
        if session.panorama_key is None:
            import clients.panorama as pc
            session.panorama_key = pc.get_user_api_key(session.username, session.password)
    if not session.panorama_key:
        raise HTTPException(503, "Panorama authentication failed for your credentials")
    return session.panorama_key


# ── FastAPI dependency ─────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def require_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> SessionEntry:
    if not credentials:
        raise HTTPException(401, "Not authenticated")
    session = get_session(credentials.credentials)
    if not session:
        raise HTTPException(401, "Session expired or invalid — please log in again")
    return session
