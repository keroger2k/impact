"""
auth_persist.py — Encrypted session persistence for IMPACT II.

When SESSION_PERSIST=true, sessions are mirrored to a diskcache store at
data/sessions/diskcache/ so they survive server restarts. Passwords are
encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256) using a key
read from SESSION_ENC_KEY.
"""
import logging
import os
import time
from pathlib import Path
from typing import Optional

import diskcache
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

PERSIST_ENABLED = os.getenv("SESSION_PERSIST", "false").lower() == "true"
SESSIONS_DIR = Path(__file__).parent / "data" / "sessions" / "diskcache"

_fernet: Optional[Fernet] = None
_store: Optional[diskcache.Cache] = None


def _ensure_init() -> bool:
    """Initialize cipher + disk store on first use. Returns False if disabled."""
    global _fernet, _store
    if not PERSIST_ENABLED:
        return False
    if _fernet is not None and _store is not None:
        return True
    key = os.getenv("SESSION_ENC_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "SESSION_PERSIST=true but SESSION_ENC_KEY is not set. "
            "Generate a key with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    try:
        _fernet = Fernet(key.encode())
    except Exception as e:
        raise RuntimeError(f"SESSION_ENC_KEY is not a valid Fernet key: {e}")
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    _store = diskcache.Cache(str(SESSIONS_DIR))
    return True


def is_enabled() -> bool:
    return PERSIST_ENABLED


def save(token: str, username: str, password: str, wall_expires_at: float) -> None:
    if not _ensure_init():
        return
    try:
        encrypted = _fernet.encrypt(password.encode("utf-8"))
        ttl_seconds = max(1, int(wall_expires_at - time.time()))
        _store.set(token, {
            "username": username,
            "password_enc": encrypted,
            "wall_expires_at": wall_expires_at,
        }, expire=ttl_seconds)
    except Exception as e:
        logger.error(f"Failed to persist session for {username}: {e}")


def delete(token: str) -> None:
    if not _ensure_init():
        return
    try:
        _store.delete(token)
    except Exception as e:
        logger.error(f"Failed to delete persisted session: {e}")


def load_all() -> list[dict]:
    """Return every unexpired persisted session. Drops corrupt or undecryptable entries."""
    if not _ensure_init():
        return []
    out: list[dict] = []
    now = time.time()
    for token in list(_store.iterkeys()):
        try:
            entry = _store.get(token)
            if not entry:
                continue
            wall_expires = entry.get("wall_expires_at", 0)
            if wall_expires <= now:
                _store.delete(token)
                continue
            password = _fernet.decrypt(entry["password_enc"]).decode("utf-8")
            out.append({
                "token": token,
                "username": entry["username"],
                "password": password,
                "wall_expires_at": wall_expires,
            })
        except InvalidToken:
            logger.warning(f"Discarding persisted session — encryption key mismatch")
            _store.delete(token)
        except Exception as e:
            logger.error(f"Failed to restore persisted session: {e}")
            _store.delete(token)
    return out
