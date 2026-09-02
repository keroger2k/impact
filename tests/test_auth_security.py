"""Tests for the Part-2 auth/session hardening (auth.py + cookie flags).

Covers the login throttle (S4), the absolute session-lifetime cap (S5) and the
shared session-cookie flags (S1). DEV_MODE is on (see conftest), so secure
cookies default off unless IMPACT_SECURE_COOKIES is set.
"""
import time

import pytest
from fastapi import HTTPException

import auth


class FakeRequest:
    """Minimal stand-in for require_auth (only reads request.cookies)."""
    def __init__(self, token=None):
        self.cookies = {"impact_token": token} if token else {}


# ── Login throttle (S4) ───────────────────────────────────────────────────────

def test_login_throttle_trips_after_max(monkeypatch):
    auth._login_failures.clear()
    ip, user = "1.2.3.4", "alice"
    assert not auth.login_throttled(ip, user)
    for _ in range(auth._LOGIN_FAIL_MAX):
        auth.record_login_failure(ip, user)
    assert auth.login_throttled(ip, user)


def test_login_success_clears_throttle():
    auth._login_failures.clear()
    ip, user = "1.2.3.4", "alice"
    for _ in range(auth._LOGIN_FAIL_MAX):
        auth.record_login_failure(ip, user)
    assert auth.login_throttled(ip, user)
    auth.record_login_success(ip, user)
    assert not auth.login_throttled(ip, user)


def test_login_throttle_is_per_ip_and_user():
    auth._login_failures.clear()
    for _ in range(auth._LOGIN_FAIL_MAX):
        auth.record_login_failure("1.1.1.1", "alice")
    assert auth.login_throttled("1.1.1.1", "alice")
    assert not auth.login_throttled("2.2.2.2", "alice")   # different source IP
    assert not auth.login_throttled("1.1.1.1", "bob")      # different username


def test_prune_drops_aged_out_entries():
    auth._login_failures.clear()
    auth._login_failures["1.1.1.1|alice"] = [time.monotonic() - auth._LOGIN_FAIL_WINDOW - 1]
    auth._prune_login_failures()
    assert "1.1.1.1|alice" not in auth._login_failures


# ── Absolute session lifetime (S5) ────────────────────────────────────────────

def test_session_slides_within_cap():
    token = auth.create_session("u", "p")
    try:
        sess = auth.require_auth(FakeRequest(token), credentials=None)
        assert sess.username == "u"
    finally:
        auth.destroy_session(token)


def test_session_expires_at_absolute_cap():
    token = auth.create_session("u", "p")
    sess = auth._sessions[token]
    sess.created_at = time.monotonic() - auth.SESSION_ABS_MAX - 10
    with pytest.raises(HTTPException) as ei:
        auth.require_auth(FakeRequest(token), credentials=None)
    assert ei.value.status_code == 401
    assert auth._sessions.get(token) is None  # destroyed on the way out


def test_missing_token_is_401():
    with pytest.raises(HTTPException) as ei:
        auth.require_auth(FakeRequest(None), credentials=None)
    assert ei.value.status_code == 401


# ── Shared cookie flags (S1) ──────────────────────────────────────────────────

def test_cookie_kwargs_dev_defaults(monkeypatch):
    monkeypatch.delenv("IMPACT_SECURE_COOKIES", raising=False)
    kw = auth.session_cookie_kwargs()
    assert kw["httponly"] is True
    assert kw["samesite"] == "strict"
    assert kw["secure"] is False  # DEV_MODE + unset override
    # The cookie lives to the ABSOLUTE session cap, not the sliding idle TTL —
    # a cookie capped at the idle TTL would hard-log-out an actively-working
    # user at exactly SESSION_TTL while their server-side session was still
    # valid (the idle timeout is enforced server-side in require_auth).
    assert kw["max_age"] == int(auth.SESSION_ABS_MAX)


def test_cookie_kwargs_secure_when_forced(monkeypatch):
    monkeypatch.setenv("IMPACT_SECURE_COOKIES", "true")
    assert auth.session_cookie_kwargs()["secure"] is True
