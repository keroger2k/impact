"""Regression tests for Panorama stale-API-key detection and auto-refresh.

Covers the bug where a cached Panorama API key, once rejected by Panorama with
``403 / Invalid Credential``, was reused indefinitely with no recovery path — so
every subsequent call (and cache-loader refresh) kept failing until the session
expired or the process restarted.
"""
from __future__ import annotations

import time

import pytest

import clients.panorama as pc


class _FakeResp:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


# ── classifier ────────────────────────────────────────────────────────────────

def test_is_invalid_credential_detects_403_and_message():
    assert pc._is_invalid_credential(403, "anything") is True
    assert pc._is_invalid_credential(200, "API Error: Invalid Credential") is True
    assert pc._is_invalid_credential(200, "invalid credential") is True  # case-insensitive
    assert pc._is_invalid_credential(200, "<response status='success'/>") is False
    assert pc._is_invalid_credential(None, None) is False


# ── low-level HTTP boundary raises the typed error ────────────────────────────

def test_config_get_raises_auth_error_on_403(monkeypatch):
    monkeypatch.setenv("PANORAMA_HOST", "panorama.example.com")
    monkeypatch.setattr(
        pc.requests, "get",
        lambda *a, **k: _FakeResp(403, "<response code='403'><msg>Invalid Credential</msg></response>"),
    )
    with pytest.raises(pc.PanoramaAuthError):
        pc._config_get("/config/shared/address", "stale-key")


def test_op_raises_auth_error_on_invalid_credential_body(monkeypatch):
    monkeypatch.setenv("PANORAMA_HOST", "panorama.example.com")
    monkeypatch.setattr(
        pc.requests, "get",
        lambda *a, **k: _FakeResp(200, "<response status='error'><msg>Invalid Credential</msg></response>"),
    )
    with pytest.raises(pc.PanoramaAuthError):
        pc._op("<show><system><info/></system></show>", "stale-key")


def test_get_device_groups_classifies_sdk_auth_error(monkeypatch):
    monkeypatch.setenv("PANORAMA_HOST", "panorama.example.com")

    def _boom(*a, **k):
        raise Exception("URLError: code: 403 reason: API Error: Invalid Credential")

    monkeypatch.setattr(pc.DeviceGroup, "refreshall", staticmethod(_boom))
    with pytest.raises(pc.PanoramaAuthError):
        pc.get_device_groups("stale-key")


# ── auth errors must propagate past the per-section swallow blocks ─────────────

def test_address_objects_propagate_auth_error(monkeypatch):
    """A stale key must surface, not be swallowed into an empty result dict."""
    def _auth_fail(*a, **k):
        raise pc.PanoramaAuthError("Invalid Credential")

    monkeypatch.setattr(pc, "_config_get", _auth_fail)
    with pytest.raises(pc.PanoramaAuthError):
        pc.get_address_objects_and_groups("stale-key", ["DG1"])


def test_security_rules_propagate_auth_error(monkeypatch):
    def _auth_fail(*a, **k):
        raise pc.PanoramaAuthError("Invalid Credential")

    monkeypatch.setattr(pc, "_config_get", _auth_fail)
    with pytest.raises(pc.PanoramaAuthError):
        pc.get_all_security_rules("stale-key", ["DG1"])


def test_managed_devices_propagate_auth_error(monkeypatch):
    def _auth_fail(*a, **k):
        raise pc.PanoramaAuthError("Invalid Credential")

    monkeypatch.setattr(pc, "_op", _auth_fail)
    with pytest.raises(pc.PanoramaAuthError):
        pc.get_managed_devices("stale-key")


def test_non_auth_error_still_swallowed(monkeypatch):
    """Genuinely-missing sections (non-auth failures) stay tolerant → empty result."""
    def _other_fail(*a, **k):
        raise pc.PanoramaAPIError("xpath not found")

    monkeypatch.setattr(pc, "_config_get", _other_fail)
    objects, groups = pc.get_address_objects_and_groups("good-key", ["DG1"])
    assert objects == {} and groups == {}


# ── force-refresh bypasses the module key cache ───────────────────────────────

def test_get_user_api_key_force_bypasses_cache(monkeypatch):
    monkeypatch.setenv("PANORAMA_HOST", "panorama.example.com")
    pc._key_cache.clear()
    pc._key_cache["panorama.example.com:user"] = ("cached-key", time.time() + 10_000)
    monkeypatch.setattr(pc, "_keygen", lambda u, p: "fresh-key")

    assert pc.get_user_api_key("user", "pw") == "cached-key"          # cache hit
    assert pc.get_user_api_key("user", "pw", force=True) == "fresh-key"  # bypass
    # cache is now updated with the fresh key
    assert pc._key_cache["panorama.example.com:user"][0] == "fresh-key"
    pc._key_cache.clear()


# ── router loader retries once with a regenerated key ─────────────────────────

def test_pan_loader_retries_on_stale_key(monkeypatch):
    import routers.firewall as fw

    def fake_get_key(session, force_refresh=False):
        return "fresh-key" if force_refresh else "stale-key"

    monkeypatch.setattr(fw, "_get_key", fake_get_key)

    seen = []

    def op(key):
        seen.append(key)
        if key == "stale-key":
            raise pc.PanoramaAuthError("Invalid Credential")
        return ["DG1", "DG2"]

    loader = fw._pan_loader(object(), op)
    assert loader() == ["DG1", "DG2"]
    assert seen == ["stale-key", "fresh-key"]  # tried stale, refreshed, retried


def test_pan_loader_no_retry_on_success(monkeypatch):
    import routers.firewall as fw

    calls = []
    monkeypatch.setattr(fw, "_get_key",
                        lambda session, force_refresh=False: "good-key")

    def op(key):
        calls.append(key)
        return ["DG1"]

    assert fw._pan_loader(object(), op)() == ["DG1"]
    assert calls == ["good-key"]  # one call, no forced refresh


def test_pan_loader_does_not_retry_non_auth_error(monkeypatch):
    import routers.firewall as fw

    forced = []

    def fake_get_key(session, force_refresh=False):
        forced.append(force_refresh)
        return "good-key"

    monkeypatch.setattr(fw, "_get_key", fake_get_key)

    def op(key):
        raise pc.PanoramaAPIError("real upstream error")

    with pytest.raises(pc.PanoramaAPIError):
        fw._pan_loader(object(), op)()
    assert forced == [False]  # never force-refreshed for a non-auth failure
