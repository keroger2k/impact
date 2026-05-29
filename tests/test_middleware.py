"""T2/T3 — SSE concurrency limiter (main.sse_rate_limit) and CSRF middleware.

Both are exercised by calling the middleware callables directly with minimal
fakes, so no live server/auth is needed.
"""
from types import SimpleNamespace

import pytest


# ── T2: SSE concurrency limiter ────────────────────────────────────────────────

def _sse_req(path, token="tok"):
    return SimpleNamespace(url=SimpleNamespace(path=path),
                           cookies={"impact_token": token} if token else {})


class _StreamResp:
    def __init__(self):
        async def _gen():
            yield b"data: x\n\n"
        self.body_iterator = _gen()


async def _call_next(_req):
    return _StreamResp()


@pytest.mark.asyncio
async def test_sse_limiter_caps_then_frees_a_slot():
    import main
    main.sse_limit_tracker.clear()
    path = "/api/warm"

    r1 = await main.sse_rate_limit(_sse_req(path), _call_next)
    r2 = await main.sse_rate_limit(_sse_req(path), _call_next)
    # Two streams are now "active" (their wrapped bodies haven't drained).
    r3 = await main.sse_rate_limit(_sse_req(path), _call_next)
    assert getattr(r3, "status_code", None) == 429

    # Draining r1's wrapped body must release its slot (the Part-2/S2 fix).
    async for _ in r1.body_iterator:
        pass
    r4 = await main.sse_rate_limit(_sse_req(path), _call_next)
    assert getattr(r4, "status_code", None) != 429

    # Drain remaining so the tracker ends clean.
    async for _ in r2.body_iterator:
        pass
    async for _ in r4.body_iterator:
        pass
    assert main.sse_limit_tracker.get(("tok", path), 0) == 0


@pytest.mark.asyncio
async def test_sse_limiter_ignores_unlimited_paths():
    import main
    main.sse_limit_tracker.clear()
    r = await main.sse_rate_limit(_sse_req("/api/dnac/devices"), _call_next)
    assert getattr(r, "status_code", None) != 429


# ── T3: CSRF middleware ────────────────────────────────────────────────────────

def _csrf_req(method="POST", path="/api/registry/sites", headers=None, cookies=None):
    return SimpleNamespace(method=method, headers=headers or {},
                           url=SimpleNamespace(path=path), cookies=cookies or {})


async def _ok(_req):
    return "PASSED"


def _mw():
    from utils.csrf import CSRFMiddleware
    return CSRFMiddleware(app=lambda *a, **k: None)


@pytest.mark.asyncio
async def test_csrf_get_is_exempt():
    assert await _mw().dispatch(_csrf_req(method="GET"), _ok) == "PASSED"


@pytest.mark.asyncio
async def test_csrf_bearer_is_exempt():
    req = _csrf_req(headers={"Authorization": "Bearer xyz"})
    assert await _mw().dispatch(req, _ok) == "PASSED"


@pytest.mark.asyncio
async def test_csrf_login_path_is_exempt():
    assert await _mw().dispatch(_csrf_req(path="/api/auth/login"), _ok) == "PASSED"


@pytest.mark.asyncio
async def test_csrf_missing_token_is_403():
    out = await _mw().dispatch(_csrf_req(), _ok)
    assert getattr(out, "status_code", None) == 403


@pytest.mark.asyncio
async def test_csrf_mismatched_token_is_403():
    req = _csrf_req(headers={"X-CSRF-Token": "a"}, cookies={"csrf_token": "b"})
    out = await _mw().dispatch(req, _ok)
    assert getattr(out, "status_code", None) == 403


@pytest.mark.asyncio
async def test_csrf_matching_token_passes():
    req = _csrf_req(headers={"X-CSRF-Token": "match"}, cookies={"csrf_token": "match"})
    assert await _mw().dispatch(req, _ok) == "PASSED"
