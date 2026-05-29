"""Tests for AppCache stale-while-revalidate behaviour (cache.py).

Covers the change that made logical-expiry revalidation non-blocking: an expired
but physically-present key now returns its stale value instantly and refreshes on
a background thread, instead of blocking the caller on the upstream loader.
"""
import threading
import time

import pytest

from cache import AppCache


@pytest.fixture
def cache(tmp_path):
    c = AppCache(tmp_path)
    yield c
    c._refresh_pool.shutdown(wait=False)


def _wait_for(fn, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(0.02)
    return False


def test_fresh_value_does_not_call_loader(cache):
    cache.set("k", "v1", ttl=100)
    calls = []
    out = cache.get_or_set("k", lambda: calls.append(1) or "v2", ttl=100)
    assert out == "v1"
    assert calls == []  # not expired → loader untouched


def test_true_miss_loads_synchronously(cache):
    out = cache.get_or_set("k", lambda: "fresh", ttl=100)
    assert out == "fresh"
    assert cache.get("k") == "fresh"


def test_expired_returns_stale_immediately_then_refreshes(cache):
    cache.set("k", "stale", ttl=-1)  # logically expired, physically present
    # Caller gets the stale value without blocking on the loader…
    assert cache.get_or_set("k", lambda: "fresh", ttl=100) == "stale"
    # …and the background refresh updates the stored value shortly after.
    assert _wait_for(lambda: cache.get("k") == "fresh")


def test_background_false_revalidates_synchronously(cache):
    cache.set("k", "stale", ttl=-1)
    out = cache.get_or_set("k", lambda: "fresh", ttl=100, background=False)
    assert out == "fresh"  # opt-out path blocks and returns the fresh value


def test_background_refresh_is_deduped(cache):
    cache.set("k", "stale", ttl=-1)
    count = {"n": 0}
    gate = threading.Event()

    def loader():
        count["n"] += 1
        gate.wait(2)
        return "fresh"

    # First expired read kicks off a (blocked) background refresh.
    assert cache.get_or_set("k", loader, ttl=100) == "stale"
    assert _wait_for(lambda: count["n"] == 1)  # loader has started
    # Second expired read while the first refresh is in flight must NOT submit
    # another loader run (no upstream stampede).
    assert cache.get_or_set("k", loader, ttl=100) == "stale"
    time.sleep(0.1)
    assert count["n"] == 1
    gate.set()
    assert _wait_for(lambda: cache.get("k") == "fresh")
    assert count["n"] == 1


def test_get_stale_returns_physically_present_value(cache):
    cache.set("k", "v", ttl=-1)
    assert cache.get("k") is None        # logically expired → hidden from get()
    assert cache.get_stale("k") == "v"   # but still served to display paths


def test_get_stale_missing_key_is_none(cache):
    assert cache.get_stale("nope") is None
