"""tests/test_dnac_client.py — clients.dnac pagination semantics.

Covers get_all_devices' `strict` flag specifically. The two modes exist for
genuinely different callers and the difference is easy to erase by accident:
cache warming wants whatever inventory it can get, while the DNAC/SolarWinds
comparison report needs all-or-nothing, since a silently-truncated list there
fabricates "in SolarWinds but not DNAC" rows and that report offers a button
to onboard them.
"""
import pytest
from clients.dnac import get_all_devices


class _Page:
    def __init__(self, items):
        self.response = items


class _FakeDnac:
    """Paginates 500 at a time; `fail_at_offset` raises for one page."""

    def __init__(self, pages, fail_at_offset=None):
        self.pages = pages
        self.fail_at_offset = fail_at_offset
        self.devices = self

    def get_device_list(self, limit, offset):
        if offset == self.fail_at_offset:
            raise RuntimeError(f"DNAC page {offset} failed")
        return _Page(self.pages.get(offset, []))


def _full_page(prefix):
    return [{"hostname": f"{prefix}-{i}", "managementIpAddress": f"1.2.3.{i}"} for i in range(500)]


def test_single_page():
    dnac = _FakeDnac({1: [{"hostname": "R-SITE-01"}]})
    assert len(get_all_devices(dnac)) == 1


def test_paginates_until_a_short_page():
    dnac = _FakeDnac({1: _full_page("a"), 501: [{"hostname": "R-SITE-99"}]})
    assert len(get_all_devices(dnac)) == 501


def test_first_page_failure_always_raises():
    """True in both modes — an empty list cached for days is worse than an
    error, and it's the behaviour that predates `strict`."""
    dnac = _FakeDnac({1: []}, fail_at_offset=1)
    for strict in (False, True):
        with pytest.raises(RuntimeError):
            get_all_devices(dnac, strict=strict)


def test_non_strict_keeps_a_partial_list_on_a_later_page_failure():
    dnac = _FakeDnac({1: _full_page("a"), 501: _full_page("b")}, fail_at_offset=501)
    devices = get_all_devices(dnac)
    assert len(devices) == 500  # page 1 only, silently truncated


def test_strict_raises_on_a_later_page_failure():
    """The case that matters for the comparison report: without this, the
    500 devices on the failed page become fabricated gaps."""
    dnac = _FakeDnac({1: _full_page("a"), 501: _full_page("b")}, fail_at_offset=501)
    with pytest.raises(RuntimeError, match="page 501"):
        get_all_devices(dnac, strict=True)


def test_strict_defaults_to_false_so_cache_warming_is_unchanged():
    dnac = _FakeDnac({1: _full_page("a"), 501: _full_page("b")}, fail_at_offset=501)
    assert len(get_all_devices(dnac)) == len(get_all_devices(dnac, strict=False))
