"""tests/test_version_compare.py — numeric-component version comparison.

Confirms the prefix-tolerant/zero-padding-tolerant semantics
utils/device_comparison_report.py needs, extracted verbatim from that
module's private _version_parts/_version_matches (see
utils/version_compare.py's module docstring)."""
from __future__ import annotations

from utils.version_compare import version_parts, versions_compatible


def test_version_parts_strips_zero_padding():
    assert version_parts("17.06.05") == (17, 6, 5)
    assert version_parts("17.6.5") == (17, 6, 5)


def test_version_parts_empty_on_no_digits():
    assert version_parts(None) == ()
    assert version_parts("") == ()
    assert version_parts("stable") == ()


def test_versions_compatible_is_prefix_tolerant():
    assert versions_compatible("17.6", "17.6.5") is True
    assert versions_compatible("17.06.05", "17.6.5") is True
    assert versions_compatible("17.6.5", "17.7.1") is False


def test_versions_compatible_true_when_either_side_unparsable():
    # device-comparison's original behavior: nothing to disagree on.
    assert versions_compatible(None, "17.6.5") is True
    assert versions_compatible("17.6.5", "") is True
