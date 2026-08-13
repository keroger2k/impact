"""tests/test_swim_targeting.py — split_platform_ids()/is_compatible(),
the shared stack-aware primitives behind both routers/swim.py's
compatibility gate and utils/swim_compliance.py's classification.

Confirms the fix for a real bug: DNAC reports a stacked switch's
platformId as a comma-separated list of every member's exact PID, not a
single value — matching/compliance code that looked up the whole combined
string as one key always failed for stacks, even when every individual
member PID was genuinely compatible.
"""
from __future__ import annotations

from utils.swim_targeting import is_compatible, list_facets, search_devices, split_platform_ids


def test_split_platform_ids_single_platform_unchanged():
    assert split_platform_ids("C9300-48U") == ["C9300-48U"]


def test_split_platform_ids_splits_stacked_switch():
    assert split_platform_ids("C9300-48UXM,C9300-48UXM") == ["C9300-48UXM", "C9300-48UXM"]


def test_split_platform_ids_strips_whitespace_around_commas():
    assert split_platform_ids("C9300-48UXM, C9300-24UXM") == ["C9300-48UXM", "C9300-24UXM"]


def test_split_platform_ids_does_not_split_on_slash():
    # A real single PID can contain "/" — must not be mistaken for a
    # stack delimiter.
    assert split_platform_ids("ISR4451-X/K9") == ["ISR4451-X/K9"]


def test_split_platform_ids_empty_or_none():
    assert split_platform_ids(None) == []
    assert split_platform_ids("") == []


def test_is_compatible_single_platform():
    compat = {"C9300-48U": "Cisco Catalyst 9300 Series Switches"}
    assert is_compatible({"platformId": "C9300-48U"}, compat) is True
    assert is_compatible({"platformId": "ISR4451-X/K9"}, compat) is False


def test_is_compatible_homogeneous_stack_all_members_known():
    compat = {"C9300-48UXM": "Cisco Catalyst 9300 Series Switches"}
    device = {"platformId": "C9300-48UXM,C9300-48UXM,C9300-48UXM"}
    assert is_compatible(device, compat) is True


def test_is_compatible_mixed_stack_all_members_known():
    compat = {
        "C9300-48UXM": "Cisco Catalyst 9300 Series Switches",
        "C9300-24UXM": "Cisco Catalyst 9300 Series Switches",
    }
    device = {"platformId": "C9300-48UXM,C9300-24UXM"}
    assert is_compatible(device, compat) is True


def test_is_compatible_partial_stack_coverage_is_not_compatible():
    # Only one member's PID is known to the image — an image pushed to a
    # stack affects every member at once, so partial coverage must not
    # read as compatible.
    compat = {"C9300-48UXM": "Cisco Catalyst 9300 Series Switches"}
    device = {"platformId": "C9300-48UXM,C9300-24UXM"}
    assert is_compatible(device, compat) is False


def test_is_compatible_empty_platform_id():
    assert is_compatible({"platformId": None}, {"C9300-48U": "x"}) is False
    assert is_compatible({}, {"C9300-48U": "x"}) is False


# ── list_facets() / search_devices() stack-awareness ────────────────────────

def test_list_facets_splits_stacked_platform_ids():
    devices = [
        {"id": "d1", "hostname": "h1", "platformId": "C9300-48UXM,C9300-24UXM", "family": "Switches and Hubs"},
        {"id": "d2", "hostname": "h2", "platformId": "ISR4451-X/K9", "family": "Routers"},
    ]
    facets = list_facets(devices, {})
    # Individually selectable member PIDs, not the raw combined string.
    assert facets["platforms"] == ["C9300-24UXM", "C9300-48UXM", "ISR4451-X/K9"]
    assert "C9300-48UXM,C9300-24UXM" not in facets["platforms"]


def test_search_devices_finds_stack_by_any_member_platform():
    stack = {"id": "d1", "hostname": "stack-1", "platformId": "C9300-48UXM,C9300-24UXM", "family": "Switches and Hubs"}
    other = {"id": "d2", "hostname": "other-1", "platformId": "ISR4451-X/K9", "family": "Routers"}
    result = search_devices([stack, other], {}, platforms=["C9300-24UXM"])
    assert result == [stack]
