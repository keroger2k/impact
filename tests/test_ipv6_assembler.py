"""Tests for utils.ipv6_assembler — pure conversion math."""
from __future__ import annotations

import ipaddress

import pytest

from utils.ipv6_assembler import (
    assemble,
    decode,
    find_overlap,
    ipv4_to_suffix,
    next_block,
    normalize_prefix,
    normalize_prefix_48,
    normalize_vvvv,
    validate_prefix_length,
    validate_site_prefix_length,
    vvvv_block_size,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def test_normalize_prefix_48_strips_leading_zeros():
    assert normalize_prefix_48("0100:0200:0300") == "100:200:300"
    assert normalize_prefix_48("100:200:300") == "100:200:300"


def test_normalize_prefix_handles_variable_length():
    # /48 trims trailing zero hextets
    assert normalize_prefix("1000:2000:3000::", 48) == "1000:2000:3000"
    # /56 keeps 4 hextets (last one partial)
    assert normalize_prefix("1000:2000:3031:0100", 56) == "1000:2000:3031:100"
    # /32 keeps only 2
    assert normalize_prefix("1000:2000::", 32) == "1000:2000"
    # /64 keeps all 4
    assert normalize_prefix("1000:2000:3031:0100", 64) == "1000:2000:3031:100"


def test_normalize_prefix_zeroes_host_bits():
    # /56 with mismatched host bits in the trailing hextet is zeroed
    assert normalize_prefix("1000:2000:3031:01ff", 56) == "1000:2000:3031:100"


def test_validate_site_prefix_length_bounds():
    for p in (32, 48, 56, 64):
        validate_site_prefix_length(p)
    for p in (31, 65, 128):
        with pytest.raises(ValueError):
            validate_site_prefix_length(p)


def test_normalize_vvvv_pads_to_four_chars():
    assert normalize_vvvv("134") == "0134"
    assert normalize_vvvv("0134") == "0134"
    assert normalize_vvvv("FFFF") == "ffff"
    assert normalize_vvvv("0") == "0000"


def test_normalize_vvvv_rejects_out_of_range():
    with pytest.raises(ValueError):
        normalize_vvvv("10000")
    with pytest.raises(ValueError):
        normalize_vvvv("-1")
    with pytest.raises(ValueError):
        normalize_vvvv("")


def test_validate_prefix_length_bounds():
    for p in (49, 56, 64):
        validate_prefix_length(p)
    for p in (47, 48, 65, 128):
        with pytest.raises(ValueError):
            validate_prefix_length(p)


def test_vvvv_block_size_matches_spec():
    # Sizes from the spec: /50->0x4000, /51->0x2000, /56->0x0100, /59->0x0020
    assert vvvv_block_size(50) == 0x4000
    assert vvvv_block_size(51) == 0x2000
    assert vvvv_block_size(56) == 0x0100
    assert vvvv_block_size(59) == 0x0020
    assert vvvv_block_size(60) == 0x0010
    assert vvvv_block_size(64) == 0x0001


# ── Conversion: IPv4 -> tail ─────────────────────────────────────────────────

def test_ipv4_to_suffix_worked_example():
    # 1.2.3.4 -> 0x0102:0x0304, canonical = 102:304
    assert ipv4_to_suffix("1.2.3.4") == "102:304"


def test_ipv4_to_suffix_low_and_high_bytes():
    assert ipv4_to_suffix("0.0.0.1") == "0:1"
    assert ipv4_to_suffix("255.255.255.255") == "ffff:ffff"
    # 7.8.9.10 -> 0x0708:0x090a
    assert ipv4_to_suffix("7.8.9.10") == "708:90a"


# ── Conversion: assemble + decode (round-trip on the worked example) ────────

def test_assemble_matches_worked_example():
    addr = assemble("1000:2000:3000", "0100", "1.2.3.4")
    # The full expanded form is 1000:2000:3000:0100:0000:0000:0102:0304.
    # ipaddress canonicalizes to lower-case + compressed.
    assert addr == ipaddress.IPv6Address("1000:2000:3000:100::102:304")


def test_assemble_accepts_unpadded_prefix_and_vvvv():
    a = assemble("1000:2000:3000", "100", "1.2.3.4")
    b = assemble("1000:2000:3000", "0100", "1.2.3.4")
    assert a == b


def test_decode_recovers_site_vvvv_and_ipv4():
    sites = [
        {"id": 1, "name": "DC1", "prefix": "1000:2000:3000", "prefix_length": 48},
        {"id": 2, "name": "DC2", "prefix": "4000:5000:6000", "prefix_length": 48},
    ]
    r = decode("1000:2000:3000:100::102:304", sites)
    assert r.site_id == 1
    assert r.site_name == "DC1"
    assert r.site_prefix_length == 48
    assert r.vvvv == "0100"
    assert r.ipv4 == "1.2.3.4"
    assert r.warnings == []


def test_decode_picks_correct_site_when_v4_is_ambiguous():
    sites = [
        {"id": 1, "name": "DC1", "prefix": "1000:2000:3000", "prefix_length": 48},
        {"id": 2, "name": "DC2", "prefix": "4000:5000:6000", "prefix_length": 48},
    ]
    same_v4 = "1.2.3.4"
    addr_dc1 = assemble("1000:2000:3000", "0100", same_v4).compressed
    addr_dc2 = assemble("4000:5000:6000", "0100", same_v4).compressed
    assert decode(addr_dc1, sites).site_name == "DC1"
    assert decode(addr_dc2, sites).site_name == "DC2"


def test_decode_warns_when_prefix_unregistered():
    r = decode("9999:9999:9999:100::102:304", sites=[])
    assert r.site_id is None
    assert any("No registered site" in w for w in r.warnings)
    # IPv4 + vvvv recovery still works
    assert r.vvvv == "0100"
    assert r.ipv4 == "1.2.3.4"


def test_decode_warns_when_middle_hextets_nonzero():
    # Bits in hextet 5 = "dead" should trip the warning
    sites = [{"id": 1, "name": "DC1", "prefix": "1000:2000:3000", "prefix_length": 48}]
    r = decode("1000:2000:3000:100:dead::102:304", sites)
    assert any("Hextets 5-6" in w for w in r.warnings)


def test_decode_assemble_round_trip_many_ipv4s():
    sites = [{"id": 1, "name": "DC1", "prefix": "1000:2000:3000", "prefix_length": 48}]
    cases = [
        ("0001", "0.0.0.1"),
        ("0100", "1.0.0.1"),
        ("0200", "2.0.0.1"),
        ("ffff", "9.9.9.9"),
    ]
    for vvvv, v4 in cases:
        addr = assemble("1000:2000:3000", vvvv, v4).compressed
        r = decode(addr, sites)
        assert r.vvvv == vvvv
        assert r.ipv4 == v4
        assert r.site_id == 1


def test_decode_prefers_longest_matching_site():
    """A /56 leaf airport wins over its containing /48 state when both
    are registered."""
    sites = [
        {"id": 1, "name": "California-State", "prefix": "1000:2000:3031",
         "prefix_length": 48},
        {"id": 2, "name": "LAX-airport", "prefix": "1000:2000:3031:0100",
         "prefix_length": 56},
    ]
    r = decode("1000:2000:3031:0100::1", sites)
    assert r.site_id == 2
    assert r.site_name == "LAX-airport"
    assert r.site_prefix_length == 56
    # Leaf-match warning is informational
    assert any("leaf" in w.lower() for w in r.warnings)


def test_decode_falls_back_to_containing_48_when_leaf_unregistered():
    sites = [
        {"id": 1, "name": "California-State", "prefix": "1000:2000:3031",
         "prefix_length": 48},
    ]
    r = decode("1000:2000:3031:0200::1", sites)
    assert r.site_id == 1
    assert r.site_prefix_length == 48


# ── Allocator ────────────────────────────────────────────────────────────────

def test_next_block_empty_returns_zero():
    assert next_block(56, []) == "0000"
    assert next_block(64, []) == "0000"


def test_next_block_honors_interval_for_each_mask():
    # First /50 is 0x0000; next is 0x4000
    occupied = [{"vvvv": "0000", "prefix_length": 50}]
    assert next_block(50, occupied) == "4000"
    # First /56 is 0x0000; next is 0x0100
    assert next_block(56, [{"vvvv": "0000", "prefix_length": 56}]) == "0100"
    # First /59 is 0x0000; next is 0x0020
    assert next_block(59, [{"vvvv": "0000", "prefix_length": 59}]) == "0020"


def test_next_block_finds_gap_between_allocations():
    # /56 blocks at 0x0000 and 0x0200 leave 0x0100 free
    occupied = [
        {"vvvv": "0000", "prefix_length": 56},
        {"vvvv": "0200", "prefix_length": 56},
    ]
    assert next_block(56, occupied) == "0100"


def test_next_block_returns_none_when_full():
    # A single /49 at 0x0000 covers half the space; one more at 0x8000 fills it
    occupied = [
        {"vvvv": "0000", "prefix_length": 49},
        {"vvvv": "8000", "prefix_length": 49},
    ]
    assert next_block(49, occupied) is None


def test_find_overlap_detects_exact_match():
    occupied = [{"id": 1, "vvvv": "0100", "prefix_length": 64}]
    hits = find_overlap("0100", 64, occupied)
    assert len(hits) == 1 and hits[0]["id"] == 1


def test_find_overlap_detects_containment_either_direction():
    # Existing /64 sits inside a proposed /56
    occupied = [{"id": 1, "vvvv": "0142", "prefix_length": 64}]
    assert find_overlap("0100", 56, occupied) == occupied

    # Existing /56 contains a proposed /64
    occupied = [{"id": 2, "vvvv": "0100", "prefix_length": 56}]
    assert find_overlap("0142", 64, occupied) == occupied


def test_find_overlap_returns_empty_when_disjoint():
    occupied = [{"id": 1, "vvvv": "0100", "prefix_length": 56}]
    assert find_overlap("0200", 56, occupied) == []
    assert find_overlap("0300", 64, occupied) == []


def test_find_overlap_excludes_self_for_update():
    occupied = [{"id": 1, "vvvv": "0100", "prefix_length": 56}]
    # Updating row id=1 to the same vvvv/prefix should not flag itself
    assert find_overlap("0100", 56, occupied, exclude_alloc_id=1) == []


def test_next_block_skips_over_smaller_existing_block():
    # A /64 occupies just one vvvv (0x0500); the next free /56 must skip that range
    occupied = [{"vvvv": "0500", "prefix_length": 64}]
    # /56 ranges: [0,100), [100,200), [200,300), [300,400), [400,500), [500,600)
    # The /64 at 0x0500 sits inside [500,600), so 0x0500 is taken; first free is 0x0000
    assert next_block(56, occupied) == "0000"
    # If we also block the first /56, next free must skip 0x0500's containing /56
    occupied = [
        {"vvvv": "0000", "prefix_length": 56},
        {"vvvv": "0500", "prefix_length": 64},
    ]
    assert next_block(56, occupied) == "0100"


# ── Generalized allocator (non-/48 sites) ───────────────────────────────────

from utils.ipv6_assembler import (
    site_vvvv_mask,
    site_vvvv_fixed_value,
    vvvv_conforms_to_site,
)


def test_validate_prefix_length_respects_site_length():
    """Allocation must be more specific than its parent site."""
    validate_prefix_length(64, site_prefix_length=48)
    validate_prefix_length(57, site_prefix_length=56)
    validate_prefix_length(64, site_prefix_length=56)
    with pytest.raises(ValueError):
        validate_prefix_length(56, site_prefix_length=56)  # not more specific
    with pytest.raises(ValueError):
        validate_prefix_length(48, site_prefix_length=48)  # equals site
    with pytest.raises(ValueError):
        validate_prefix_length(65, site_prefix_length=48)  # past /64 boundary


def test_site_vvvv_mask_matches_fixed_bit_count():
    assert site_vvvv_mask(48) == 0x0000
    assert site_vvvv_mask(49) == 0x8000
    assert site_vvvv_mask(56) == 0xFF00
    assert site_vvvv_mask(60) == 0xFFF0
    assert site_vvvv_mask(64) == 0xFFFF


def test_site_vvvv_fixed_value_extracts_high_byte_for_56():
    # T573 example from the spreadsheet
    assert site_vvvv_fixed_value("1000:2000:3028:2d00", 56) == 0x2D00
    assert site_vvvv_fixed_value("1000:2000:3028:2d80", 60) == 0x2D80
    assert site_vvvv_fixed_value("1000:2000:3000", 48) == 0x0000


def test_vvvv_conforms_to_site_filters_by_mask():
    # /56 site at 2d00 only accepts vvvvs whose high byte is 0x2D
    assert vvvv_conforms_to_site("2d00", "1000:2000:3028:2d00", 56)
    assert vvvv_conforms_to_site("2d06", "1000:2000:3028:2d00", 56)
    assert vvvv_conforms_to_site("2dff", "1000:2000:3028:2d00", 56)
    assert not vvvv_conforms_to_site("2e00", "1000:2000:3028:2d00", 56)
    assert not vvvv_conforms_to_site("0100", "1000:2000:3028:2d00", 56)
    # /48 site accepts anything
    assert vvvv_conforms_to_site("0100", "1000:2000:3000", 48)
    assert vvvv_conforms_to_site("ffff", "1000:2000:3000", 48)


def test_next_block_constrains_to_site_range():
    """For a /56 site at 2d00, next_block should suggest values in 2d00..2dff."""
    site = {"prefix": "1000:2000:3028:2d00", "prefix_length": 56}
    # Empty site → first slot is the site's fixed value itself
    assert next_block(64, [], site=site) == "2d00"
    # Mark 2d00 occupied → next is 2d01
    occupied = [{"vvvv": "2d00", "prefix_length": 64}]
    assert next_block(64, occupied, site=site) == "2d01"
    # Fully exhaust 256 slots → None
    full = [{"vvvv": f"{0x2D00 + i:04x}", "prefix_length": 64} for i in range(256)]
    assert next_block(64, full, site=site) is None


def test_next_block_unconstrained_for_48_site():
    """Without `site=`, iteration covers the full 16-bit vvvv space."""
    assert next_block(64, [{"vvvv": "0000", "prefix_length": 64}]) == "0001"


def test_assemble_works_for_56_site():
    """Assemble for a /56 site: vvvv carries the site's fixed high byte."""
    addr = assemble("1000:2000:3028:2d00", "2d01", "10.0.0.1",
                    site_prefix_length=56)
    assert str(addr) == "1000:2000:3028:2d01::a00:1"


def test_assemble_back_compat_48():
    """Assemble call without site_prefix_length still works for /48."""
    addr = assemble("1000:2000:3000", "0100", "1.2.3.4")
    assert str(addr) == "1000:2000:3000:100::102:304"
