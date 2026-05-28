"""Tests for utils.site_code — the DNAC site-hierarchy → short-code extractor."""
from utils.site_code import site_code, site_code_from_hostname, site_code_strict


def test_letter_plus_digits_pattern():
    assert site_code("Global/California/DC15 K024/DC15 K024") == "K024"
    assert site_code("Global/Texas/T123 Building") == "T123"
    assert site_code("S456 - Server Closet") == "S456"


def test_four_letter_facility_code():
    assert site_code("Global/Mississippi/SDCZ - DC1/Stennis Space Center") == "SDCZ"
    assert site_code("Global/Region/IXXX Site Name") == "IXXX"


def test_priority_letter_digits_over_pure_letters():
    """When both shapes appear, the letter+digits (building) code wins —
    it's the more specific identifier."""
    # K024 (P1) should win over EDGE (which is a stopword anyway)
    assert site_code("EDGE Site K024 Building") == "K024"


def test_stopwords_dont_match():
    assert site_code("DHCP Pool") == ""
    assert site_code("EIGRP Topology") == ""
    assert site_code("Global Region") == ""
    assert site_code("EDGE Switch") == ""


def test_empty_input():
    assert site_code("") == ""
    assert site_code(None) == ""


def test_no_match_returns_empty():
    assert site_code("Generic Site Name With No Code") == ""
    assert site_code("Global/Mississippi/Stennis Space Center") == ""


def test_pure_letter_too_short():
    """3-letter all-caps codes are intentionally excluded — too many false
    positives against acronyms (DNS, VPN, ACL, …)."""
    assert site_code("LAX site") == ""
    assert site_code("JFK terminal") == ""


def test_first_match_wins_within_priority():
    """When two letter+digit codes appear, the first one is returned."""
    assert site_code("T123 / S456") == "T123"


# ── Hostname-aware variant ─────────────────────────────────────────────

def test_hostname_lowercase_extracts_code():
    """Palo firewall hostnames are typically lowercase — the regex requires
    uppercase, so the hostname variant must uppercase first."""
    assert site_code_from_hostname("k024fwl006") == "K024"
    assert site_code_from_hostname("sdczfwl0013") == "SDCZ"


def test_hostname_uppercase_still_works():
    assert site_code_from_hostname("K150FWL001") == "K150"
    # Multi-token hostname: DC1EDGE doesn't match (DC then digit, only 2
    # letters before the digit); next token "KSTDSABV005" → 4-letter
    # prefix "KSTD" wins.
    assert site_code_from_hostname("DC1EDGE_KSTDSABV005") == "KSTD"


def test_hostname_stopwords_skipped():
    """EDGE / CORE are common function abbreviations that match the
    4-letter pattern but aren't site codes."""
    assert site_code_from_hostname("edge-fwl-001") == ""
    assert site_code_from_hostname("CORE-RTR-K024") == "K024"  # falls through to K024 token


def test_hostname_none_and_empty():
    assert site_code_from_hostname(None) == ""
    assert site_code_from_hostname("") == ""


# ── Strict K/S/T/I 4-char variant ──────────────────────────────────────

def test_strict_hostname_extracts_kxxx():
    assert site_code_strict("k024fwl006") == "K024"
    assert site_code_strict("K150FWL001") == "K150"


def test_strict_hostname_extracts_sxxx():
    assert site_code_strict("sdczrtr0001") == "SDCZ"
    assert site_code_strict("S456-EDGE-01") == "S456"


def test_strict_site_path_extracts_code():
    assert site_code_strict("Global/USA/K024") == "K024"
    assert site_code_strict("Global/Mississippi/SDCZ - DC1/Stennis Space Center") == "SDCZ"
    assert site_code_strict("Global/Texas/T123 Building") == "T123"
    assert site_code_strict("Global/Region/IXXX Site Name") == "IXXX"


def test_strict_ignores_non_ksti_prefix():
    """ROUTER-K024 should pick K024, not ROUT — only K/S/T/I-prefixed tokens
    qualify. This avoids the false-positive `_HOSTNAME_P2` had with any 4-letter
    prefix."""
    assert site_code_strict("ROUTER-K024") == "K024"
    assert site_code_strict("EDGE-RTR-SDCZ-01") == "SDCZ"


def test_strict_no_match_returns_empty():
    assert site_code_strict("Generic Site Name") == ""
    assert site_code_strict("LAX terminal") == ""  # 3 chars, doesn't fit shape
    assert site_code_strict("DC15 Building") == ""  # doesn't start with K/S/T/I


def test_strict_none_and_empty():
    assert site_code_strict(None) == ""
    assert site_code_strict("") == ""


def test_strict_first_match_wins():
    """When several K/S/T/I tokens appear, the first wins — the leftmost
    field passed by the caller is the most authoritative."""
    assert site_code_strict("Global/Region/K024/SDCZ") == "K024"


def test_strict_falls_back_to_site_path():
    """Devices whose hostname doesn't embed a code (e.g. generic 'firewall-01'
    or 'router-edge') still resolve a code from the DNAC site path. The audit
    template chains these calls: device first, then site_path."""
    # Hostname yields nothing — no K/S/T/I prefix.
    assert site_code_strict("firewall-01") == ""
    # Site path resolves on its own.
    assert site_code_strict("Global/USA/K023") == "K023"


def test_strict_rejects_stennis():
    """Real-world false positive: 'Stennis Space Center' would naively match
    STEN, but the stopword + hostname-tail check prevents it."""
    assert site_code_strict("Global/Mississippi/Stennis Space Center") == ""


def test_strict_letter_digits_beats_letters():
    """When both shapes appear, the letter+digits shape wins (more specific)."""
    assert site_code_strict("Global/SDCZ - DC1/K024 building") == "K024"
