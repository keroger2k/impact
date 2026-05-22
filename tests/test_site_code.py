"""Tests for utils.site_code — the DNAC site-hierarchy → short-code extractor."""
from utils.site_code import site_code


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
