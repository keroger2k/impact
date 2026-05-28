"""Extract short site codes from DNAC site hierarchies.

The TSA fleet uses a handful of recurring site-code shapes inside the
DNAC site hierarchy strings (e.g. ``Global/Mississippi/SDCZ - DC1/
Stennis Space Center`` carries the code ``SDCZ``; ``Global/California/
DC15 K024/DC15 K024`` carries ``K024``). This module picks them out so
the UI can show a 4-character column instead of a 40-character path.

Pattern priority — first match in the input wins:
  1. ``[A-Z]\\d{3,4}``         — building code (K024, T123, S456)
  2. ``[A-Z]{4,5}\\d{0,3}``    — facility / campus code (SDCZ, IXXX)

The 3-letter pattern (LAX, JFK, …) is intentionally excluded — too many
false positives against common acronyms (DNS, VPN, ACL, …) and the
TSA fleet's codes are all in P1/P2 anyway.
"""
from __future__ import annotations

import re

_PATTERNS = (
    re.compile(r'\b([A-Z]\d{3,4})\b'),
    re.compile(r'\b([A-Z]{4,5}\d{0,3})\b'),
)

# 4-5 letter all-caps tokens that look like P2 codes but are actually
# common networking / functional acronyms appearing in site names.
_STOPWORDS = {
    "DHCP", "EIGRP", "OSPF", "ISIS", "MPLS", "VLAN", "VRRP", "VPLS",
    "PROD", "TEST", "STAG", "DEMO", "MGMT", "EDGE", "CORE", "DIST",
    "BACK", "MAIN", "USER", "NULL", "VOID",
    "GLOBAL", "NORTH", "SOUTH", "EAST", "WEST",
}


def site_code(text: str | None) -> str:
    """Return the first matching site code in ``text``, or ``""`` if none.

    Safe to call on ``None`` / empty input — used as a Jinja filter.
    """
    if not text:
        return ""
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            code = match.group(1)
            if code.upper() not in _STOPWORDS:
                return code
    return ""


_HOSTNAME_P1 = re.compile(r'^([A-Z]\d{3,4})')
_HOSTNAME_P2 = re.compile(r'^([A-Z]{4})')

# Strict TSA-fleet code shapes:
#   * letter + 3 digits  (K024, S456, T123) — unambiguous; matched first
#   * 4 caps letters     (SDCZ, IXXX, KSTD) — needs stopword filter
# Leading letter must be in {K, S, T, I}.
_STRICT_LD = re.compile(r"\b([KSTI]\d{3})\b")
_STRICT_LL = re.compile(r"\b([KSTI][A-Z]{3})\b")
_STRICT_LD_PREFIX = re.compile(r"^([KSTI]\d{3})")
_STRICT_LL_PREFIX = re.compile(r"^([KSTI][A-Z]{3})")
# Hostname-shape tail: function letters then digits (e.g. SDCZ + RTR0001).
# Used to validate the 4-letter prefix match inside a longer token, so
# generic English words (STENNIS, SITES, …) don't masquerade as codes.
_STRICT_HN_TAIL = re.compile(r"^[A-Z]{2,}\d+")

# 4-letter [KSTI]-prefixed tokens that are common English words or
# abbreviations — would otherwise be returned as false-positive site codes.
_STRICT_STOPWORDS = {
    "SITE", "SIDE", "SOME", "SOIL", "STOP", "STEM", "STEP", "STAR", "STAT",
    "TEAM", "TEXT", "TIME", "TYPE", "TASK", "TRUE", "TIPS", "TEST",
    "TEXA", "TENN",
    "INFO", "ITEM", "IRON", "IDEA",
    "KIND", "KEEP", "KIDS",
}


def site_code_strict(text: str | None) -> str:
    """Return the first 4-char fleet site code (KXXX / SXXX / TXXX / IXXX)
    found in ``text``.

    Recognized shapes:
      * letter + 3 digits     (K024, T123, S456) — unambiguous.
      * 4 capital letters     (SDCZ, IXXX, KSTD) — filtered against a
        stopword list of common false-positive English words.

    Works for both DNAC site paths (``Global/USA/K024`` → ``K024``,
    ``Global/MS/SDCZ - DC1`` → ``SDCZ``) and hostnames where the code is
    embedded without separators (``k024fwl006`` → ``K024``,
    ``sdczrtr0001`` → ``SDCZ``). For hostname embedding the 4-letter
    variant requires a function-letters-then-digits tail to avoid matching
    real English words like ``STENNIS`` (STEN + NIS).
    """
    if not text:
        return ""
    s = text.upper()
    # Pass 1: letter+digits with word boundaries — the high-confidence shape.
    m = _STRICT_LD.search(s)
    if m:
        return m.group(1)
    # Pass 2: 4-caps-letters with word boundaries, stopword filtered.
    for m in _STRICT_LL.finditer(s):
        code = m.group(1)
        if code not in _STRICT_STOPWORDS:
            return code
    # Pass 3: hostname-embedded codes (no separators around the match).
    for token in re.split(r"[^A-Z0-9]+", s):
        if not token:
            continue
        m = _STRICT_LD_PREFIX.match(token)
        if m:
            return m.group(1)
        m = _STRICT_LL_PREFIX.match(token)
        if (m and m.group(1) not in _STRICT_STOPWORDS
                and len(token) > 4 and _STRICT_HN_TAIL.match(token[4:])):
            return m.group(1)
    return ""


def site_code_from_hostname(hostname: str | None) -> str:
    """Extract a site code from a device hostname.

    Fleet hostnames embed the site code as a PREFIX (``k024fwl006`` → K024,
    ``sdczfwl0013`` → SDCZ) without separators. The general-purpose
    ``site_code`` regex requires word boundaries on both sides so it can't
    pull a code out of ``K024fwl006`` (``\\bK024\\b`` fails: ``f`` is a
    word character). This function takes a different approach:

      1. Uppercase the input.
      2. Split at common separators (``_``, ``-``, ``.``).
      3. For each token, look at the *prefix* — letter+3-4 digits first
         (the K024/T123/S456 building-code shape), then a 4-letter facility
         code (SDCZ/IXXX). First match wins.
      4. Fall back to the general ``site_code`` search across the whole
         string for hostnames that already have word-boundary-friendly
         shape (rare but possible).

    Note: prefers 4-letter facility codes over 5-letter. Five-letter codes
    like ``KSTDS`` would need explicit configuration since ``SDCZFWL``
    would over-match to ``SDCZF``. The 4-letter default works for SDCZ,
    IXXX, and the bulk of the fleet.
    """
    if not hostname:
        return ""
    s = hostname.upper()
    for token in re.split(r'[_.\-]+', s):
        if not token:
            continue
        m = _HOSTNAME_P1.match(token)
        if m and m.group(1).upper() not in _STOPWORDS:
            return m.group(1)
        m = _HOSTNAME_P2.match(token)
        if m and m.group(1).upper() not in _STOPWORDS:
            return m.group(1)
    # Fallback: try the word-boundary regex (rare, but covers hostnames
    # with embedded separators we didn't split on).
    return site_code(s)
