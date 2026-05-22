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
