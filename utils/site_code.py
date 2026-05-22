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
