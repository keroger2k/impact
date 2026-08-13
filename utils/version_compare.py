"""utils/version_compare.py — numeric-component software version comparison.

Extracted from utils/device_comparison_report.py's `_version_parts`/
`_version_matches` (identical logic, moved verbatim) so the golden-image
compliance dashboard (utils/swim_compliance.py) can reuse it instead of
re-deriving the same "17.6.5 vs 17.06.05" zero-padding quirk a second time.

Two comparison semantics live here, because the two callers need different
strictness:

  * `versions_compatible()` — prefix-tolerant (the original device-comparison
    behavior): truncates both sides to the shorter length before comparing,
    so "17.6" reads as compatible with "17.6.5". Right for "is this cosmetic
    formatting noise between two systems describing the same box," which is
    device-comparison's job.
  * `versions_equal()` — full-tuple equality, no truncation. "17.6" is NOT
    equal to "17.6.5". Right for compliance, where a device reporting only a
    major.minor version must not silently read as matching a golden image
    pinned to a specific patch level.

Both share the same zero-padding tolerance ("17.06.05" == "17.6.5") via
`version_parts()`, since `int("06") == 6` regardless of which comparison
wraps it.
"""
from __future__ import annotations

import re


def version_parts(value: str | None) -> tuple[int, ...]:
    """Parse a version string into a tuple of its numeric components,
    e.g. "17.06.05" -> (17, 6, 5). Zero-padding disappears here, which is
    what makes both comparisons below tolerant of it."""
    return tuple(int(p) for p in re.findall(r"\d+", value or ""))


def versions_compatible(a: str | None, b: str | None) -> bool:
    """Prefix-tolerant match: truncated-to-shortest-length comparison, so
    "17.6" reads as compatible with "17.6.5". Returns True if either side has
    no parsable numeric component (nothing to disagree on)."""
    pa, pb = version_parts(a), version_parts(b)
    if not pa or not pb:
        return True
    length = min(len(pa), len(pb))
    return pa[:length] == pb[:length]


def versions_equal(a: str | None, b: str | None) -> bool:
    """Strict equality on the full parsed tuple — no truncation. "17.6" is
    NOT equal to "17.6.5". Two unparsable/empty versions are never equal
    (unlike versions_compatible, which treats "nothing to compare" as no
    conflict) — compliance has nothing to call compliant without a real
    version on both sides."""
    pa, pb = version_parts(a), version_parts(b)
    if not pa or not pb:
        return False
    return pa == pb
