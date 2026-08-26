"""utils/version_compare.py — numeric-component software version comparison.

Backs utils/device_comparison_report.py's model/version reconciliation:
`versions_compatible()` is prefix-tolerant (truncates both sides to the
shorter length before comparing), so "17.6" reads as compatible with
"17.6.5" — right for "is this cosmetic formatting noise between two systems
describing the same box," which is device-comparison's job. It also
tolerates zero-padding ("17.06.05" == "17.6.5") via `version_parts()`, since
`int("06") == 6`.
"""
from __future__ import annotations

import re


def version_parts(value: str | None) -> tuple[int, ...]:
    """Parse a version string into a tuple of its numeric components,
    e.g. "17.06.05" -> (17, 6, 5). Zero-padding disappears here, which is
    what makes versions_compatible() below tolerant of it."""
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
