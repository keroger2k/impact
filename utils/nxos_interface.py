"""Shared NX-OS `show interface` parsing primitives.

Two callers parse the same `show interface` text for different shapes:

  - `collectors/nxos.py`      — the web app's cached Nexus collection
                                (flat per-interface dicts, IPAM/audit inputs)
  - `scripts/nexus_interface_report.py` — the CLI health report
                                (rich per-interface stats, human-facing table)

Their *output shapes* legitimately differ, but the low-level line patterns and
the byte formatting must not. This module is that seam: anything both sides
read out of the same NX-OS line lives here exactly once, so a fix to a regex
can't land in one parser and silently miss the other.

Keep this module free of heavy imports (no netmiko, no FastAPI) — the CLI
script imports netmiko lazily on purpose so `--help` stays instant.
"""

from __future__ import annotations

import re

# ── Cumulative RX/TX byte counters ──────────────────────────────────────────
# Found inside the per-interface RX/TX blocks:
#     123463701 input packets  987654321098 bytes
#     123463692 output packets  876543210987 bytes
# These are running totals since the device's last "clear counters" — a total,
# never a rate. Interpreting them requires the counter age (see CLEARED_RE).
INPUT_BYTES_RE = re.compile(r"^\d+\s+input\s+packets\s+(\d+)\s+bytes", re.IGNORECASE)
OUTPUT_BYTES_RE = re.compile(r"^\d+\s+output\s+packets\s+(\d+)\s+bytes", re.IGNORECASE)

# ── Counter provenance / stability ──────────────────────────────────────────
# "Last clearing of "show interface" counters never"  (or "... 3w2d")
# Without this, an error or byte total is an uninterpretable number: 500 CRC
# since 2019 and 500 CRC since Tuesday look identical.
CLEARED_RE = re.compile(
    r'^Last\s+clearing\s+of\s+"?show\s+interface"?\s+counters\s+(.+?)\s*$',
    re.IGNORECASE,
)
# "Last link flapped 3d02h" — recency of the most recent link transition.
LAST_FLAP_RE = re.compile(r"^Last\s+link\s+flapped\s+(\S+)", re.IGNORECASE)
# "1 interface resets" — how many times it has bounced.
RESETS_RE = re.compile(r"^(\d+)\s+interface\s+resets?\b", re.IGNORECASE)


def format_bytes(n: int | None) -> str:
    """Human-readable byte count.

    `None` means "never collected" and is rendered distinctly from 0, which
    means "collected, and genuinely zero traffic" — on a link that should be
    passing traffic those two states point at completely different problems.
    """
    if n is None:
        return "N/A"
    val = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if val < 1024 or unit == "PB":
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.2f} {unit}"
        val /= 1024
    return f"{val:.2f} PB"
