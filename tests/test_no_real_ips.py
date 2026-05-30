"""Guard: no real network addressing in the test suite, template placeholders,
or test fixtures. See docs/IP_ADDRESS_POLICY.md.

Real site addressing (anything the user pastes/screenshots/logs) must never be
copied into the repo. This fails the build if a forbidden pattern appears, so
the policy can't be quietly re-broken. It is a safety net, not a substitute for
the rule — the rule applies everywhere, including files this guard doesn't scan.

If the user discloses a new real prefix, add it to _FORBIDDEN below.
The functional exception (`_DEFAULT_SCOPE_V6` in utils/ip_audit.py) is out of
scope here by design — this guard only scans tests, templates, and fixtures.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SELF = Path(__file__).resolve()

# (regex, human reason). Case-insensitive. Each pattern is a known-real
# signature the user has disclosed, plus general real-looking-allocation guards.
_FORBIDDEN: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b10\.254\.\d"), "real org IPv4 range 10.254.0.0/16 (seen in screenshots)"),
    (re.compile(r"\b10\.166\.\d"), "real org IPv4 range 10.166.0.0/16 (seen in screenshots)"),
    (re.compile(r"\b10\.44\.\d"),  "real org IPv4 range 10.44.0.0/16 (seen in screenshots)"),
    (re.compile(r"2600:", re.I),   "org IPv6 allocation block (2600:…) — use 1000:2000:3000 / 4000:5000:6000"),
    (re.compile(r"2001:(?!0?db8)", re.I), "real-looking IPv6 (2001:…) — use 2001:db8 for documentation"),
]


def _files_in_scope() -> list[Path]:
    """Test modules (anywhere), template HTML, and test fixtures — minus this
    file and anything under a virtualenv."""
    paths: list[Path] = []
    paths += _ROOT.rglob("test_*.py")
    paths += (_ROOT / "templates").rglob("*.html")
    fixtures = _ROOT / "tests" / "fixtures"
    if fixtures.is_dir():
        paths += [p for p in fixtures.rglob("*") if p.is_file()]

    out, seen = [], set()
    for p in paths:
        rp = p.resolve()
        if rp == _SELF or ".venv" in rp.parts or "site-packages" in rp.parts:
            continue
        if rp not in seen:
            seen.add(rp)
            out.append(rp)
    return out


def test_no_real_ips_in_tests_templates_and_fixtures():
    violations: list[str] = []
    for path in _files_in_scope():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for rx, why in _FORBIDDEN:
                if rx.search(line):
                    rel = path.relative_to(_ROOT)
                    violations.append(f"{rel}:{lineno}: {why}\n      {line.strip()[:110]}")

    assert not violations, (
        "\nReal addressing found in the repo (see docs/IP_ADDRESS_POLICY.md). "
        "Replace with approved fake values:\n\n  " + "\n  ".join(violations) + "\n"
    )
