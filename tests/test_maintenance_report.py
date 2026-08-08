"""tests/test_maintenance_report.py — parsing and node resolution for the
Maintenance Mode Scheduler.

All node names/IPs here are fake per docs/IP_ADDRESS_POLICY.md.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from utils.maintenance_report import cancel_one, parse_rows, resolve_node_uris, schedule_one


# ── parse_rows ────────────────────────────────────────────────────────────────

def test_parse_rows_accepts_valid_row():
    valid, errors = parse_rows([
        {"node": "R-SITE01-01", "start_utc": "2026-08-10T08:00:00.000Z", "stop_utc": "2026-08-10T12:00:00.000Z"},
    ])
    assert errors == []
    assert len(valid) == 1
    assert valid[0]["node"] == "R-SITE01-01"
    assert valid[0]["start"].tzinfo is not None
    assert valid[0]["stop"] > valid[0]["start"]


def test_parse_rows_normalizes_fqdn_node_name():
    valid, errors = parse_rows([
        {"node": "R-SITE01-01.network.ad.tsa.gov", "start_utc": "2026-08-10T08:00:00Z", "stop_utc": "2026-08-10T09:00:00Z"},
    ])
    assert errors == []
    assert valid[0]["node"] == "R-SITE01-01"


def test_parse_rows_rejects_bad_node_charset():
    valid, errors = parse_rows([
        {"node": "R-SITE01-01; rm -rf", "start_utc": "2026-08-10T08:00:00Z", "stop_utc": "2026-08-10T09:00:00Z"},
    ])
    assert valid == []
    assert len(errors) == 1
    assert "invalid node name" in errors[0]["message"]


def test_parse_rows_rejects_unparseable_timestamp():
    valid, errors = parse_rows([
        {"node": "R-SITE01-01", "start_utc": "not-a-date", "stop_utc": "2026-08-10T09:00:00Z"},
    ])
    assert valid == []
    assert "start time" in errors[0]["message"]


def test_parse_rows_rejects_stop_before_start():
    valid, errors = parse_rows([
        {"node": "R-SITE01-01", "start_utc": "2026-08-10T12:00:00Z", "stop_utc": "2026-08-10T08:00:00Z"},
    ])
    assert valid == []
    assert "stop time must be after start time" in errors[0]["message"]


def test_parse_rows_isolates_bad_rows_from_good_ones():
    valid, errors = parse_rows([
        {"node": "R-SITE01-01", "start_utc": "2026-08-10T08:00:00Z", "stop_utc": "2026-08-10T09:00:00Z"},
        {"node": "R-SITE02-01", "start_utc": "bogus", "stop_utc": "2026-08-10T09:00:00Z"},
    ])
    assert len(valid) == 1
    assert valid[0]["node"] == "R-SITE01-01"
    assert len(errors) == 1
    assert errors[0]["node"] == "R-SITE02-01"


# ── resolve_node_uris ─────────────────────────────────────────────────────────

_URI = "swis://host/Orion/Orion.Nodes/NodeID=42"


def test_resolve_node_uris_unique_match():
    fake_rows = [{"Uri": _URI, "Caption": "R-SITE01-01"}]
    with patch("clients.solarwinds.query", return_value=fake_rows) as mock_query:
        result = resolve_node_uris(["R-SITE01-01"], "dev", "dev")
    assert result["r-site01-01"] == {"uri": _URI}
    swql = mock_query.call_args[0][0]
    assert "Caption = 'R-SITE01-01'" in swql


def test_resolve_node_uris_not_found():
    with patch("clients.solarwinds.query", return_value=[]):
        result = resolve_node_uris(["R-SITE01-01"], "dev", "dev")
    assert result["r-site01-01"] == {"error": "not found in SolarWinds"}


def test_resolve_node_uris_ambiguous():
    fake_rows = [
        {"Uri": _URI, "Caption": "R-SITE01-01"},
        {"Uri": "swis://host/Orion/Orion.Nodes/NodeID=43", "Caption": "R-SITE01-01"},
    ]
    with patch("clients.solarwinds.query", return_value=fake_rows):
        result = resolve_node_uris(["R-SITE01-01"], "dev", "dev")
    assert "error" in result["r-site01-01"]
    assert "ambiguous" in result["r-site01-01"]["error"]


def test_resolve_node_uris_queries_once_for_multiple_distinct_names():
    with patch("clients.solarwinds.query", return_value=[]) as mock_query:
        resolve_node_uris(["R-SITE01-01", "R-SITE02-01", "r-site01-01"], "dev", "dev")
    assert mock_query.call_count == 1


def test_resolve_node_uris_empty_input_skips_query():
    with patch("clients.solarwinds.query") as mock_query:
        result = resolve_node_uris([], "dev", "dev")
    assert result == {}
    mock_query.assert_not_called()


# ── schedule_one ──────────────────────────────────────────────────────────────

def test_schedule_one_calls_suppress_alerts():
    from datetime import datetime, timezone
    start = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)
    stop = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)
    with patch("clients.solarwinds.suppress_alerts") as mock_suppress:
        schedule_one(_URI, start, stop, "dev", "dev")
    mock_suppress.assert_called_once_with(_URI, start, stop, "dev", "dev")


# ── cancel_one ────────────────────────────────────────────────────────────────

def test_cancel_one_calls_resume_alerts():
    with patch("clients.solarwinds.resume_alerts") as mock_resume:
        cancel_one(_URI, "dev", "dev")
    mock_resume.assert_called_once_with(_URI, "dev", "dev")
