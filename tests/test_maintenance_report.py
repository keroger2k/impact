"""tests/test_maintenance_report.py — parsing and node resolution for the
Maintenance Mode Scheduler.

All node names/IPs here are fake per docs/IP_ADDRESS_POLICY.md.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from utils.maintenance_report import parse_rows, resolve_node_ids, schedule_one


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


# ── resolve_node_ids ──────────────────────────────────────────────────────────

def test_resolve_node_ids_unique_match():
    fake_rows = [{"NodeID": 42, "Caption": "R-SITE01-01"}]
    with patch("clients.solarwinds.query", return_value=fake_rows) as mock_query:
        result = resolve_node_ids(["R-SITE01-01"], "dev", "dev")
    assert result["r-site01-01"] == {"node_id": 42}
    swql = mock_query.call_args[0][0]
    assert "Caption = 'R-SITE01-01'" in swql


def test_resolve_node_ids_not_found():
    with patch("clients.solarwinds.query", return_value=[]):
        result = resolve_node_ids(["R-SITE01-01"], "dev", "dev")
    assert result["r-site01-01"] == {"error": "not found in SolarWinds"}


def test_resolve_node_ids_ambiguous():
    fake_rows = [
        {"NodeID": 1, "Caption": "R-SITE01-01"},
        {"NodeID": 2, "Caption": "R-SITE01-01"},
    ]
    with patch("clients.solarwinds.query", return_value=fake_rows):
        result = resolve_node_ids(["R-SITE01-01"], "dev", "dev")
    assert "error" in result["r-site01-01"]
    assert "ambiguous" in result["r-site01-01"]["error"]


def test_resolve_node_ids_queries_once_for_multiple_distinct_names():
    with patch("clients.solarwinds.query", return_value=[]) as mock_query:
        resolve_node_ids(["R-SITE01-01", "R-SITE02-01", "r-site01-01"], "dev", "dev")
    assert mock_query.call_count == 1


def test_resolve_node_ids_empty_input_skips_query():
    with patch("clients.solarwinds.query") as mock_query:
        result = resolve_node_ids([], "dev", "dev")
    assert result == {}
    mock_query.assert_not_called()


# ── schedule_one ──────────────────────────────────────────────────────────────

def test_schedule_one_calls_unmanage_node():
    from datetime import datetime, timezone
    start = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)
    stop = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)
    with patch("clients.solarwinds.unmanage_node") as mock_unmanage:
        schedule_one(42, start, stop, "dev", "dev")
    mock_unmanage.assert_called_once_with(42, start, stop, "dev", "dev")
