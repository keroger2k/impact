"""tests/test_solarwinds.py — clients/solarwinds.py's read + write surface.

The most important test here is `test_write_surface_is_narrow_and_explicit`
— the F5-style structural guarantee for this client's *one* mutating call:
it fails the build if a generic entity/verb "invoke anything" passthrough is
ever introduced, or if `unmanage_node` stops posting to the exact Orion verb
it's documented to call.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import clients.solarwinds as sw

_SRC = Path(__file__).resolve().parent.parent / "clients" / "solarwinds.py"


@pytest.fixture(autouse=True)
def _solarwinds_url(monkeypatch):
    # _base_url() reads this per-call (not at import time, unlike conftest.py's
    # DEV_MODE/ACI_FABRICS), so a plain per-test monkeypatch is fine here.
    monkeypatch.setenv("SOLARWINDS_URL", "https://solarwinds.example.local")


# ── Write-surface narrowness ─────────────────────────────────────────────────

def test_write_surface_is_narrow_and_explicit():
    """No generic invoke(entity, verb, *args)-style passthrough exists — the
    only Invoke/ call in the module is the hardcoded Orion.Nodes/Unmanage
    literal used by unmanage_node()."""
    src = _SRC.read_text(encoding="utf-8")
    invoke_literals = re.findall(r"Invoke/[\w.]+/\w+", src)
    assert invoke_literals == ["Invoke/Orion.Nodes/Unmanage"], invoke_literals
    assert "def invoke(" not in src


# ── query() ───────────────────────────────────────────────────────────────────

def _fake_response(status_code=200, json_body=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body or {}
    return resp


def test_query_posts_swql_and_returns_results():
    resp = _fake_response(200, {"results": [{"NodeID": 1}]})
    with patch("requests.post", return_value=resp) as mock_post:
        rows = sw.query("SELECT NodeID FROM Orion.Nodes", "dev", "dev")
    assert rows == [{"NodeID": 1}]
    args, kwargs = mock_post.call_args
    assert args[0].endswith("/SolarWinds/InformationService/v3/Json/Query")
    assert kwargs["json"] == {"query": "SELECT NodeID FROM Orion.Nodes"}


def test_query_raises_with_response_detail_on_error():
    resp = _fake_response(400, text="Cannot resolve property X")
    with patch("requests.post", return_value=resp):
        with pytest.raises(RuntimeError, match="Cannot resolve property X"):
            sw.query("SELECT bogus", "dev", "dev")


def test_query_requires_credentials():
    with pytest.raises(RuntimeError):
        sw.query("SELECT 1", "", "")


# ── unmanage_node() ───────────────────────────────────────────────────────────

def test_unmanage_node_posts_expected_invoke_body():
    resp = _fake_response(200, text="")
    start = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)
    stop = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
    with patch("requests.post", return_value=resp) as mock_post:
        sw.unmanage_node(123, start, stop, "dev", "dev")

    args, kwargs = mock_post.call_args
    assert args[0].endswith("/SolarWinds/InformationService/v3/Json/Invoke/Orion.Nodes/Unmanage")
    assert kwargs["json"] == ["N:123", start.isoformat(), stop.isoformat(), False]


def test_unmanage_node_requires_timezone_aware_datetimes():
    naive = datetime(2026, 8, 10, 8, 0)
    aware = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        sw.unmanage_node(1, naive, aware, "dev", "dev")


def test_unmanage_node_raises_with_response_detail_on_error():
    resp = _fake_response(403, text='{"Message":"Access to Orion.Nodes.Unmanage verb denied."}')
    start = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)
    stop = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
    with patch("requests.post", return_value=resp):
        with pytest.raises(RuntimeError, match="Access to Orion.Nodes.Unmanage verb denied"):
            sw.unmanage_node(1, start, stop, "dev", "dev")


def test_unmanage_node_requires_credentials():
    start = datetime(2026, 8, 10, 8, 0, tzinfo=timezone.utc)
    stop = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(RuntimeError):
        sw.unmanage_node(1, start, stop, "", "")
