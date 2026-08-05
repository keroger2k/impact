"""tests/test_bandwidth_report.py — find_node_ip (SolarWinds node IP resolution)."""
from unittest.mock import patch

import pytest
from utils.bandwidth_report import InvalidNameError, find_node_ip


def test_find_node_ip_exact_match_preferred():
    rows = [
        {"NodeName": "RTRYL005AA001-OLD", "NodeIpAddress": "5.6.7.8"},
        {"NodeName": "RTRYL005AA001", "NodeIpAddress": "1.2.3.4"},
    ]
    with patch("clients.solarwinds.query", return_value=rows):
        ip = find_node_ip("RTRYL005AA001", "dev", "dev")
    assert ip == "1.2.3.4"


def test_find_node_ip_falls_back_to_first_like_match():
    rows = [{"NodeName": "RTRYL005AA001-SUB", "NodeIpAddress": "5.6.7.8"}]
    with patch("clients.solarwinds.query", return_value=rows):
        ip = find_node_ip("RTRYL005AA001", "dev", "dev")
    assert ip == "5.6.7.8"


def test_find_node_ip_no_match_returns_none():
    with patch("clients.solarwinds.query", return_value=[]):
        ip = find_node_ip("nonexistent-router", "dev", "dev")
    assert ip is None


def test_find_node_ip_rejects_bad_charset():
    with pytest.raises(InvalidNameError):
        find_node_ip("bad;name", "dev", "dev")
