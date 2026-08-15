"""tests/test_swim_site_circuit.py — utils/swim_site_circuit.py.

Covers the three things that matter for this module (see its docstring):
tier boundaries, the deliberately-conservative WAN-interface pick (never
guess across ambiguous candidates), and the unconditional fallback to
concurrency 1 on any failure mode (SolarWinds unreachable, no matching
node/interface, or unusable Speed).
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

import utils.swim_site_circuit as circuit


# ── _concurrency_for_mbps ────────────────────────────────────────────────────

@pytest.mark.parametrize("mbps,expected", [
    (0.0, 1),
    (9.9, 1),
    (10.0, 2),
    (24.9, 2),
    (25.0, 3),
    (49.9, 3),
    (50.0, 5),
    (99.9, 5),
    (100.0, circuit._SITE_CONCURRENCY_CEILING),
    (500.0, circuit._SITE_CONCURRENCY_CEILING),
])
def test_concurrency_for_mbps_boundaries(mbps, expected):
    assert circuit._concurrency_for_mbps(mbps) == expected


# ── _pick_wan_interface ──────────────────────────────────────────────────────

def _iface(caption: str, speed=100_000_000) -> dict:
    return {"InterfaceCaption": caption, "InterfaceName": caption, "InterfaceSpeed": speed}


def test_pick_wan_interface_prefers_exact_tunnel5000():
    rows = [_iface("GigabitEthernet0/0/0 · LAN"), _iface("Tunnel5000 · DMVPN Tunnel for TSA (ATT)")]
    picked = circuit._pick_wan_interface(rows)
    assert picked is not None
    assert picked["InterfaceCaption"].startswith("Tunnel5000")


def test_pick_wan_interface_falls_back_to_single_other_tunnel():
    rows = [_iface("GigabitEthernet0/0/0 · LAN"), _iface("Tunnel100 · Backup DMVPN")]
    picked = circuit._pick_wan_interface(rows)
    assert picked is not None
    assert picked["InterfaceCaption"].startswith("Tunnel100")


def test_pick_wan_interface_no_candidates_is_none():
    rows = [_iface("GigabitEthernet0/0/0 · LAN"), _iface("Vlan1 · Management")]
    assert circuit._pick_wan_interface(rows) is None


def test_pick_wan_interface_empty_rows_is_none():
    assert circuit._pick_wan_interface([]) is None


def test_pick_wan_interface_two_tunnel5000_is_ambiguous():
    """A dual-router site with two live Tunnel5000s — never guess which
    one's Speed represents the site's circuit."""
    rows = [_iface("Tunnel5000 · Router A"), _iface("Tunnel5000 · Router B")]
    assert circuit._pick_wan_interface(rows) is None


def test_pick_wan_interface_two_different_tunnels_is_ambiguous():
    rows = [_iface("Tunnel100 · Primary"), _iface("Tunnel200 · Secondary")]
    assert circuit._pick_wan_interface(rows) is None


# ── _lookup_one_site ─────────────────────────────────────────────────────────

def test_lookup_one_site_solarwinds_exception_falls_back(monkeypatch):
    with patch("clients.solarwinds.query", side_effect=RuntimeError("SOLARWINDS_URL is not configured")):
        result = circuit._lookup_one_site("K001", "dev", "dev")
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "solarwinds-unreachable"}


def test_lookup_one_site_no_rows_falls_back():
    with patch("clients.solarwinds.query", return_value=[]):
        result = circuit._lookup_one_site("K001", "dev", "dev")
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


def test_lookup_one_site_null_speed_falls_back():
    rows = [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": None}]
    with patch("clients.solarwinds.query", return_value=rows):
        result = circuit._lookup_one_site("K001", "dev", "dev")
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


def test_lookup_one_site_zero_speed_falls_back():
    rows = [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": 0}]
    with patch("clients.solarwinds.query", return_value=rows):
        result = circuit._lookup_one_site("K001", "dev", "dev")
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


def test_lookup_one_site_valid_row_resolves_tier():
    rows = [{"InterfaceCaption": "Tunnel5000 · DMVPN Tunnel for TSA (ATT)", "InterfaceName": "Tunnel5000",
             "InterfaceSpeed": 20_000_000}]  # 20 Mbps -> tier 2 (10-25 Mbps)
    with patch("clients.solarwinds.query", return_value=rows) as mock_query:
        result = circuit._lookup_one_site("K001", "dev", "dev")
    assert result == {"concurrency": 2, "circuit_mbps": 20.0, "source": "solarwinds"}
    swql = mock_query.call_args[0][0]
    assert "cp.Site = 'K001'" in swql


def test_lookup_one_site_escapes_site_code():
    with patch("clients.solarwinds.query", return_value=[]) as mock_query:
        circuit._lookup_one_site("K0'01", "dev", "dev")
    swql = mock_query.call_args[0][0]
    assert "cp.Site = 'K0''01'" in swql


# ── resolve_site_concurrency ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_site_concurrency_unknown_sentinel_skips_solarwinds():
    with patch("clients.solarwinds.query") as mock_query:
        result = await circuit.resolve_site_concurrency(["UNKNOWN"], "dev", "dev")
    mock_query.assert_not_called()
    assert result == {"UNKNOWN": {"concurrency": 1, "circuit_mbps": None, "source": "unresolved-site"}}


@pytest.mark.asyncio
async def test_resolve_site_concurrency_dedupes_and_covers_every_input():
    def fake_query(swql, username, password, timeout=None):
        return [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": 50_000_000}]

    with patch("clients.solarwinds.query", side_effect=fake_query) as mock_query:
        result = await circuit.resolve_site_concurrency(["K001", "K002", "K001"], "dev", "dev")

    assert set(result.keys()) == {"K001", "K002"}
    assert mock_query.call_count == 2  # deduped
    assert result["K001"]["source"] == "solarwinds"


@pytest.mark.asyncio
async def test_resolve_site_concurrency_one_site_failure_does_not_affect_another():
    def fake_query(swql, username, password, timeout=None):
        if "K001" in swql:
            raise RuntimeError("Orion unreachable")
        return [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": 200_000_000}]

    with patch("clients.solarwinds.query", side_effect=fake_query):
        result = await circuit.resolve_site_concurrency(["K001", "K002"], "dev", "dev")

    assert result["K001"]["source"] == "solarwinds-unreachable"
    assert result["K001"]["concurrency"] == 1
    assert result["K002"]["source"] == "solarwinds"
    assert result["K002"]["concurrency"] == circuit._SITE_CONCURRENCY_CEILING


@pytest.mark.asyncio
async def test_resolve_site_concurrency_runs_lookups_in_parallel(monkeypatch):
    """Ten sites, each lookup deliberately slow (0.05s via a real thread
    sleep, since the call runs through run_in_executor) — if lookups ran
    serially this would take ~0.5s; run in parallel it should take close to
    one lookup's duration."""
    monkeypatch.setattr(circuit, "_LOOKUP_FANOUT_LIMIT", 20)
    site_codes = [f"K{i:03d}" for i in range(10)]

    def slow_query(swql, username, password, timeout=None):
        time.sleep(0.05)
        return [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": 50_000_000}]

    with patch("clients.solarwinds.query", side_effect=slow_query):
        start = time.monotonic()
        result = await circuit.resolve_site_concurrency(site_codes, "dev", "dev")
        elapsed = time.monotonic() - start

    assert len(result) == 10
    assert elapsed < 0.30, f"elapsed={elapsed:.3f}s — site lookups do not appear to run in parallel"


@pytest.mark.asyncio
async def test_resolve_site_concurrency_fanout_limit_bounds_concurrency(monkeypatch):
    """The fan-out semaphore actually caps how many lookups run at once —
    with the limit set to 1, ten 0.05s lookups must take close to 10*0.05s,
    not overlap."""
    monkeypatch.setattr(circuit, "_LOOKUP_FANOUT_LIMIT", 1)
    site_codes = [f"K{i:03d}" for i in range(6)]

    def slow_query(swql, username, password, timeout=None):
        time.sleep(0.05)
        return [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": 50_000_000}]

    with patch("clients.solarwinds.query", side_effect=slow_query):
        start = time.monotonic()
        await circuit.resolve_site_concurrency(site_codes, "dev", "dev")
        elapsed = time.monotonic() - start

    assert elapsed > 0.25, f"elapsed={elapsed:.3f}s — fan-out limit of 1 did not serialize the lookups"
