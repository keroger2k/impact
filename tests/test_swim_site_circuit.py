"""tests/test_swim_site_circuit.py — utils/swim_site_circuit.py.

Covers the things that matter for this module (see its docstring): tier
boundaries, config-text bandwidth extraction, the deliberately-conservative
WAN-interface pick (never guess across ambiguous candidates), router
identification per site, and the unconditional fallback to concurrency 1 on
any failure mode (no router at the site, no matching interface, unusable
bandwidth, or a DNAC config-fetch failure).

`cache.get_or_set` is patched to call straight through to the loader (no real
disk-cache interaction) so tests stay deterministic and don't depend on
`clients.dnac.get_device_config`'s actual cache key/state.
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

import utils.swim_site_circuit as circuit


def _passthrough_get_or_set(key, loader, ttl=None):
    return loader()


@pytest.fixture(autouse=True)
def _bypass_cache(monkeypatch):
    monkeypatch.setattr(circuit.cache, "get_or_set", _passthrough_get_or_set)


def _device(id_: str, family="Routers", hostname=None) -> dict:
    return {"id": id_, "hostname": hostname or f"host-{id_}", "family": family}


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
    rows = [_iface("GigabitEthernet0/0/0"), _iface("Tunnel5000")]
    picked = circuit._pick_wan_interface(rows)
    assert picked is not None
    assert picked["InterfaceCaption"] == "Tunnel5000"


def test_pick_wan_interface_falls_back_to_single_other_tunnel():
    rows = [_iface("GigabitEthernet0/0/0"), _iface("Tunnel100")]
    picked = circuit._pick_wan_interface(rows)
    assert picked is not None
    assert picked["InterfaceCaption"] == "Tunnel100"


def test_pick_wan_interface_no_candidates_is_none():
    rows = [_iface("GigabitEthernet0/0/0"), _iface("Vlan1")]
    assert circuit._pick_wan_interface(rows) is None


def test_pick_wan_interface_empty_rows_is_none():
    assert circuit._pick_wan_interface([]) is None


def test_pick_wan_interface_two_tunnel5000_is_ambiguous():
    """A dual-router site with two live Tunnel5000s — never guess which
    one's bandwidth represents the site's circuit."""
    rows = [_iface("Tunnel5000"), _iface("Tunnel5000")]
    assert circuit._pick_wan_interface(rows) is None


def test_pick_wan_interface_two_different_tunnels_is_ambiguous():
    rows = [_iface("Tunnel100"), _iface("Tunnel200")]
    assert circuit._pick_wan_interface(rows) is None


# ── _tunnel_bandwidth_rows_from_config ───────────────────────────────────────

def test_tunnel_bandwidth_rows_extracts_configured_bandwidth():
    config = """
hostname R-SITE01-01
!
interface Tunnel5000
 bandwidth 20000
 ip address 5.6.7.8 255.255.255.252
 tunnel source GigabitEthernet0/0/0
!
interface GigabitEthernet0/0/0
 bandwidth 1000000
 ip address 1.2.3.4 255.255.255.0
!
end
"""
    rows = circuit._tunnel_bandwidth_rows_from_config(config)
    assert rows == [{"InterfaceCaption": "Tunnel5000", "InterfaceName": "Tunnel5000", "InterfaceSpeed": 20_000_000}]


def test_tunnel_bandwidth_rows_skips_tunnel_without_bandwidth_line():
    config = """
interface Tunnel5000
 ip address 5.6.7.8 255.255.255.252
 tunnel source GigabitEthernet0/0/0
!
end
"""
    assert circuit._tunnel_bandwidth_rows_from_config(config) == []


def test_tunnel_bandwidth_rows_multiple_tunnels():
    config = """
interface Tunnel5000
 bandwidth 20000
!
interface Tunnel100
 bandwidth 5000
!
end
"""
    rows = circuit._tunnel_bandwidth_rows_from_config(config)
    captions = {r["InterfaceCaption"] for r in rows}
    assert captions == {"Tunnel5000", "Tunnel100"}


def test_tunnel_bandwidth_rows_empty_config():
    assert circuit._tunnel_bandwidth_rows_from_config("") == []
    assert circuit._tunnel_bandwidth_rows_from_config(None) == []


# ── _router_devices_for_site ─────────────────────────────────────────────────

def test_router_devices_for_site_filters_by_family_and_site(monkeypatch):
    devices = [
        _device("r1", family="Routers"),
        _device("sw1", family="Switches and Hubs"),
        _device("r2", family="Routers"),
    ]
    site_of = {"r1": "K001", "sw1": "K001", "r2": "K002"}
    monkeypatch.setattr(circuit, "resolve_site_code", lambda dev_id, hostname, m: (site_of[dev_id], "device_site_map"))

    routers = circuit._router_devices_for_site("K001", devices, {})
    assert [d["id"] for d in routers] == ["r1"]


def test_router_devices_for_site_no_match_returns_empty(monkeypatch):
    devices = [_device("r1", family="Routers")]
    monkeypatch.setattr(circuit, "resolve_site_code", lambda dev_id, hostname, m: ("K999", "device_site_map"))
    assert circuit._router_devices_for_site("K001", devices, {}) == []


# ── _lookup_one_site ─────────────────────────────────────────────────────────

def _patch_site(monkeypatch, site_of: dict):
    monkeypatch.setattr(circuit, "resolve_site_code", lambda dev_id, hostname, m: (site_of.get(dev_id, ""), "device_site_map"))


def test_lookup_one_site_no_router_at_site_falls_back(monkeypatch):
    _patch_site(monkeypatch, {})
    result = circuit._lookup_one_site("K001", [_device("sw1", family="Switches and Hubs")], {}, dnac=object())
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


def test_lookup_one_site_config_fetch_raises_falls_back(monkeypatch):
    _patch_site(monkeypatch, {"r1": "K001"})
    with patch("utils.swim_site_circuit.dnac_client.get_device_config", side_effect=RuntimeError("DNAC unreachable")):
        result = circuit._lookup_one_site("K001", [_device("r1")], {}, dnac=object())
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


def test_lookup_one_site_no_tunnel_bandwidth_falls_back(monkeypatch):
    _patch_site(monkeypatch, {"r1": "K001"})
    with patch("utils.swim_site_circuit.dnac_client.get_device_config", return_value="interface GigabitEthernet0/0/0\n bandwidth 1000000\n!\n"):
        result = circuit._lookup_one_site("K001", [_device("r1")], {}, dnac=object())
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


def test_lookup_one_site_valid_config_resolves_tier(monkeypatch):
    _patch_site(monkeypatch, {"r1": "K001"})
    config = "interface Tunnel5000\n bandwidth 20000\n!\n"  # 20 Mbps -> tier 2 (10-25 Mbps)
    with patch("utils.swim_site_circuit.dnac_client.get_device_config", return_value=config) as mock_get_config:
        result = circuit._lookup_one_site("K001", [_device("r1")], {}, dnac="fake-dnac")
    assert result == {"concurrency": 2, "circuit_mbps": 20.0, "source": "dnac-config"}
    mock_get_config.assert_called_once_with("fake-dnac", "r1")


def test_lookup_one_site_ambiguous_across_two_routers_falls_back(monkeypatch):
    """Two routers at the same site, each with its own live Tunnel5000 —
    never guess which one is the site's real circuit."""
    _patch_site(monkeypatch, {"r1": "K001", "r2": "K001"})
    config = "interface Tunnel5000\n bandwidth 20000\n!\n"
    with patch("utils.swim_site_circuit.dnac_client.get_device_config", return_value=config):
        result = circuit._lookup_one_site("K001", [_device("r1"), _device("r2")], {}, dnac=object())
    assert result == {"concurrency": 1, "circuit_mbps": None, "source": "no-circuit-data"}


# ── resolve_site_concurrency ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_site_concurrency_unknown_sentinel_skips_dnac(monkeypatch):
    with patch("utils.swim_site_circuit.dnac_client.get_device_config") as mock_get_config:
        result = await circuit.resolve_site_concurrency(["UNKNOWN"], dnac=object(), devices=[], device_site_map={})
    mock_get_config.assert_not_called()
    assert result == {"UNKNOWN": {"concurrency": 1, "circuit_mbps": None, "source": "unresolved-site"}}


@pytest.mark.asyncio
async def test_resolve_site_concurrency_dedupes_and_covers_every_input(monkeypatch):
    devices = [_device("r1"), _device("r2")]
    _patch_site(monkeypatch, {"r1": "K001", "r2": "K002"})
    config = "interface Tunnel5000\n bandwidth 50000\n!\n"
    with patch("utils.swim_site_circuit.dnac_client.get_device_config", return_value=config) as mock_get_config:
        result = await circuit.resolve_site_concurrency(["K001", "K002", "K001"], dnac=object(), devices=devices, device_site_map={})

    assert set(result.keys()) == {"K001", "K002"}
    assert mock_get_config.call_count == 2  # deduped
    assert result["K001"]["source"] == "dnac-config"


@pytest.mark.asyncio
async def test_resolve_site_concurrency_one_site_failure_does_not_affect_another(monkeypatch):
    devices = [_device("r1"), _device("r2")]
    _patch_site(monkeypatch, {"r1": "K001", "r2": "K002"})

    def fake_get_config(dnac, device_id):
        if device_id == "r1":
            raise RuntimeError("DNAC unreachable")
        return "interface Tunnel5000\n bandwidth 200000\n!\n"

    with patch("utils.swim_site_circuit.dnac_client.get_device_config", side_effect=fake_get_config):
        result = await circuit.resolve_site_concurrency(["K001", "K002"], dnac=object(), devices=devices, device_site_map={})

    assert result["K001"]["source"] == "no-circuit-data"
    assert result["K001"]["concurrency"] == 1
    assert result["K002"]["source"] == "dnac-config"
    assert result["K002"]["concurrency"] == circuit._SITE_CONCURRENCY_CEILING


@pytest.mark.asyncio
async def test_resolve_site_concurrency_runs_lookups_in_parallel(monkeypatch):
    """Ten sites, each with its own router and a deliberately slow config
    fetch (0.05s via a real thread sleep, since the call runs through
    run_in_executor) — if lookups ran serially this would take ~0.5s; run in
    parallel it should take close to one lookup's duration."""
    monkeypatch.setattr(circuit, "_LOOKUP_FANOUT_LIMIT", 20)
    devices = [_device(f"r{i}") for i in range(10)]
    site_of = {f"r{i}": f"K{i:03d}" for i in range(10)}
    _patch_site(monkeypatch, site_of)
    site_codes = list(site_of.values())

    def slow_get_config(dnac, device_id):
        time.sleep(0.05)
        return "interface Tunnel5000\n bandwidth 50000\n!\n"

    with patch("utils.swim_site_circuit.dnac_client.get_device_config", side_effect=slow_get_config):
        start = time.monotonic()
        result = await circuit.resolve_site_concurrency(site_codes, dnac=object(), devices=devices, device_site_map={})
        elapsed = time.monotonic() - start

    assert len(result) == 10
    assert elapsed < 0.30, f"elapsed={elapsed:.3f}s — site lookups do not appear to run in parallel"


@pytest.mark.asyncio
async def test_resolve_site_concurrency_fanout_limit_bounds_concurrency(monkeypatch):
    """The fan-out semaphore actually caps how many lookups run at once —
    with the limit set to 1, six 0.05s lookups must take close to 6*0.05s,
    not overlap."""
    monkeypatch.setattr(circuit, "_LOOKUP_FANOUT_LIMIT", 1)
    devices = [_device(f"r{i}") for i in range(6)]
    site_of = {f"r{i}": f"K{i:03d}" for i in range(6)}
    _patch_site(monkeypatch, site_of)
    site_codes = list(site_of.values())

    def slow_get_config(dnac, device_id):
        time.sleep(0.05)
        return "interface Tunnel5000\n bandwidth 50000\n!\n"

    with patch("utils.swim_site_circuit.dnac_client.get_device_config", side_effect=slow_get_config):
        start = time.monotonic()
        await circuit.resolve_site_concurrency(site_codes, dnac=object(), devices=devices, device_site_map={})
        elapsed = time.monotonic() - start

    assert elapsed > 0.25, f"elapsed={elapsed:.3f}s — fan-out limit of 1 did not serialize the lookups"
