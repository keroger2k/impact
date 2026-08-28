"""Tests for scripts/nexus_interface_report.py parsing + rendering.

The fixtures are hand-written NX-OS output shapes, not captures from real
hardware — all addressing is fake per docs/IP_ADDRESS_POLICY.md.
"""
import pytest

from scripts.nexus_interface_report import (
    InterfaceStats,
    build_table,
    normalize_iface_name,
    parse_err_disabled,
    parse_port_channel_summary,
    parse_show_interface,
    parse_transceivers,
    parse_trunk,
)

SHOW_INTERFACE = """
Ethernet1/1 is up
admin state is up, Dedicated Interface
  Hardware: 1000/10000 Ethernet, address: 0050.5685.a1b2 (bia 0050.5685.a1b2)
  Description: uplink-to-core
  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec
  reliability 255/255, txload 40/255, rxload 90/255
  Port mode is trunk
  full-duplex, 10 Gb/s, media type is 10G
  Auto-Negotiation is turned on, FEC mode is Auto
  Last link flapped 00:04:12
  Last clearing of "show interface" counters never
  3 interface resets
  30 seconds input rate 12345678 bits/sec, 1234 packets/sec
  30 seconds output rate 87654321 bits/sec, 5678 packets/sec
  RX
    123456789 unicast packets  1234 multicast packets  5678 broadcast packets
    123463701 input packets  987654321098 bytes
    45 runts  3 giants  912 CRC  0 no buffer
    960 input error  0 short frame  0 overrun   0 underrun  0 ignored
  TX
    123463692 output packets  876543210987 bytes
    0 output error  0 collision  0 deferred  0 late collision
    17 output discard

Ethernet1/2 is down (Link not connected)
admin state is up, Dedicated Interface
  Hardware: 1000/10000 Ethernet, address: 0050.5685.a1c0 (bia 0050.5685.a1c0)
  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec
  Port mode is access
  Last clearing of "show interface" counters 3w2d
  0 interface resets

Ethernet1/3 is down (Administratively down)
admin state is down, Dedicated Interface
  Hardware: 1000/10000 Ethernet, address: 0050.5685.a1c3 (bia 0050.5685.a1c3)
  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec

Vlan10 is up, line protocol is up
  Hardware is EtherSVI, address is 0050.5685.a1b3
  Internet Address is 1.2.3.4/24
  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  RX
    100 input packets  5000 bytes
  TX
    90 output packets  4500 bytes
"""


@pytest.fixture(scope="module")
def ifaces():
    return parse_show_interface(SHOW_INTERFACE)


# ── Tier 1: fields already present in `show interface` ──────────────────────

def test_parses_counter_age_flap_and_resets(ifaces):
    eth1 = ifaces["Ethernet1/1"]
    assert eth1.counters_cleared == "never"
    assert eth1.counters_are_lifetime is True
    assert eth1.last_flapped == "00:04:12"
    assert eth1.interface_resets == 3

    # A cleared-counters value is captured verbatim, not coerced to "never".
    assert ifaces["Ethernet1/2"].counters_cleared == "3w2d"
    assert ifaces["Ethernet1/2"].counters_are_lifetime is False


def test_parses_l2_l3_context(ifaces):
    eth1 = ifaces["Ethernet1/1"]
    assert eth1.port_mode == "trunk"
    assert eth1.mac_address == "00:50:56:85:a1:b2"
    assert eth1.autoneg == "on"
    assert eth1.fec_mode == "Auto"

    svi = ifaces["Vlan10"]
    assert svi.ipv4_address == "1.2.3.4/24"
    # An address implies routed even with no explicit "Port mode" line.
    assert svi.port_mode == "routed"


def test_byte_counters_and_totals(ifaces):
    eth1 = ifaces["Ethernet1/1"]
    assert eth1.input_bytes == 987654321098
    assert eth1.output_bytes == 876543210987
    assert eth1.total_bytes == 987654321098 + 876543210987
    # No RX/TX block at all -> None, distinct from a real zero.
    assert ifaces["Ethernet1/3"].total_bytes is None


# ── Errors vs drops ─────────────────────────────────────────────────────────

def test_errors_and_drops_are_counted_separately(ifaces):
    eth1 = ifaces["Ethernet1/1"]
    assert "crc" in eth1.input_errors
    assert "runts" in eth1.input_errors
    # Discards are congestion, not integrity faults — they must not land in
    # the error bucket or a busy uplink looks like a failing optic.
    assert "output_discard" in eth1.output_drops
    assert "output_discard" not in eth1.output_errors
    assert eth1.drop_total == 17


def test_error_total_does_not_double_count_the_rollup(ifaces):
    """NX-OS prints "960 input error" AND its components (45+3+912=960).
    Summing everything reports exactly double the real fault count."""
    eth1 = ifaces["Ethernet1/1"]
    assert eth1.input_errors["input_error"] == 960
    assert eth1.input_errors["crc"] == 912
    assert eth1.error_total == 960


# ── State helpers ───────────────────────────────────────────────────────────

def test_up_down_and_admin_down_classification(ifaces):
    assert ifaces["Ethernet1/1"].is_oper_up is True
    assert ifaces["Ethernet1/1"].is_unexpectedly_down is False

    # Down but NOT shut -> should be up, worth triaging.
    assert ifaces["Ethernet1/2"].is_unexpectedly_down is True

    # Shut on purpose -> down, but not a fault.
    assert ifaces["Ethernet1/3"].is_admin_down is True
    assert ifaces["Ethernet1/3"].is_unexpectedly_down is False


def test_is_physical_flags_non_physical_interfaces(ifaces):
    """load% is scaled against configured BW, so it is only a saturation
    signal on real ports."""
    assert ifaces["Ethernet1/1"].is_physical is True
    assert ifaces["Vlan10"].is_physical is False


# ── Transceiver DOM ─────────────────────────────────────────────────────────

TRANSCEIVER = """
Ethernet1/1
    transceiver is present
    type is 10Gbase-SR
    serial number is AVD1610A0X1

  Temperature   32.65 C        75.00 C     -5.00 C     70.00 C        0.00 C
  Voltage        3.28 V         3.63 V      2.97 V      3.46 V        3.13 V
  Current        7.79 mA       11.80 mA     4.00 mA    10.80 mA       5.00 mA
  Tx Power      -2.35 dBm       1.99 dBm  -11.30 dBm   -1.00 dBm     -7.30 dBm
  Rx Power     -14.42 dBm --    1.99 dBm  -13.97 dBm   -1.00 dBm     -9.91 dBm

Ethernet1/2
    transceiver is not present

Ethernet1/3
    transceiver is present
    type is 10Gbase-LR
  Rx Power      -8.20 dBm -     1.99 dBm  -13.97 dBm   -1.00 dBm     -7.91 dBm
"""


def test_transceiver_dom_and_alarm_markers():
    optics = parse_transceivers(TRANSCEIVER)

    eth1 = optics["Ethernet1/1"]
    assert eth1.present is True
    assert eth1.type == "10Gbase-SR"
    assert eth1.serial == "AVD1610A0X1"
    assert eth1.rx_power_dbm == -14.42
    assert eth1.rx_power_flag == "--"      # low-alarm, per the switch itself
    assert eth1.tx_power_dbm == -2.35
    assert eth1.tx_power_flag is None
    assert eth1.temperature_c == 32.65
    assert eth1.voltage_v == 3.28
    assert eth1.current_ma == 7.79
    assert eth1.has_alarm is True
    assert eth1.has_warning is False

    # An empty cage is recorded, not omitted — "no optic" and "never checked"
    # are different answers.
    assert optics["Ethernet1/2"].present is False
    assert optics["Ethernet1/2"].rx_power_dbm is None

    warn = optics["Ethernet1/3"]
    assert warn.rx_power_flag == "-"
    assert warn.has_warning is True
    assert warn.has_alarm is False


# ── err-disabled / port-channel / trunk ─────────────────────────────────────

def test_err_disabled_reason():
    text = """
--------------------------------------------------------------------------------
Port          Name               Status      Reason
--------------------------------------------------------------------------------
Eth1/5        --                 errDisabled  bpduguard
Eth1/6        some description   errDisabled  link-flap
"""
    out = parse_err_disabled(text)
    assert out["Ethernet1/5"] == "bpduguard"
    # Name column contains spaces — the row must not be split by position.
    assert out["Ethernet1/6"] == "link-flap"


def test_port_channel_member_flags():
    text = """
Group Port-       Type     Protocol  Member Ports
      Channel
--------------------------------------------------------------------------------
1     Po1(SU)     Eth      LACP      Eth1/1(P)    Eth1/2(I)
2     Po2(SD)     Eth      LACP      Eth1/7(s)
"""
    out = parse_port_channel_summary(text)
    assert out["Ethernet1/1"] == ("Po1", "P")
    # (I)ndividual = LACP never converged; the LAG is silently degraded.
    assert out["Ethernet1/2"] == ("Po1", "I")
    assert out["Ethernet1/7"] == ("Po2", "S")


def test_trunk_native_and_allowed_vlans():
    text = """
--------------------------------------------------------------------------------
Port          Native  Status        Port
              Vlan                  Channel
--------------------------------------------------------------------------------
Eth1/1        99      trunking      Po1

--------------------------------------------------------------------------------
Port          Vlans Allowed on Trunk
--------------------------------------------------------------------------------
Eth1/1        10,20,30-40

--------------------------------------------------------------------------------
Port          STP Forwarding
--------------------------------------------------------------------------------
Eth1/1        10,20
"""
    out = parse_trunk(text)
    assert out["Ethernet1/1"].native_vlan == "99"
    assert out["Ethernet1/1"].allowed_vlans == "10,20,30-40"


# ── interface-name normalization (regression) ───────────────────────────────

@pytest.mark.parametrize("given", [
    "Eth1/1", "eth1/1", "ETH1/1", "ethernet1/1", "Ethernet1/1", "ETHERNET1/1",
])
def test_normalize_accepts_any_casing_or_abbreviation(given):
    """Regression: a lowercase FULL name used to normalize to itself and miss
    the canonical dict key, so --interface worked or failed depending on how
    much of the name you typed."""
    assert normalize_iface_name(given) == "Ethernet1/1"


@pytest.mark.parametrize("given,expected", [
    ("po1", "port-channel1"),
    ("PORT-CHANNEL1", "port-channel1"),
    ("vl10", "Vlan10"),
    ("vlan10", "Vlan10"),
    ("lo0", "loopback0"),
])
def test_normalize_other_interface_families(given, expected):
    assert normalize_iface_name(given) == expected


# ── table rendering ─────────────────────────────────────────────────────────

def _headers(table):
    return [c.header for c in table.columns]


def test_table_hides_columns_that_are_empty_for_every_row():
    bare = InterfaceStats(name="Ethernet9/9", oper_status="up")
    headers = _headers(build_table([bare], "name", False))
    assert "Interface" in headers and "Status" in headers
    # Nothing to show for these on a plain device -> dropped, not a wall of "-"
    for absent in ("Drops", "Last Flap", "Rx dBm", "Mode"):
        assert absent not in headers


def test_table_shows_optional_columns_when_data_exists(ifaces):
    headers = _headers(build_table(list(ifaces.values()), "name", False))
    assert "Drops" in headers
    assert "Last Flap" in headers
    assert "Mode" in headers


def test_up_only_and_down_only_filters(ifaces):
    rows = list(ifaces.values())

    up = build_table(rows, "name", False, up_only=True)
    assert up.row_count == 2  # Ethernet1/1 + Vlan10

    # Only ports that should be up but aren't — excludes the shut one.
    down = build_table(rows, "name", False, down_only=True)
    assert down.row_count == 1


def test_sort_by_bytes_puts_busiest_first(ifaces):
    table = build_table(list(ifaces.values()), "bytes", False)
    first_cell = table.columns[0]._cells[0]
    assert "Ethernet1/1" in str(first_cell)
