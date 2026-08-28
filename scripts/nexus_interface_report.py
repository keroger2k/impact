#!/usr/bin/env python3
"""scripts/nexus_interface_report.py — per-interface health report for one Cisco Nexus switch.

Given a device name (looked up in data/device_lists/nexus.csv) or a bare IP
(--ip), this SSHes to the switch (Netmiko) and runs read-only show commands:

    1. show interface
       The workhorse — admin/line-protocol state, description, speed/duplex,
       MTU/BW, port mode, IPv4/MAC, auto-negotiation + FEC mode, NX-OS's own
       txload/rxload (a 0-255 load scale, used directly as the busy signal
       rather than computed from raw bps), 30s in/out rates, cumulative RX/TX
       byte counters, and the RX/TX counter blocks.

       Three fields out of this command carry most of the diagnostic weight
       and are easy to overlook:
         - "Last clearing of counters" — the denominator for every cumulative
           number here. 500 CRC since 2019 and 500 CRC since Tuesday are the
           same integer and completely different incidents.
         - "Last link flapped" + "N interface resets" — recency and count of
           link transitions; usually the fastest route to the actual fault.
         - Auto-negotiation / FEC mode — a frequent root cause of CRC errors
           on 25G/100G links.

    2. show interface transceiver details
       Optical DOM: Rx/Tx power, temperature, voltage, bias current, each with
       NX-OS's own alarm/warning markers. Most "random CRCs / random flaps"
       tickets are a marginal or dying optic, and nothing else collected here
       can see that. Absent on copper/virtual ports — that's not an error.

    3. show interface status err-disabled
       WHY a port is down. A bare "down" is not actionable; "err-disabled
       (bpduguard)" is.

    4. show port-channel summary
       Member->port-channel mapping and per-member state flags. A LAG running
       at half capacity because one member is (s)uspended or (I)ndividual
       otherwise looks perfectly healthy port-by-port.

    5. show interface trunk
       Native VLAN and allowed-VLAN list per trunk — the answer to most
       "why won't VLAN X pass" questions.

    6. show cdp neighbors detail
       Primary "what's plugged into this port" source.

    7. show lldp neighbors detail
       Fallback neighbor source for ports CDP didn't cover (e.g. a neighbor
       with CDP disabled). If LLDP itself isn't enabled on this switch, the
       command errors out — that's detected and treated as "no LLDP data",
       not a failure; the report still runs on CDP alone.

Every command after the first is best-effort: a device that doesn't support
one (no optics, no LACP, LLDP disabled) degrades that column to empty rather
than failing the run.

Nothing else is ever sent — no send_config_set, no write verbs of any kind.

Output is a single Rich table, sorted busiest-first by default. Columns that
are empty for every interface on the device are dropped automatically, so a
switch with no optics or no drops gets a narrower table rather than a screen
of "-". Errors and drops are deliberately counted SEPARATELY: CRC/runts/
giants are physical-layer corruption, while output discards are usually
normal congestion or QoS policy — summing them makes a busy-but-healthy
uplink indistinguishable from a failing optic.

Auth: defaults to the shared AD service account (DOMAIN_USERNAME/
DOMAIN_PASSWORD in .env — same as every other script here); override with
--username/--password for a specific run.

Usage:
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --errors-only
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --down-only
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --sort flaps
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --sort optics
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --interface Ethernet1/1
    .venv/bin/python -m scripts.nexus_interface_report --ip 1.2.3.4 --hostname spare-switch
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --raw ./raw_output -v
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from difflib import get_close_matches
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

from utils.nxos_interface import (  # noqa: E402
    CLEARED_RE,
    INPUT_BYTES_RE,
    LAST_FLAP_RE,
    OUTPUT_BYTES_RE,
    RESETS_RE,
    format_bytes as _format_bytes,
)

logger = logging.getLogger("nexus_interface_report")

SSH_TIMEOUT_DEFAULT = 60  # show interface on a big chassis can run long; collectors/nxos.py also uses 60s for it
NEXUS_CSV_PATH = Path("data/device_lists/nexus.csv")
DEVICE_TYPE = "cisco_nxos"

# ─────────────────────────── interface name normalization ──────────────────
# CDP's "Interface:" field and (especially) LLDP's "Local Port id:" field
# sometimes report a short form ("Eth1/1") where `show interface` uses the
# long form ("Ethernet1/1") as the block header — same class of mismatch as
# the SNA/bandwidth-report interface-name bug documented in CLAUDE.md.
# Canonicalize before using a name as a dict key so neighbor merging isn't
# silently broken by which form a given command happened to use.
_IFACE_ABBREV_MAP = {
    "eth": "Ethernet",
    "po": "port-channel",
    "vl": "Vlan",
    "lo": "loopback",
    "tu": "tunnel",
    "nv": "nve",
    "mgmt": "mgmt",
}

# The canonical spelling `show interface` uses for each long form. Without
# these, a user-typed lowercase FULL name ("ethernet1/1") normalized to itself
# and missed the "Ethernet1/1" dict key, while the abbreviation ("eth1/1")
# resolved fine — so --interface worked or failed depending on how much of the
# name you typed. Both forms now land on the same canonical key.
_IFACE_CANONICAL = {v.lower(): v for v in _IFACE_ABBREV_MAP.values()}


def normalize_iface_name(name: str) -> str:
    m = re.match(r"^([A-Za-z-]+)(\d.*)$", name.strip())
    if not m:
        return name.strip()
    prefix, rest = m.groups()
    key = prefix.lower()
    long_form = _IFACE_ABBREV_MAP.get(key) or _IFACE_CANONICAL.get(key)
    return f"{long_form}{rest}" if long_form else name.strip()


# ─────────────────────────── data model ─────────────────────────────────────

@dataclass
class NeighborInfo:
    device_id: str
    remote_port: str | None
    platform: str | None  # CDP only
    source: str  # "cdp" | "lldp"


@dataclass
class TransceiverInfo:
    """Optical DOM for one port, from `show interface transceiver details`.

    `*_flag` carries NX-OS's own threshold marker as printed next to the
    measurement ("++" high-alarm, "+" high-warning, "--" low-alarm, "-"
    low-warning, None = within range). Trusting the device's markers avoids
    hardcoding per-optic thresholds that legitimately differ by transceiver
    model — the switch already knows them, having read the optic's EEPROM.
    """
    present: bool = False
    type: str | None = None
    serial: str | None = None
    temperature_c: float | None = None
    voltage_v: float | None = None
    current_ma: float | None = None
    tx_power_dbm: float | None = None
    tx_power_flag: str | None = None
    rx_power_dbm: float | None = None
    rx_power_flag: str | None = None

    @property
    def has_alarm(self) -> bool:
        return any(f in ("++", "--") for f in (self.tx_power_flag, self.rx_power_flag) if f)

    @property
    def has_warning(self) -> bool:
        return any(f in ("+", "-") for f in (self.tx_power_flag, self.rx_power_flag) if f)


@dataclass
class TrunkInfo:
    native_vlan: str | None = None
    allowed_vlans: str | None = None


@dataclass
class InterfaceStats:
    name: str
    oper_status: str = "unknown"  # "up" | "down", from the header line
    admin_status: str = "unknown"  # "up" | "administratively down" (best-effort)
    line_protocol: str | None = None
    description: str | None = None
    speed: str | None = None
    duplex: str | None = None
    mtu: int | None = None
    bandwidth_kbit: int | None = None
    txload: int | None = None  # raw NX-OS 0-255 scale
    rxload: int | None = None
    input_rate_bps: int | None = None
    input_rate_pps: int | None = None
    output_rate_bps: int | None = None
    output_rate_pps: int | None = None
    input_bytes: int | None = None   # cumulative RX byte counter, since last clear
    output_bytes: int | None = None  # cumulative TX byte counter, since last clear
    # Integrity faults (CRC/runts/giants/...) vs congestion drops (discards).
    # Kept apart on purpose: a saturated-but-healthy uplink and a failing optic
    # both produce nonzero counters, and folding them together makes the two
    # indistinguishable at a glance — which is the whole point of this report.
    input_errors: dict[str, int] = field(default_factory=dict)
    output_errors: dict[str, int] = field(default_factory=dict)
    input_drops: dict[str, int] = field(default_factory=dict)
    output_drops: dict[str, int] = field(default_factory=dict)
    # Counter provenance — the denominator for every cumulative number above.
    counters_cleared: str | None = None   # "never" | "3w2d" | ...
    last_flapped: str | None = None       # "3d02h" | ...
    interface_resets: int | None = None
    # L2/L3 context, all already present in `show interface` output
    port_mode: str | None = None          # access | trunk | routed | ...
    ipv4_address: str | None = None
    mac_address: str | None = None
    autoneg: str | None = None            # "on" | "off"
    fec_mode: str | None = None
    # From the supplementary commands
    optics: TransceiverInfo | None = None
    err_disabled_reason: str | None = None
    port_channel: str | None = None       # parent Po for a member port
    pc_member_state: str | None = None    # P (bundled) | I (individual) | s (suspended) | ...
    trunk: TrunkInfo | None = None
    neighbor: NeighborInfo | None = None
    raw_block: str = ""

    @property
    def txload_pct(self) -> float | None:
        return round(self.txload / 255 * 100, 1) if self.txload is not None else None

    @property
    def rxload_pct(self) -> float | None:
        return round(self.rxload / 255 * 100, 1) if self.rxload is not None else None

    @property
    def util_pct(self) -> float | None:
        vals = [v for v in (self.txload_pct, self.rxload_pct) if v is not None]
        return max(vals) if vals else None

    @property
    def total_bytes(self) -> int | None:
        """Combined RX+TX traffic, or None if neither counter was collected."""
        if self.input_bytes is None and self.output_bytes is None:
            return None
        return (self.input_bytes or 0) + (self.output_bytes or 0)

    @property
    def error_total(self) -> int:
        return _fault_total(self.input_errors) + _fault_total(self.output_errors)

    @property
    def drop_total(self) -> int:
        return _fault_total(self.input_drops) + _fault_total(self.output_drops)

    @property
    def is_admin_down(self) -> bool:
        return "administratively down" in (self.admin_status or "").lower()

    @property
    def is_oper_up(self) -> bool:
        return self.oper_status == "up"

    @property
    def is_unexpectedly_down(self) -> bool:
        """Down while not administratively shut — i.e. it should be up.
        This is the set worth triaging; a shut port is down on purpose."""
        return not self.is_oper_up and not self.is_admin_down

    @property
    def counters_are_lifetime(self) -> bool:
        """True when counters have never been cleared, so the totals span the
        box's whole uptime. Large error counts are far less alarming here."""
        return (self.counters_cleared or "").strip().lower() == "never"

    @property
    def is_physical(self) -> bool:
        """Physical ports only. SVIs/port-channels/loopbacks report a
        configured (often default) BW, so their load% is not a saturation
        signal the way a real port's is — see rxload_pct/txload_pct."""
        return self.name.lower().startswith(("ethernet", "mgmt"))


# ─────────────────────────── "show interface" parsing ───────────────────────

_IFACE_HEADER_RE = re.compile(
    r"^(Ethernet\S+|port-channel\S+|Vlan\S+|mgmt\S+|loopback\S+|tunnel\S+|nve\S+)\s+is\s+"
    r"(up|down)(?:\s*\(([^)]*)\))?",
    re.IGNORECASE,
)
_ADMIN_STATE_RE = re.compile(r"^admin state is (up|down)", re.IGNORECASE)
_LINE_PROTOCOL_RE = re.compile(r"line protocol is (up|down)", re.IGNORECASE)
_DESCRIPTION_RE = re.compile(r"^Description:\s*(.+)$", re.IGNORECASE)
_MTU_BW_RE = re.compile(r"^MTU\s+(\d+)\s+bytes,\s*BW\s+(\d+)\s*Kbit", re.IGNORECASE)
_LOAD_RE = re.compile(r"txload\s+(\d+)/255,\s*rxload\s+(\d+)/255", re.IGNORECASE)
_DUPLEX_SPEED_RE = re.compile(r"^(full|half)-duplex,\s*([^,]+?),\s*media type", re.IGNORECASE)
_INPUT_RATE_RE = re.compile(r"^\d+\s+seconds\s+input\s+rate\s+(\d+)\s*bits/sec,\s*(\d+)\s*packets/sec", re.IGNORECASE)
_OUTPUT_RATE_RE = re.compile(r"^\d+\s+seconds\s+output\s+rate\s+(\d+)\s*bits/sec,\s*(\d+)\s*packets/sec", re.IGNORECASE)

# Byte counters, counter age, flap recency and reset count all come from
# utils.nxos_interface so collectors/nxos.py parses the identical lines.
_INPUT_BYTES_RE = INPUT_BYTES_RE
_OUTPUT_BYTES_RE = OUTPUT_BYTES_RE

# Additional context lines already present in `show interface` output.
_PORT_MODE_RE = re.compile(r"^Port\s+mode\s+is\s+(\S+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"^Internet\s+Address\s+is\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", re.IGNORECASE)
_MAC_RE = re.compile(r"address[:\s]+is\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})|address:\s*([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", re.IGNORECASE)
_AUTONEG_RE = re.compile(r"Auto-Negotiation\s+is\s+turned\s+(\w+)", re.IGNORECASE)
_FEC_RE = re.compile(r"FEC\s+mode\s+is\s+(\S+?)\s*$", re.IGNORECASE)

# Matches "<count>  <label>" pairs on a counter line, e.g.
# "0 runts  0 giants  0 CRC/FCS  0 no buffer" -> [("0","runts"), ("0","giants"), ...]
_COUNTER_PAIR_RE = re.compile(r"(\d+)\s+([A-Za-z][A-Za-z/ \-]*?)(?=\s{2,}\d|\s*$)")

# The RX/TX blocks also carry plain traffic counters (unicast/multicast
# packets, bytes, pause frames) that must NOT be counted as faults, or every
# interface reads as "erroring" and the report's whole point is defeated.
#
# Of the counters that ARE faults, two classes are tracked separately:
#   _ERROR_KEYWORDS — physical-layer integrity. Something is corrupting
#     frames: bad optic, bad cable, duplex/FEC mismatch. Always worth a look.
#   _DROP_KEYWORDS  — the switch chose not to forward. Usually congestion or
#     QoS policy, i.e. a capacity conversation, not a hardware fault.
# Order matters in _classify_counter: "input discard" contains neither an
# error keyword nor ambiguity, but "no buffer" is a drop despite sounding
# like an error, so drops are tested first.
_ERROR_KEYWORDS = (
    "error", "crc", "runt", "giant", "collision", "overrun", "underrun",
    "babble", "carrier", "watchdog", "frame", "jabber", "fcs",
)
_DROP_KEYWORDS = (
    "drop", "discard", "no buffer", "ignored", "throttle",
)


def _classify_counter(label: str) -> str | None:
    """Return "drop", "error", or None (not a fault counter at all)."""
    if any(kw in label for kw in _DROP_KEYWORDS):
        return "drop"
    if any(kw in label for kw in _ERROR_KEYWORDS):
        return "error"
    return None


# NX-OS prints both a roll-up and its components in the same RX/TX block:
#     45 runts  3 giants  912 CRC  0 no buffer
#     960 input error  0 short frame  0 overrun  0 underrun  0 ignored
# 45+3+912 == 960 — "input error" IS the sum of the others. Adding every
# counter together therefore reports exactly double the real fault count, so
# when a roll-up is present it wins and the components are kept only for the
# human-readable breakdown.
_AGGREGATE_ERROR_KEYS = ("input_error", "output_error", "input_errors", "output_errors")


def _fault_total(counters: dict[str, int]) -> int:
    """Total faults for one direction, without double-counting the roll-up."""
    aggregates = {k: v for k, v in counters.items() if k in _AGGREGATE_ERROR_KEYS}
    if aggregates:
        return sum(aggregates.values())
    return sum(counters.values())


def parse_show_interface(text: str) -> dict[str, InterfaceStats]:
    interfaces: dict[str, InterfaceStats] = {}
    current: InterfaceStats | None = None
    current_lines: list[str] = []
    section: str | None = None  # None | "rx" | "tx"

    def flush() -> None:
        if current is not None:
            current.raw_block = "\n".join(current_lines)
            interfaces[current.name] = current

    for raw_line in text.splitlines():
        stripped = raw_line.strip()

        header = _IFACE_HEADER_RE.match(raw_line)
        if header:
            flush()
            name, oper, paren = header.group(1), header.group(2).lower(), header.group(3) or ""
            current = InterfaceStats(name=name, oper_status=oper)
            current.admin_status = "administratively down" if "administrative" in paren.lower() else oper
            current_lines = [raw_line]
            section = None
            lp = _LINE_PROTOCOL_RE.search(raw_line)
            if lp:
                current.line_protocol = lp.group(1).lower()
            continue

        if current is None:
            continue
        current_lines.append(raw_line)

        m = _ADMIN_STATE_RE.match(stripped)
        if m:
            current.admin_status = "up" if m.group(1).lower() == "up" else "administratively down"
            continue
        m = _DESCRIPTION_RE.match(stripped)
        if m:
            current.description = m.group(1).strip()
            continue
        m = _MTU_BW_RE.match(stripped)
        if m:
            current.mtu = int(m.group(1))
            current.bandwidth_kbit = int(m.group(2))
            continue
        m = _LOAD_RE.search(stripped)
        if m:
            current.txload = int(m.group(1))
            current.rxload = int(m.group(2))
            continue
        m = _DUPLEX_SPEED_RE.match(stripped)
        if m:
            current.duplex = f"{m.group(1).lower()}-duplex"
            current.speed = m.group(2).strip()
            continue
        m = _INPUT_RATE_RE.match(stripped)
        if m:
            current.input_rate_bps = int(m.group(1))
            current.input_rate_pps = int(m.group(2))
            continue
        m = _OUTPUT_RATE_RE.match(stripped)
        if m:
            current.output_rate_bps = int(m.group(1))
            current.output_rate_pps = int(m.group(2))
            continue
        m = _INPUT_BYTES_RE.match(stripped)
        if m:
            current.input_bytes = int(m.group(1))
            continue
        m = _OUTPUT_BYTES_RE.match(stripped)
        if m:
            current.output_bytes = int(m.group(1))
            continue

        # ── counter provenance + flap history ──────────────────────────────
        m = CLEARED_RE.match(stripped)
        if m:
            current.counters_cleared = m.group(1).strip()
            continue
        m = LAST_FLAP_RE.match(stripped)
        if m:
            current.last_flapped = m.group(1).strip()
            continue
        m = RESETS_RE.match(stripped)
        if m:
            current.interface_resets = int(m.group(1))
            continue

        # ── L2/L3 context already in this output ───────────────────────────
        m = _PORT_MODE_RE.match(stripped)
        if m:
            current.port_mode = m.group(1).strip().rstrip(",").lower()
            continue
        m = _IPV4_RE.match(stripped)
        if m:
            current.ipv4_address = m.group(1)
            # A port with an IP is routed, even if no "Port mode" line said so.
            current.port_mode = current.port_mode or "routed"
            continue
        if current.mac_address is None and ("address is" in stripped.lower() or "address:" in stripped.lower()):
            mac_m = _MAC_RE.search(stripped)
            if mac_m:
                raw_mac = (mac_m.group(1) or mac_m.group(2) or "").replace(".", "")
                if len(raw_mac) == 12:
                    current.mac_address = ":".join(raw_mac[i:i + 2] for i in range(0, 12, 2)).lower()
        m = _AUTONEG_RE.search(stripped)
        if m:
            current.autoneg = m.group(1).strip().lower()
            # FEC often shares this line: "Auto-Negotiation is turned on, FEC mode is Auto"
            fec_m = _FEC_RE.search(stripped)
            if fec_m:
                current.fec_mode = fec_m.group(1).strip()
            continue
        m = _FEC_RE.search(stripped)
        if m and current.fec_mode is None:
            current.fec_mode = m.group(1).strip()
            continue

        if current.line_protocol is None:
            lp = _LINE_PROTOCOL_RE.search(stripped)
            if lp:
                current.line_protocol = lp.group(1).lower()
                continue

        if stripped == "RX":
            section = "rx"
            continue
        if stripped == "TX":
            section = "tx"
            continue

        if section in ("rx", "tx"):
            for count_str, label in _COUNTER_PAIR_RE.findall(stripped):
                label_norm = label.strip().lower()
                kind = _classify_counter(label_norm)
                if kind is None:
                    continue
                if kind == "error":
                    target = current.input_errors if section == "rx" else current.output_errors
                else:
                    target = current.input_drops if section == "rx" else current.output_drops
                key = re.sub(r"[^a-z0-9]+", "_", label_norm).strip("_")
                target[key] = target.get(key, 0) + int(count_str)

    flush()
    return interfaces


# ─────────────────────────── transceiver (optical DOM) parsing ──────────────

# A DOM measurement row, e.g.
#   "  Rx Power      -3.42 dBm       1.99 dBm  -13.97 dBm   -1.00 dBm   -9.91 dBm"
#   "  Rx Power     -14.42 dBm --    1.99 dBm  -13.97 dBm   -1.00 dBm   -9.91 dBm"
# Only the FIRST value (the current measurement) is captured, plus NX-OS's own
# threshold marker if it printed one. The remaining four columns are the
# optic's own alarm/warning thresholds — deliberately not parsed, because the
# marker already encodes the comparison the switch made against them.
_DOM_ROW_RE = re.compile(
    r"^(Temperature|Voltage|Current|Tx\s+Power|Rx\s+Power)\s+"
    r"(-?[\d.]+)\s*(?:C|V|mA|dBm)\s*"
    r"(\+\+|--|\+|-)?(?=\s|$)",
    re.IGNORECASE,
)
_XCVR_TYPE_RE = re.compile(r"^type\s+is\s+(\S+)", re.IGNORECASE)
_XCVR_SERIAL_RE = re.compile(r"^serial\s+number\s+is\s+(\S+)", re.IGNORECASE)
_XCVR_PRESENT_RE = re.compile(r"^transceiver\s+is\s+(not\s+)?present", re.IGNORECASE)
# Interface block headers in this command start at column 0 with a bare name.
_XCVR_HEADER_RE = re.compile(
    r"^(Ethernet\S+|port-channel\S+|mgmt\S+)\s*$", re.IGNORECASE
)


def parse_transceivers(text: str) -> dict[str, TransceiverInfo]:
    """Parse `show interface transceiver details` into {iface: TransceiverInfo}.

    Ports with no optic installed still get an entry (present=False) so the
    caller can tell "copper/empty port" apart from "command never ran".
    """
    out: dict[str, TransceiverInfo] = {}
    current_name: str | None = None
    current: TransceiverInfo | None = None

    def flush() -> None:
        if current_name and current is not None:
            out[normalize_iface_name(current_name)] = current

    for raw_line in text.splitlines():
        header = _XCVR_HEADER_RE.match(raw_line)
        if header:
            flush()
            current_name = header.group(1)
            current = TransceiverInfo()
            continue
        if current is None:
            continue

        stripped = raw_line.strip()

        m = _XCVR_PRESENT_RE.match(stripped)
        if m:
            current.present = m.group(1) is None
            continue
        m = _XCVR_TYPE_RE.match(stripped)
        if m:
            current.type = m.group(1)
            continue
        m = _XCVR_SERIAL_RE.match(stripped)
        if m:
            current.serial = m.group(1)
            continue

        m = _DOM_ROW_RE.match(stripped)
        if m:
            label = re.sub(r"\s+", " ", m.group(1)).strip().lower()
            value = float(m.group(2))
            flag = m.group(3)
            if label == "temperature":
                current.temperature_c = value
            elif label == "voltage":
                current.voltage_v = value
            elif label == "current":
                current.current_ma = value
            elif label == "tx power":
                current.tx_power_dbm, current.tx_power_flag = value, flag
            elif label == "rx power":
                current.rx_power_dbm, current.rx_power_flag = value, flag

    flush()
    return out


# ─────────────────────────── err-disabled parsing ───────────────────────────

# `show interface status err-disabled` rows, e.g.
#   "Eth1/5       some description   errDisabled  link-flap"
# The Name column is free text and may contain spaces, so the row is anchored
# on the status token rather than split by whitespace position.
_ERRDIS_ROW_RE = re.compile(
    r"^(\S+)\s+.*?\b(?:err[-\s]?[Dd]isabled|errDisabled)\b\s+(\S.*?)\s*$",
)


def parse_err_disabled(text: str) -> dict[str, str]:
    """Parse `show interface status err-disabled` into {iface: reason}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("-", "Port")):
            continue
        m = _ERRDIS_ROW_RE.match(line)
        if not m:
            continue
        iface, reason = m.group(1), m.group(2).strip()
        if reason and reason != "--":
            out[normalize_iface_name(iface)] = reason
    return out


# ─────────────────────────── port-channel summary parsing ───────────────────

# "1     Po1(SU)     Eth      LACP      Eth1/1(P)    Eth1/2(P)"
_PC_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(Po\d+)\(([A-Za-z]+)\)\s+\S+\s+\S+\s*(.*)$",
    re.IGNORECASE,
)
_PC_MEMBER_RE = re.compile(r"(\S+?)\(([A-Za-z])\)")


def parse_port_channel_summary(text: str) -> dict[str, tuple[str, str]]:
    """Parse `show port-channel summary` into {member_iface: (po_name, flag)}.

    The member flag is the diagnostic payload: (P) bundled, (I) individual —
    LACP never converged, (s) suspended, (D) down. A port-channel whose member
    is (I) or (s) is silently running at reduced capacity, which no per-port
    status field reveals.
    """
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = _PC_ROW_RE.match(line)
        if not m:
            continue
        po_name = m.group(2)
        members_raw = m.group(4) or ""
        for member, flag in _PC_MEMBER_RE.findall(members_raw):
            out[normalize_iface_name(member)] = (po_name, flag.upper())
    return out


# ─────────────────────────── trunk parsing ──────────────────────────────────

def parse_trunk(text: str) -> dict[str, TrunkInfo]:
    """Parse `show interface trunk` into {iface: TrunkInfo}.

    The command emits several separately-headed tables (native VLAN/status,
    allowed VLANs, STP-forwarding VLANs), all keyed by port. Only the first
    two are kept; the section is tracked by its header rather than by position
    so an extra table in a future NX-OS release doesn't shift the parse.
    """
    out: dict[str, TrunkInfo] = {}
    section: str | None = None

    def entry(name: str) -> TrunkInfo:
        key = normalize_iface_name(name)
        if key not in out:
            out[key] = TrunkInfo()
        return out[key]

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("-"):
            continue

        lowered = stripped.lower()
        if lowered.startswith("port"):
            if "native" in lowered:
                section = "native"
            elif "allowed" in lowered:
                section = "allowed"
            elif "forwarding" in lowered or "err" in lowered or "stp" in lowered:
                section = "other"
            else:
                section = section or "native"
            continue
        # Continuation of a wrapped header ("Vlan", "Channel", ...)
        if len(stripped.split()) == 1 and not re.match(r"^\S+\d", stripped):
            continue

        parts = stripped.split()
        if len(parts) < 2:
            continue
        iface = parts[0]
        if not re.match(r"^[A-Za-z]+[\d/]", iface):
            continue

        if section == "native":
            entry(iface).native_vlan = parts[1]
        elif section == "allowed":
            entry(iface).allowed_vlans = " ".join(parts[1:])

    return out


# ─────────────────────────── CDP / LLDP neighbor parsing ────────────────────

_FEATURE_DISABLED_MARKERS = ("invalid command", "not enabled", "% error")

_CDP_BLOCK_SPLIT_RE = re.compile(r"-{10,}")
_CDP_DEVICE_ID_RE = re.compile(r"Device ID\s*:\s*(\S+)", re.IGNORECASE)
_CDP_INTERFACE_RE = re.compile(r"Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)", re.IGNORECASE)
_CDP_PLATFORM_RE = re.compile(r"Platform:\s*([^,]+),", re.IGNORECASE)

_LLDP_LOCAL_PORT_RE = re.compile(r"^Local Port id:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_LLDP_REMOTE_PORT_RE = re.compile(r"^Port id:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_LLDP_SYSTEM_NAME_RE = re.compile(r"^System Name:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_LLDP_CHASSIS_ID_RE = re.compile(r"^Chassis id:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def is_feature_disabled_output(raw: str) -> bool:
    lowered = raw.lower()
    return any(marker in lowered for marker in _FEATURE_DISABLED_MARKERS)


def parse_cdp_neighbors(text: str) -> dict[str, NeighborInfo]:
    neighbors: dict[str, NeighborInfo] = {}
    for block in _CDP_BLOCK_SPLIT_RE.split(text):
        device_m = _CDP_DEVICE_ID_RE.search(block)
        iface_m = _CDP_INTERFACE_RE.search(block)
        if not device_m or not iface_m:
            continue
        platform_m = _CDP_PLATFORM_RE.search(block)
        local_iface = normalize_iface_name(iface_m.group(1))
        neighbors[local_iface] = NeighborInfo(
            device_id=device_m.group(1),
            remote_port=iface_m.group(2),
            platform=platform_m.group(1).strip() if platform_m else None,
            source="cdp",
        )
    return neighbors


def parse_lldp_neighbors(text: str) -> dict[str, NeighborInfo]:
    neighbors: dict[str, NeighborInfo] = {}
    blocks = re.split(r"(?=^Chassis id:)", text, flags=re.MULTILINE | re.IGNORECASE)
    for block in blocks:
        local_m = _LLDP_LOCAL_PORT_RE.search(block)
        if not local_m:
            continue
        local_iface = normalize_iface_name(local_m.group(1))
        remote_port_m = _LLDP_REMOTE_PORT_RE.search(block)
        name_m = _LLDP_SYSTEM_NAME_RE.search(block)
        chassis_m = _LLDP_CHASSIS_ID_RE.search(block)
        device_id = None
        if name_m and name_m.group(1).lower() not in ("not", "n/a", ""):
            device_id = name_m.group(1)
        elif chassis_m:
            device_id = chassis_m.group(1)
        if not device_id:
            continue
        neighbors[local_iface] = NeighborInfo(
            device_id=device_id,
            remote_port=remote_port_m.group(1) if remote_port_m else None,
            platform=None,
            source="lldp",
        )
    return neighbors


def merge_neighbors(
    interfaces: dict[str, InterfaceStats],
    cdp: dict[str, NeighborInfo],
    lldp: dict[str, NeighborInfo],
) -> None:
    """CDP always wins when both sources cover the same port — richer data
    (has Platform) — never blends fields from both sources for one port."""
    for name, stats in interfaces.items():
        norm = normalize_iface_name(name)
        stats.neighbor = cdp.get(norm) or lldp.get(norm)


def _find_neighbor_block(raw: str, iface_name: str, is_cdp: bool) -> str | None:
    if not raw:
        return None
    target = normalize_iface_name(iface_name)
    if is_cdp:
        for block in _CDP_BLOCK_SPLIT_RE.split(raw):
            m = _CDP_INTERFACE_RE.search(block)
            if m and normalize_iface_name(m.group(1)) == target:
                return block.strip()
    else:
        for block in re.split(r"(?=^Chassis id:)", raw, flags=re.MULTILINE | re.IGNORECASE):
            m = _LLDP_LOCAL_PORT_RE.search(block)
            if m and normalize_iface_name(m.group(1)) == target:
                return block.strip()
    return None


# ─────────────────────────── device resolution ──────────────────────────────

def load_nexus_csv(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.exists():
        return []
    rows: list[dict[str, str]] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hostname = (row.get("hostname") or "").strip()
            ip = (row.get("management ip address") or "").strip()
            if hostname and ip:
                rows.append({"hostname": hostname, "ip": ip})
    return rows


def resolve_device(name: str, rows: list[dict[str, str]]) -> tuple[str, str]:
    needle = name.strip().lower()
    for row in rows:
        if row["hostname"].lower() == needle:
            return row["hostname"], row["ip"]
    names = [r["hostname"] for r in rows]
    close = get_close_matches(name, names, n=5, cutoff=0.4)
    if not close:
        close = [n for n in names if needle in n.lower()][:5]
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    raise ValueError(f"No device '{name}' found in the Nexus device list.{hint}")


# ─────────────────────────── device SSH (read-only) ─────────────────────────

def ssh_run_commands(ip: str, username: str, password: str,
                      commands: list[tuple[str, str]], timeout: int,
                      required: tuple[str, ...] = ("show_interface",)) -> dict[str, str]:
    """SSH to one device and run each (label, command) with send_command
    only. Never issues send_config_set — this function has no write path.

    Individual commands are best-effort: a switch with no optics, no LACP or
    LLDP disabled should still produce a report, so a failing supplementary
    command yields an empty string instead of aborting the run. Labels in
    `required` still propagate their exception — without `show interface`
    there is no report to render.
    """
    from netmiko import ConnectHandler

    out: dict[str, str] = {}
    with ConnectHandler(
        device_type=DEVICE_TYPE,
        host=ip,
        username=username,
        password=password,
        timeout=timeout,
        conn_timeout=timeout,
        fast_cli=False,
    ) as conn:
        for label, cmd in commands:
            try:
                out[label] = conn.send_command(cmd, read_timeout=timeout) or ""
            except Exception as exc:
                if label in required:
                    raise
                logger.warning("'%s' failed (continuing without it): %s: %s",
                               cmd, type(exc).__name__, str(exc)[:120])
                out[label] = ""
    return out


# ─────────────────────────── rendering ───────────────────────────────────────

def _util_style(pct: float | None) -> str:
    if pct is None:
        return "dim"
    if pct > 70:
        return "red"
    if pct > 30:
        return "yellow"
    return "green"


def _fmt_pct(pct: float | None) -> Text:
    if pct is None:
        return Text("-", style="dim")
    return Text(f"{pct:.0f}%", style=_util_style(pct))


def _status_cell(stats: InterfaceStats) -> Text:
    if stats.is_admin_down:
        return Text("admin-down", style="dim")
    if stats.oper_status == "up":
        return Text("up", style="green")
    return Text("down", style="red")


def _counter_summary(counters_in: dict[str, int], counters_out: dict[str, int],
                      style: str) -> Text:
    total = _fault_total(counters_in) + _fault_total(counters_out)
    if total == 0:
        return Text("-", style="dim")
    # Lead with the total (de-duplicated against NX-OS's roll-up), then the
    # top contributing counters — the breakdown is what tells you whether it's
    # a cabling problem (runts/CRC) or something else.
    def _label(key: str, outbound: bool) -> str:
        # Counter names already carry their direction on NX-OS ("output
        # discard"); prefixing those again produced "out-output_discard".
        if outbound and not key.startswith(("output", "out_")):
            return f"out-{key}"
        return key

    parts = [f"{_label(k, False)}:{v}" for k, v in sorted(counters_in.items(), key=lambda kv: -kv[1])
             if v and k not in _AGGREGATE_ERROR_KEYS]
    parts += [f"{_label(k, True)}:{v}" for k, v in sorted(counters_out.items(), key=lambda kv: -kv[1])
              if v and k not in _AGGREGATE_ERROR_KEYS]
    # When a single named counter accounts for the whole total, the number on
    # its own is redundant — show just the breakdown.
    if len(parts) == 1 and parts[0].endswith(f":{total}"):
        return Text(parts[0], style=style)
    shown = f"{total}"
    if parts:
        shown += " (" + " ".join(parts[:2]) + ("…" if len(parts) > 2 else "") + ")"
    return Text(shown, style=style)


def _error_summary(stats: InterfaceStats) -> Text:
    return _counter_summary(stats.input_errors, stats.output_errors, "red")


def _drop_summary(stats: InterfaceStats) -> Text:
    # Yellow, not red: drops are usually a capacity conversation rather than a
    # fault, and colouring them like CRC errors is what trains people to
    # ignore the column entirely.
    return _counter_summary(stats.input_drops, stats.output_drops, "yellow")


def _bytes_cell(stats: InterfaceStats) -> Text:
    total = stats.total_bytes
    if total is None:
        return Text("N/A", style="dim")
    return Text(_format_bytes(total))


def _status_text(stats: InterfaceStats) -> Text:
    """Status, with the err-disable reason folded in — a bare 'down' is not
    actionable, 'err-dis(bpduguard)' is."""
    if stats.err_disabled_reason:
        return Text(f"err-dis({stats.err_disabled_reason})", style="bold red")
    return _status_cell(stats)


def _mode_cell(stats: InterfaceStats) -> Text:
    """Port mode plus port-channel membership, e.g. 'trunk Po10(P)'.
    A non-(P) member state is highlighted — that's a LAG quietly running
    below capacity."""
    bits: list[tuple[str, str]] = []
    if stats.port_mode:
        bits.append((stats.port_mode, ""))
    if stats.port_channel:
        flag = stats.pc_member_state or "?"
        bits.append((f"{stats.port_channel}({flag})", "" if flag == "P" else "bold yellow"))
    if not bits:
        return Text("-", style="dim")
    out = Text()
    for i, (txt, style) in enumerate(bits):
        if i:
            out.append(" ")
        out.append(txt, style=style or None)
    return out


def _flap_cell(stats: InterfaceStats) -> Text:
    """Last flap + reset count. The single fastest 'is this the problem right
    now' signal — an interface that bounced minutes ago reads very differently
    from one that has been stable for a year."""
    if stats.last_flapped is None and stats.interface_resets is None:
        return Text("-", style="dim")
    label = stats.last_flapped or "?"
    if stats.interface_resets:
        label += f" ({stats.interface_resets})"
    style = "red" if _flap_is_recent(stats.last_flapped) else ""
    return Text(label, style=style or None)


# "never", "3d02h", "1w4d", "00:05:12" — NX-OS mixes formats. Only the
# obviously-recent ones are highlighted; anything unparseable stays neutral
# rather than guessing.
def _flap_is_recent(flap: str | None) -> bool:
    if not flap:
        return False
    f = flap.strip().lower()
    if f == "never":
        return False
    if re.match(r"^\d{1,2}:\d{2}:\d{2}$", f):  # under a day
        return True
    m = re.match(r"^(\d+)m(\d+)s$", f)
    if m:
        return True
    m = re.match(r"^(\d+)d(\d+)h$", f)
    if m:
        return int(m.group(1)) < 1
    return False


def _optics_cell(stats: InterfaceStats) -> Text:
    """Rx optical power with the switch's own alarm/warning marker.

    Rx power is the one number that most often explains CRC errors and
    unexplained flaps, so it gets the column; the rest of the DOM data is in
    the --interface detail view.
    """
    o = stats.optics
    if o is None or not o.present or o.rx_power_dbm is None:
        return Text("-", style="dim")
    label = f"{o.rx_power_dbm:.2f}"
    if o.rx_power_flag:
        label += f" {o.rx_power_flag}"
    if o.rx_power_flag in ("++", "--"):
        style = "bold red"
    elif o.rx_power_flag in ("+", "-"):
        style = "yellow"
    else:
        style = "green"
    return Text(label, style=style)


def _neighbor_cell(stats: InterfaceStats) -> Text:
    n = stats.neighbor
    if n is None:
        return Text("-", style="dim")
    label = n.device_id
    if n.remote_port:
        label += f" ({n.remote_port})"
    if n.source == "lldp":
        label += " [lldp]"
    return Text(label)


def _counter_age_caption(rows: list[InterfaceStats]) -> str | None:
    """One-line note on counter provenance, shown under the table.

    Deliberately a caption rather than a per-row column: the value is almost
    always uniform across a device, and spending a whole column on the same
    repeated string crowds out data that actually varies. When it isn't
    uniform, the caption says so instead of hiding the difference.
    """
    values = {s.counters_cleared for s in rows if s.counters_cleared}
    if not values:
        return None
    if len(values) == 1:
        only = next(iter(values))
        if only.lower() == "never":
            return "Counters: never cleared (totals span device uptime)"
        return f"Counters: last cleared {only} ago"
    return f"Counters: cleared at differing times across interfaces ({len(values)} distinct)"


def build_table(interfaces: list[InterfaceStats], sort: str, errors_only: bool,
                 up_only: bool = False, down_only: bool = False) -> Table:
    rows = list(interfaces)
    if up_only:
        rows = [s for s in rows if s.is_oper_up]
    if down_only:
        rows = [s for s in rows if s.is_unexpectedly_down]
    if errors_only:
        rows = [s for s in rows if s.error_total > 0]

    if sort == "errors":
        rows.sort(key=lambda s: s.error_total, reverse=True)
    elif sort == "drops":
        rows.sort(key=lambda s: s.drop_total, reverse=True)
    elif sort == "name":
        rows.sort(key=lambda s: s.name)
    elif sort == "bytes":
        rows.sort(key=lambda s: s.total_bytes if s.total_bytes is not None else -1, reverse=True)
    elif sort == "flaps":
        # Most-reset first; ports that never reported a reset sort last.
        rows.sort(key=lambda s: s.interface_resets if s.interface_resets is not None else -1,
                  reverse=True)
    elif sort == "optics":
        # Weakest Rx power first — the end of the list you actually care about.
        rows.sort(key=lambda s: (
            s.optics.rx_power_dbm
            if s.optics and s.optics.present and s.optics.rx_power_dbm is not None
            else float("inf")
        ))
    else:  # "util" (default)
        rows.sort(key=lambda s: s.util_pct if s.util_pct is not None else -1, reverse=True)

    # Column spec: (header, renderer, always_show, kwargs). Columns whose every
    # cell is empty are dropped — a switch with no optics, no drops and no
    # port-channels gets a narrow readable table instead of three dead columns
    # of "-". Identity/state columns are pinned via always_show so the table
    # never loses its anchor columns on a quiet device.
    def _plain(text: str | None) -> Text:
        return Text(text) if text else Text("-", style="dim")

    specs: list[tuple[str, callable, bool, dict]] = [
        ("Interface",     lambda s: Text(s.name),                                   True,  {}),
        ("Status",        _status_text,                                              True,  {}),
        ("Mode",          _mode_cell,                                                False, {}),
        ("Description",   lambda s: _plain(s.description),                           True,
         {"overflow": "fold", "max_width": 24}),
        ("Speed/Duplex",  lambda s: _plain(", ".join(x for x in (s.speed, s.duplex) if x)), True, {}),
        ("In%",           lambda s: _fmt_pct(s.rxload_pct),                          True,  {"justify": "right"}),
        ("Out%",          lambda s: _fmt_pct(s.txload_pct),                          True,  {"justify": "right"}),
        ("Bytes (RX+TX)", _bytes_cell,                                               True,  {"justify": "right"}),
        ("Errors",        _error_summary,                                            True,  {}),
        ("Drops",         _drop_summary,                                             False, {}),
        ("Last Flap",     _flap_cell,                                                False, {}),
        ("Rx dBm",        _optics_cell,                                              False, {"justify": "right"}),
        ("Neighbor",      _neighbor_cell,                                            True,  {}),
    ]

    rendered: dict[str, list[Text]] = {}
    for header, renderer, _always, _kw in specs:
        rendered[header] = [renderer(s) for s in rows]

    def _is_empty(cells: list[Text]) -> bool:
        return all(c.plain.strip() in ("", "-") for c in cells)

    table = Table(title="Interface Report", caption=_counter_age_caption(rows))
    active: list[str] = []
    for header, _renderer, always, kwargs in specs:
        if not always and _is_empty(rendered[header]):
            continue
        active.append(header)
        table.add_column(header, **kwargs)

    for idx in range(len(rows)):
        table.add_row(*(rendered[h][idx] for h in active))
    return table


def _detail_summary_table(stats: InterfaceStats) -> Table:
    """Structured digest of everything parsed for one interface.

    The raw block below it is authoritative but long; this surfaces the fields
    that answer the common questions without scanning 40 lines of output.
    """
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column("Field", style="bold")
    t.add_column("Value")

    def row(label: str, value, style: str | None = None) -> None:
        if value in (None, "", "-"):
            return
        t.add_row(label, Text(str(value), style=style) if style else str(value))

    row("Status", stats.err_disabled_reason and f"err-disabled ({stats.err_disabled_reason})"
        or (stats.admin_status if stats.is_admin_down else stats.oper_status))
    row("Description", stats.description)
    row("Mode", stats.port_mode)
    row("IPv4", stats.ipv4_address)
    row("MAC", stats.mac_address)
    row("Speed/Duplex", ", ".join(x for x in (stats.speed, stats.duplex) if x))
    row("MTU", stats.mtu)
    row("Bandwidth", stats.bandwidth_kbit and f"{stats.bandwidth_kbit} Kbit")
    row("Auto-Neg", stats.autoneg)
    row("FEC mode", stats.fec_mode)

    if stats.port_channel:
        flag = stats.pc_member_state or "?"
        row("Port-channel", f"{stats.port_channel} member, state ({flag})",
            None if flag == "P" else "bold yellow")
    if stats.trunk:
        row("Native VLAN", stats.trunk.native_vlan)
        row("Allowed VLANs", stats.trunk.allowed_vlans)

    row("Load (rx/tx)", (stats.rxload_pct is not None or stats.txload_pct is not None)
        and f"{stats.rxload_pct}% / {stats.txload_pct}%"
        + ("" if stats.is_physical else "  (vs configured BW — not a physical saturation signal)"))
    row("Rate (in/out)", (stats.input_rate_bps is not None)
        and f"{stats.input_rate_bps} bps / {stats.output_rate_bps} bps")
    row("Bytes RX", _format_bytes(stats.input_bytes))
    row("Bytes TX", _format_bytes(stats.output_bytes))
    row("Counters cleared", stats.counters_cleared)
    row("Last flap", stats.last_flapped,
        "red" if _flap_is_recent(stats.last_flapped) else None)
    row("Interface resets", stats.interface_resets)

    if stats.input_errors or stats.output_errors:
        row("Errors", _counter_summary(stats.input_errors, stats.output_errors, "red").plain, "red")
    if stats.input_drops or stats.output_drops:
        row("Drops", _counter_summary(stats.input_drops, stats.output_drops, "yellow").plain, "yellow")

    o = stats.optics
    if o is not None:
        if not o.present:
            row("Transceiver", "not present")
        else:
            row("Transceiver", " ".join(x for x in (o.type, o.serial) if x) or "present")
            for label, val, unit, flag in (
                ("Rx power", o.rx_power_dbm, "dBm", o.rx_power_flag),
                ("Tx power", o.tx_power_dbm, "dBm", o.tx_power_flag),
                ("Temperature", o.temperature_c, "C", None),
                ("Voltage", o.voltage_v, "V", None),
                ("Bias current", o.current_ma, "mA", None),
            ):
                if val is None:
                    continue
                text = f"{val} {unit}"
                style = None
                if flag in ("++", "--"):
                    text, style = f"{text} {flag} (ALARM)", "bold red"
                elif flag in ("+", "-"):
                    text, style = f"{text} {flag} (warning)", "yellow"
                row(label, text, style)

    if stats.neighbor:
        n = stats.neighbor
        row("Neighbor", f"{n.device_id}" + (f" ({n.remote_port})" if n.remote_port else "")
            + f"  [{n.source}]" + (f"  {n.platform}" if n.platform else ""))
    return t


def render_interface_detail(stats: InterfaceStats, raw_cdp: str, raw_lldp: str, console: Console) -> None:
    console.rule(f"[bold]{stats.name}[/bold]")
    console.print(_detail_summary_table(stats))
    console.rule("Raw 'show interface' block")
    print(stats.raw_block)
    cdp_block = _find_neighbor_block(raw_cdp, stats.name, is_cdp=True)
    lldp_block = _find_neighbor_block(raw_lldp, stats.name, is_cdp=False)
    if cdp_block:
        console.rule("CDP neighbor detail")
        print(cdp_block)
    if lldp_block:
        console.rule("LLDP neighbor detail")
        print(lldp_block)
    if not cdp_block and not lldp_block:
        console.print("[dim]No CDP/LLDP neighbor found for this interface.[/dim]")


def dump_raw(raw: dict[str, str], out_dir: Path, hostname: str) -> None:
    """Mirrors collectors/nxos.py::_save_raw — one timestamped file per
    command, best-effort (a write failure is logged, not fatal)."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create raw-output directory %s: %s", out_dir, exc)
        return
    for label, text in raw.items():
        path = out_dir / f"{hostname}__{label}__{ts}.txt"
        try:
            path.write_text(text, encoding="utf-8")
            logger.debug("Saved raw output: %s", path)
        except OSError as exc:
            logger.warning("Could not save raw output for %s: %s", label, exc)


# ─────────────────────────── main ────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Read-only per-interface health report for a Cisco Nexus switch "
                     "(utilization, error counters, CDP/LLDP neighbor).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("device", nargs="?", help=f"Device hostname, matched in {NEXUS_CSV_PATH}")
    ap.add_argument("--ip", help="Connect directly to this IP, skipping the device-list lookup")
    ap.add_argument("--hostname", help="Display label to use when --ip is given without a matching CSV row")
    ap.add_argument("--csv", type=Path, default=NEXUS_CSV_PATH,
                     help=f"Device list CSV (default: {NEXUS_CSV_PATH})")
    ap.add_argument("--username", default=os.getenv("DOMAIN_USERNAME", ""),
                     help="SSH username (default: DOMAIN_USERNAME from .env)")
    ap.add_argument("--password", default=os.getenv("DOMAIN_PASSWORD", ""),
                     help="SSH password (default: DOMAIN_PASSWORD from .env)")
    ap.add_argument("--timeout", type=int, default=SSH_TIMEOUT_DEFAULT,
                     help=f"SSH read timeout in seconds (default: {SSH_TIMEOUT_DEFAULT}; a chassis with "
                          f"many interfaces may need more, e.g. --timeout 120)")
    ap.add_argument("--sort", choices=("util", "errors", "drops", "name", "bytes", "flaps", "optics"),
                     default="util",
                     help="Sort order (default: util — busiest by load%% first). 'bytes' = cumulative "
                          "RX+TX; 'flaps' = most interface resets; 'optics' = weakest Rx power first; "
                          "'drops' = most discards")
    ap.add_argument("--errors-only", action="store_true", help="Only show interfaces with nonzero error counters")
    ap.add_argument("--up-only", action="store_true",
                     help="Only operationally-up interfaces. NOTE: this now means what it says — it "
                          "previously only hid administratively-down ports and still showed ports that "
                          "were down with a cable fault")
    ap.add_argument("--down-only", action="store_true",
                     help="Only interfaces that are down WITHOUT being administratively shut — i.e. "
                          "ports that should be up but aren't. The triage view")
    ap.add_argument("--interface", help="Show full raw detail for exactly this interface, skip the table")
    ap.add_argument("--raw", type=Path, help="Dump raw show-command output to timestamped files in this directory")
    ap.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return ap


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.verbose:
        logging.getLogger("netmiko").setLevel(logging.WARNING)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    if not args.device and not args.ip:
        ap.error("either DEVICE or --ip is required")
    if not args.username or not args.password:
        logger.error("No SSH credentials — set DOMAIN_USERNAME/DOMAIN_PASSWORD in .env or pass --username/--password")
        return 1

    if args.ip:
        ip = args.ip
        hostname = args.hostname or args.ip
    else:
        rows = load_nexus_csv(args.csv)
        try:
            hostname, ip = resolve_device(args.device, rows)
        except ValueError as e:
            logger.error(str(e))
            return 1

    commands = [
        ("show_interface", "show interface"),
        ("transceiver", "show interface transceiver details"),
        ("err_disabled", "show interface status err-disabled"),
        ("port_channel", "show port-channel summary"),
        ("trunk", "show interface trunk"),
        ("cdp", "show cdp neighbors detail"),
        ("lldp", "show lldp neighbors detail"),
    ]

    logger.info("%s (%s): connecting via SSH...", hostname, ip)
    try:
        raw = ssh_run_commands(ip, args.username, args.password, commands, args.timeout)
    except Exception as e:
        logger.error("%s: SSH failed — %s: %s", hostname, type(e).__name__, str(e)[:200])
        return 1

    iface_text = raw.get("show_interface", "")
    if not iface_text.strip():
        logger.error("%s: empty output for 'show interface'", hostname)
        return 1

    interfaces = parse_show_interface(iface_text)
    if not interfaces:
        logger.error("%s: no interfaces parsed from 'show interface' output", hostname)
        return 1
    logger.info("%s: parsed %d interface(s)", hostname, len(interfaces))

    # ── supplementary data, all best-effort ────────────────────────────────
    # Each of these enriches the report; none of them is worth failing over,
    # and each is absent for legitimate reasons on some devices (copper-only
    # switch, no LACP, no trunks).
    def _attach(label: str, parser, apply_fn, what: str) -> None:
        text = raw.get(label, "")
        if not text.strip() or is_feature_disabled_output(text):
            logger.info("%s: no usable %s output", hostname, what)
            return
        try:
            parsed = parser(text)
        except Exception as e:
            logger.warning("%s: failed to parse %s: %s", hostname, what, e)
            return
        hits = 0
        for name, stats in interfaces.items():
            key = normalize_iface_name(name)
            if key in parsed:
                apply_fn(stats, parsed[key])
                hits += 1
        logger.debug("%s: %s matched %d interface(s)", hostname, what, hits)

    def _set_optics(stats: InterfaceStats, value: TransceiverInfo) -> None:
        stats.optics = value

    def _set_errdis(stats: InterfaceStats, value: str) -> None:
        stats.err_disabled_reason = value

    def _set_pc(stats: InterfaceStats, value: tuple[str, str]) -> None:
        stats.port_channel, stats.pc_member_state = value

    def _set_trunk(stats: InterfaceStats, value: TrunkInfo) -> None:
        stats.trunk = value

    _attach("transceiver", parse_transceivers, _set_optics, "transceiver DOM")
    _attach("err_disabled", parse_err_disabled, _set_errdis, "err-disabled status")
    _attach("port_channel", parse_port_channel_summary, _set_pc, "port-channel summary")
    _attach("trunk", parse_trunk, _set_trunk, "trunk config")

    cdp_text = raw.get("cdp", "")
    cdp_neighbors: dict[str, NeighborInfo] = {}
    if cdp_text.strip() and not is_feature_disabled_output(cdp_text):
        try:
            cdp_neighbors = parse_cdp_neighbors(cdp_text)
        except Exception as e:
            logger.warning("%s: failed to parse CDP neighbors: %s", hostname, e)
    else:
        logger.info("%s: no usable CDP output", hostname)

    lldp_text = raw.get("lldp", "")
    lldp_neighbors: dict[str, NeighborInfo] = {}
    if lldp_text.strip() and not is_feature_disabled_output(lldp_text):
        try:
            lldp_neighbors = parse_lldp_neighbors(lldp_text)
        except Exception as e:
            logger.warning("%s: failed to parse LLDP neighbors: %s", hostname, e)
    else:
        logger.info("%s: LLDP not enabled or no neighbors — continuing with CDP only", hostname)

    merge_neighbors(interfaces, cdp_neighbors, lldp_neighbors)

    if args.raw:
        dump_raw(raw, args.raw, hostname)

    console = Console()

    if args.interface:
        target = normalize_iface_name(args.interface)
        stats = interfaces.get(target) or interfaces.get(args.interface)
        if not stats:
            logger.error("%s: no interface named '%s' found", hostname, args.interface)
            return 1
        render_interface_detail(stats, cdp_text, lldp_text, console)
        return 0

    table = build_table(list(interfaces.values()), args.sort, args.errors_only,
                        args.up_only, args.down_only)
    console.print(f"[bold]{hostname}[/bold] ({ip})")
    console.print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
