#!/usr/bin/env python3
"""scripts/nexus_interface_report.py — per-interface health report for one Cisco Nexus switch.

Given a device name (looked up in data/device_lists/nexus.csv) or a bare IP
(--ip), this SSHes to the switch (Netmiko) and runs exactly three read-only
commands:

    1. show interface
       The workhorse — admin/line-protocol state, description, speed/duplex,
       MTU/BW, NX-OS's own txload/rxload (a 0-255 load scale, used directly
       as the busy/utilization signal rather than computed from raw bps),
       30s in/out rates, cumulative RX/TX byte counters (since the device's
       last "clear counters", not a rate), and the RX/TX error-counter
       blocks (CRC, runts, giants, input/output errors, collisions, ...).

    2. show cdp neighbors detail
       Primary "what's plugged into this port" source.

    3. show lldp neighbors detail
       Fallback neighbor source for ports CDP didn't cover (e.g. a neighbor
       with CDP disabled). If LLDP itself isn't enabled on this switch, the
       command errors out — that's detected and treated as "no LLDP data",
       not a failure; the report still runs on CDP alone.

Nothing else is ever sent — no send_config_set, no write verbs of any kind.

Output is a single Rich table, sorted busiest-first by default: Interface,
Status, Description, Speed/Duplex, In%/Out% utilization (color-coded),
Bytes (cumulative RX+TX since last clear), Errors (a compact red summary of
nonzero counters), and Neighbor (device + remote port, CDP unless marked
[lldp]).

Auth: defaults to the shared AD service account (DOMAIN_USERNAME/
DOMAIN_PASSWORD in .env — same as every other script here); override with
--username/--password for a specific run.

Usage:
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --errors-only
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --up-only --sort errors
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --sort bytes
    .venv/bin/python -m scripts.nexus_interface_report N9K-LEAF-01 --interface Ethernet1/1
    .venv/bin/python -m scripts.nexus_interface_report --ip 10.1.1.5 --hostname spare-switch
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
}


def normalize_iface_name(name: str) -> str:
    m = re.match(r"^([A-Za-z-]+)(\d.*)$", name.strip())
    if not m:
        return name.strip()
    prefix, rest = m.groups()
    long_form = _IFACE_ABBREV_MAP.get(prefix.lower())
    return f"{long_form}{rest}" if long_form else name.strip()


# ─────────────────────────── data model ─────────────────────────────────────

@dataclass
class NeighborInfo:
    device_id: str
    remote_port: str | None
    platform: str | None  # CDP only
    source: str  # "cdp" | "lldp"


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
    input_errors: dict[str, int] = field(default_factory=dict)
    output_errors: dict[str, int] = field(default_factory=dict)
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
        return sum(self.input_errors.values()) + sum(self.output_errors.values())

    @property
    def is_admin_down(self) -> bool:
        return "administratively down" in (self.admin_status or "").lower()


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

# Cumulative RX/TX byte counters, from inside the RX/TX blocks, e.g.:
#   "123463701 input packets  987654321098 bytes"
#   "123463692 output packets  876543210987 bytes"
# Same pattern collectors/nxos.py uses — keep these two in sync.
_INPUT_BYTES_RE  = re.compile(r"^\d+\s+input\s+packets\s+(\d+)\s+bytes", re.IGNORECASE)
_OUTPUT_BYTES_RE = re.compile(r"^\d+\s+output\s+packets\s+(\d+)\s+bytes", re.IGNORECASE)

# Matches "<count>  <label>" pairs on a counter line, e.g.
# "0 runts  0 giants  0 CRC/FCS  0 no buffer" -> [("0","runts"), ("0","giants"), ...]
_COUNTER_PAIR_RE = re.compile(r"(\d+)\s+([A-Za-z][A-Za-z/ \-]*?)(?=\s{2,}\d|\s*$)")

# Only counters that look like errors/drops are kept — the same RX/TX blocks
# also carry plain traffic counters (unicast/multicast packets, bytes, pause
# frames) that must NOT be folded into error_total, or every interface would
# read as "erroring" all the time and the report's whole point is defeated.
_ERROR_KEYWORDS = (
    "error", "crc", "runt", "giant", "drop", "discard", "collision",
    "overrun", "underrun", "babble", "carrier", "watchdog", "no buffer",
)


def _is_error_label(label: str) -> bool:
    return any(kw in label for kw in _ERROR_KEYWORDS)


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
            target = current.input_errors if section == "rx" else current.output_errors
            for count_str, label in _COUNTER_PAIR_RE.findall(stripped):
                label_norm = label.strip().lower()
                if not _is_error_label(label_norm):
                    continue
                key = re.sub(r"[^a-z0-9]+", "_", label_norm).strip("_")
                target[key] = target.get(key, 0) + int(count_str)

    flush()
    return interfaces


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
                      commands: list[tuple[str, str]], timeout: int) -> dict[str, str]:
    """SSH to one device and run each (label, command) with send_command
    only. Never issues send_config_set — this function has no write path."""
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
            out[label] = conn.send_command(cmd, read_timeout=timeout) or ""
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


def _error_summary(stats: InterfaceStats) -> Text:
    if stats.error_total == 0:
        return Text("-", style="dim")
    parts = [f"{k}:{v}" for k, v in sorted(stats.input_errors.items(), key=lambda kv: -kv[1]) if v]
    parts += [f"out-{k}:{v}" for k, v in sorted(stats.output_errors.items(), key=lambda kv: -kv[1]) if v]
    shown = " ".join(parts[:3])
    if len(parts) > 3:
        shown += " …"
    return Text(shown, style="red")


def _format_bytes(n: int | None) -> str:
    """Human-readable byte count. Mirrors templates_module.py::_format_bytes
    (the web app's equivalent) — keep these two in sync."""
    if n is None:
        return "N/A"
    val = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if val < 1024 or unit == "PB":
            return f"{val:.0f} {unit}" if unit == "B" else f"{val:.2f} {unit}"
        val /= 1024
    return f"{val:.2f} PB"


def _bytes_cell(stats: InterfaceStats) -> Text:
    total = stats.total_bytes
    if total is None:
        return Text("N/A", style="dim")
    return Text(_format_bytes(total))


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


def build_table(interfaces: list[InterfaceStats], sort: str, errors_only: bool, up_only: bool) -> Table:
    rows = list(interfaces)
    if up_only:
        rows = [s for s in rows if not s.is_admin_down]
    if errors_only:
        rows = [s for s in rows if s.error_total > 0]

    if sort == "errors":
        rows.sort(key=lambda s: s.error_total, reverse=True)
    elif sort == "name":
        rows.sort(key=lambda s: s.name)
    elif sort == "bytes":
        rows.sort(key=lambda s: s.total_bytes if s.total_bytes is not None else -1, reverse=True)
    else:  # "util" (default)
        rows.sort(key=lambda s: s.util_pct if s.util_pct is not None else -1, reverse=True)

    table = Table(title="Interface Report")
    table.add_column("Interface")
    table.add_column("Status")
    table.add_column("Description", overflow="fold", max_width=28)
    table.add_column("Speed/Duplex")
    table.add_column("In%", justify="right")
    table.add_column("Out%", justify="right")
    table.add_column("Bytes (RX+TX)", justify="right")
    table.add_column("Errors")
    table.add_column("Neighbor")

    for s in rows:
        speed_duplex = ", ".join(x for x in (s.speed, s.duplex) if x) or "-"
        table.add_row(
            s.name,
            _status_cell(s),
            s.description or "-",
            speed_duplex,
            _fmt_pct(s.rxload_pct),
            _fmt_pct(s.txload_pct),
            _bytes_cell(s),
            _error_summary(s),
            _neighbor_cell(s),
        )
    return table


def render_interface_detail(stats: InterfaceStats, raw_cdp: str, raw_lldp: str, console: Console) -> None:
    console.rule(f"[bold]{stats.name}[/bold]")
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
    ap.add_argument("--sort", choices=("util", "errors", "name", "bytes"), default="util",
                     help="Sort order for the table (default: util — busiest by load% first; "
                          "'bytes' sorts by cumulative RX+TX traffic instead)")
    ap.add_argument("--errors-only", action="store_true", help="Only show interfaces with nonzero error counters")
    ap.add_argument("--up-only", action="store_true", help="Hide administratively-down interfaces")
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

    table = build_table(list(interfaces.values()), args.sort, args.errors_only, args.up_only)
    console.print(f"[bold]{hostname}[/bold] ({ip})")
    console.print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
