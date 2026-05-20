"""
ipsec_live.py — Parse runtime IPsec/IKE state from IOS `show` output and
Palo Alto op-command XML into a single normalized shape.

Pure functions. No I/O. The router (`routers/tunnels.py`) is responsible for
SSH/HTTP I/O and feeds the raw text or XML into the parsers here.

Normalized output (one dict per endpoint live-fetch):

    {
      "status":     "up"|"down"|"degraded"|"unknown",
      "peer_ip":    str,
      "uptime":     str,         # human, e.g. "1d18h"
      "encap_pkts": int|None,
      "decap_pkts": int|None,
      "encap_bytes": int|None,
      "decap_bytes": int|None,
      "phase1":   { protocol, state, encryption, integrity, dh_group,
                    lifetime_remaining_sec },
      "phase2":   { encryption, integrity, pfs, spi_in, spi_out,
                    lifetime_remaining_sec, lifetime_remaining_kb },
      "interface_state":  {line, protocol, last_input, last_output,
                           input_errors, output_errors, input_rate_bps,
                           output_rate_bps} | None,
      "dmvpn_peers":      [{nbma, tunnel, state, uptime, attrb}] | None,
      "errors":           [str],
      "raw":              {command_label: output_text, ...},
    }
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any


_IOS_ERROR_PATTERNS = (
    "% Invalid input",
    "% Incomplete command",
    "% Ambiguous command",
    "% Unrecognized",
    "% No such",
)


def _is_ios_error(text: str) -> bool:
    """True if the output is an IOS command-not-supported response."""
    if not text:
        return False
    head = text[:400]
    return any(p in head for p in _IOS_ERROR_PATTERNS)


_EMPTY_STATE: dict = {
    "status":          "unknown",
    "peer_ip":         "",      # the peer when one session — empty when many
    "uptime":          "",      # earliest uptime when many sessions
    "encap_pkts":      None,    # aggregate across sessions
    "decap_pkts":      None,
    "encap_drops":     None,
    "decap_drops":     None,
    "encap_bytes":     None,    # only populated for Palo; IOS show crypto session
    "decap_bytes":     None,    #   has no byte counters
    "session_count":   0,       # number of per-peer sessions parsed
    "sessions":        [],      # per-peer session list (for table rendering)
    "peers_up":        0,
    "peers_down":      0,
    "phase1":          {},      # negotiated phase1 (from ikev2/isakmp sa)
    "phase2":          {},      # phase2 lifetime remaining (min across sessions)
    "interface_state": None,
    "dmvpn_peers":     None,
    "palo":            None,    # PAN-specific extras (TS, monitor, NAT-T, mode, …)
    "errors":          [],
    "raw":             {},
}


def empty_state() -> dict:
    """Fresh deep copy of the normalized state skeleton."""
    return {
        **_EMPTY_STATE,
        "phase1":   {},
        "phase2":   {},
        "errors":   [],
        "raw":      {},
        "sessions": [],
    }


# ── IOS: show crypto session detail ─────────────────────────────────────────

_RE_CS_INTERFACE   = re.compile(r"^Interface:\s*(\S+)")
_RE_CS_PROFILE     = re.compile(r"^\s*Profile:\s*(\S+)")
_RE_CS_UPTIME      = re.compile(r"^\s*Uptime:\s*(\S+)")
_RE_CS_STATUS      = re.compile(r"^\s*Session status:\s*(\S+)")
_RE_CS_PEER        = re.compile(r"^\s*Peer:\s*(\S+)")
_RE_CS_IKEV2       = re.compile(
    r"^\s*IKEv2 SA:\s*local\s+(\S+)\s+remote\s+(\S+)\s+(\S+)"
)
_RE_CS_IKEV1       = re.compile(
    r"^\s*IKEv1?\s+SA:\s*local\s+(\S+)\s+remote\s+(\S+)\s+(\S+)"
)
_RE_CS_IKE_LIFE    = re.compile(r"lifetime[:\s]+(\d+):(\d+):(\d+)", re.I)
# Inbound:  #pkts dec'ed N drop M life (KB/Sec) KB/SEC
_RE_CS_INBOUND     = re.compile(
    r"^\s*Inbound:\s+#pkts\s+dec(?:'|’)ed\s+(\d+)\s+drop\s+(\d+)\s+life\s*\(KB/Sec\)\s*(\d+)/(\d+)",
    re.I,
)
_RE_CS_OUTBOUND    = re.compile(
    r"^\s*Outbound:\s+#pkts\s+enc(?:'|’)ed\s+(\d+)\s+drop\s+(\d+)\s+life\s*\(KB/Sec\)\s*(\d+)/(\d+)",
    re.I,
)


def parse_show_crypto_session(text: str, target_iface: str = "") -> dict:
    """Parse `show crypto session detail` into per-peer session records.

    A DMVPN hub will have one session block per spoke (all under the same
    ``Interface: TunnelN``), so the output is structurally a list, not a
    single value. ``target_iface`` filters to one logical tunnel.

    Returns:
        {"sessions": [ {peer, uptime, status, profile, phase1, encap_pkts,
                        encap_drops, decap_pkts, decap_drops,
                        p2_lifetime_sec, p2_lifetime_kb}, ... ],
         "errors": [...]}
    """
    if not text:
        return {"sessions": [], "errors": ["empty output from show crypto session"]}
    if _is_ios_error(text):
        return {"sessions": [], "errors":
                ["device rejected 'show crypto session detail' — IOS version may not support it"]}

    blocks = _split_session_blocks(text)
    if target_iface:
        target_norm = target_iface.lower()
        blocks = [b for b in blocks if _block_interface(b).lower() == target_norm]
        if not blocks:
            return {"sessions": [],
                    "errors": [f"interface {target_iface} not found in crypto session output"]}

    sessions: list[dict] = []
    for b in blocks:
        s = _parse_session_block(b)
        if s:
            sessions.append(s)
    return {"sessions": sessions, "errors": []}


def _split_session_blocks(text: str) -> list[list[str]]:
    """Split into per-session blocks — each starts at an ``Interface:`` line."""
    lines = text.splitlines()
    blocks: list[list[str]] = []
    current: list[str] = []
    for ln in lines:
        if _RE_CS_INTERFACE.match(ln):
            if current:
                blocks.append(current)
            current = [ln]
        elif current:
            current.append(ln)
    if current:
        blocks.append(current)
    return blocks


def _block_interface(block: list[str]) -> str:
    if not block:
        return ""
    m = _RE_CS_INTERFACE.match(block[0])
    return m.group(1) if m else ""


def _parse_session_block(block: list[str]) -> dict:
    """Parse a single session block into one peer record. Captures uptime,
    status, peer IP, profile, phase1 + lifetime, packet/drop counters, and
    phase2 lifetime remaining."""
    s: dict = {
        "peer":            "",
        "uptime":          "",
        "status":          "unknown",
        "profile":         "",
        "phase1":          {},
        "encap_pkts":      None,
        "encap_drops":     None,
        "decap_pkts":      None,
        "decap_drops":     None,
        "p2_lifetime_sec": None,
        "p2_lifetime_kb":  None,
    }

    encap_pkts = decap_pkts = 0
    encap_drops = decap_drops = 0
    has_inbound = has_outbound = False
    life_sec_min: int | None = None
    life_kb_min:  int | None = None

    for line in block:
        if (m := _RE_CS_PROFILE.match(line)):
            s["profile"] = m.group(1)
        elif (m := _RE_CS_UPTIME.match(line)):
            s["uptime"] = m.group(1).strip(",")
        elif (m := _RE_CS_STATUS.match(line)):
            st = m.group(1).upper()
            s["status"] = ("up" if st.startswith("UP")
                           else "down" if st.startswith("DOWN")
                           else "degraded")
        elif (m := _RE_CS_PEER.match(line)):
            s["peer"] = m.group(1)
        elif (m := _RE_CS_IKEV2.match(line)):
            s["phase1"] = {"protocol": "ikev2", "state": m.group(3).lower()}
        elif (m := _RE_CS_IKEV1.match(line)):
            s["phase1"] = {"protocol": "ikev1", "state": m.group(3).lower()}
        elif "lifetime:" in line and s["phase1"]:
            # IKE SA detail line includes lifetime:HH:MM:SS — capture remaining.
            if (lm := _RE_CS_IKE_LIFE.search(line)):
                hours, minutes, seconds = int(lm.group(1)), int(lm.group(2)), int(lm.group(3))
                s["phase1"]["lifetime_remaining_sec"] = hours * 3600 + minutes * 60 + seconds
        elif (m := _RE_CS_INBOUND.match(line)):
            has_inbound  = True
            decap_pkts  += int(m.group(1))
            decap_drops += int(m.group(2))
            kb  = int(m.group(3)); sec = int(m.group(4))
            life_kb_min  = kb  if life_kb_min  is None else min(life_kb_min,  kb)
            life_sec_min = sec if life_sec_min is None else min(life_sec_min, sec)
        elif (m := _RE_CS_OUTBOUND.match(line)):
            has_outbound = True
            encap_pkts  += int(m.group(1))
            encap_drops += int(m.group(2))
            kb  = int(m.group(3)); sec = int(m.group(4))
            life_kb_min  = kb  if life_kb_min  is None else min(life_kb_min,  kb)
            life_sec_min = sec if life_sec_min is None else min(life_sec_min, sec)

    s["encap_pkts"]      = encap_pkts  if has_outbound else None
    s["encap_drops"]     = encap_drops if has_outbound else None
    s["decap_pkts"]      = decap_pkts  if has_inbound  else None
    s["decap_drops"]     = decap_drops if has_inbound  else None
    s["p2_lifetime_sec"] = life_sec_min
    s["p2_lifetime_kb"]  = life_kb_min

    # Skip empty blocks (would happen on malformed input).
    if not s["peer"] and not s["status"] != "unknown":
        return {}
    return s


# ── IOS: show dmvpn detail ──────────────────────────────────────────────────

_RE_DMVPN_TYPE = re.compile(r"Type:\s*(\w+)", re.I)
# Match the per-peer rows of show dmvpn — the layout is whitespace-aligned and
# can wrap. Capture the meaningful fields by position from the right since the
# ent count + NBMA + tunnel IPs are the stable left columns.
_RE_DMVPN_PEER = re.compile(
    r"^\s*(\d+)\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s*$"
)


def parse_show_dmvpn(text: str, target_iface: str = "") -> dict:
    """Parse `show dmvpn detail`. Returns peer list and tunnel role."""
    out: dict = {"dmvpn_peers": [], "errors": []}
    if not text:
        out["errors"].append("empty output from show dmvpn")
        return out
    if _is_ios_error(text):
        # Non-DMVPN devices reject this — that's expected, not an error to surface.
        return {"dmvpn_peers": []}

    capture = not bool(target_iface)
    role = ""
    for line in text.splitlines():
        if target_iface and line.lower().startswith("interface ") and target_iface.lower() in line.lower():
            capture = True
            continue
        if target_iface and capture and line.startswith("Interface ") and target_iface.lower() not in line.lower():
            break
        if not capture:
            continue
        if (m := _RE_DMVPN_TYPE.search(line)):
            role = m.group(1).lower()
        elif (m := _RE_DMVPN_PEER.match(line)):
            out["dmvpn_peers"].append({
                "nbma":    m.group(2),
                "tunnel":  m.group(3),
                "state":   m.group(4),
                "uptime":  m.group(5),
                "attrb":   m.group(6),
            })

    if role:
        out["dmvpn_role"] = role
    return out


# ── IOS: show interface Tunnel N ────────────────────────────────────────────

_RE_IF_LINE_PROTO = re.compile(
    r"^\S+\s+is\s+(\S+)(?:,| up,)?\s+line protocol is\s+(\S+)", re.I
)
_RE_IF_LAST       = re.compile(r"^\s*Last input\s+(\S+),\s+output\s+(\S+)")
_RE_IF_IN_RATE    = re.compile(r"input rate\s+(\d+)\s+bits/sec")
_RE_IF_OUT_RATE   = re.compile(r"output rate\s+(\d+)\s+bits/sec")
_RE_IF_IN_ERR     = re.compile(r"^\s*(\d+)\s+input errors")
_RE_IF_OUT_ERR    = re.compile(r"^\s*(\d+)\s+output errors")


def parse_show_interface(text: str) -> dict:
    """Parse `show interface TunnelN` for line/proto state, last input/output,
    rates, and error counters."""
    if not text or _is_ios_error(text):
        return {}
    iface: dict[str, Any] = {}
    for line in text.splitlines():
        if not iface and (m := _RE_IF_LINE_PROTO.match(line)):
            iface["line"]     = m.group(1).rstrip(",")
            iface["protocol"] = m.group(2)
        elif (m := _RE_IF_LAST.match(line)):
            iface["last_input"]  = m.group(1)
            iface["last_output"] = m.group(2).rstrip(",")
        elif (m := _RE_IF_IN_RATE.search(line)):
            iface["input_rate_bps"] = int(m.group(1))
        elif (m := _RE_IF_OUT_RATE.search(line)):
            iface["output_rate_bps"] = int(m.group(1))
        elif (m := _RE_IF_IN_ERR.match(line)):
            iface["input_errors"] = int(m.group(1))
        elif (m := _RE_IF_OUT_ERR.match(line)):
            iface["output_errors"] = int(m.group(1))
    return iface


# ── IOS: show crypto ikev2 sa detailed / show crypto isakmp sa detail ───────

_RE_IKEV2_HDR = re.compile(
    r"^\s*\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s*$"
)
_RE_IKEV2_ENC = re.compile(
    r"Encr:\s*(\S+?),.*?Hash:\s*(\S+?),.*?DH Grp:\s*(\d+)", re.I
)
_RE_IKEV2_LIFE = re.compile(r"Life/Active Time:\s*(\d+)/(\d+)\s*sec", re.I)


def parse_show_ikev2_sa(text: str, peer_ip: str = "") -> dict:
    """Parse `show crypto ikev2 sa detail` for the SA matching peer_ip
    (or the first SA if peer_ip is empty)."""
    if not text or _is_ios_error(text):
        return {}
    phase1: dict = {"protocol": "ikev2"}
    found_match = not bool(peer_ip)
    for line in text.splitlines():
        m = _RE_IKEV2_HDR.match(line)
        if m and "/" in m.group(1) and "/" in m.group(2):
            remote = m.group(2).split("/")[0]
            if peer_ip and remote != peer_ip:
                found_match = False
                continue
            found_match = True
            phase1["state"] = m.group(3).lower()
            continue
        if not found_match:
            continue
        if (m := _RE_IKEV2_ENC.search(line)):
            phase1["encryption"] = m.group(1)
            phase1["integrity"] = m.group(2)
            phase1["dh_group"]  = m.group(3)
        elif (m := _RE_IKEV2_LIFE.search(line)):
            total = int(m.group(1)); active = int(m.group(2))
            phase1["lifetime_remaining_sec"] = max(total - active, 0)
    return phase1 if len(phase1) > 1 else {}


_RE_ISAKMP_LINE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(\S+)\s+(\S+)\s+(\d+)"
)


def parse_show_isakmp_sa(text: str, peer_ip: str = "") -> dict:
    """Parse `show crypto isakmp sa` for the SA matching peer_ip."""
    if not text or _is_ios_error(text):
        return {}
    for line in text.splitlines():
        m = _RE_ISAKMP_LINE.match(line)
        if not m:
            continue
        remote = m.group(2)
        if peer_ip and remote != peer_ip:
            continue
        return {
            "protocol": "ikev1",
            "state":    m.group(3).lower(),
        }
    return {}


# ── PAN: op-cmd XML parsers ─────────────────────────────────────────────────

def _int_or_none(s: str | None) -> int | None:
    try:
        return int(s) if s not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        return None


def _parse_ts_side(elem: ET.Element | None) -> dict:
    """Parse one side of a PAN `<ts>` (traffic selector) block."""
    if elem is None:
        return {}
    return {
        "start_ip":   (elem.findtext("sip") or "").strip(),
        "end_ip":     (elem.findtext("eip") or "").strip(),
        "protocol":   _int_or_none(elem.findtext("proto")),
        "start_port": _int_or_none(elem.findtext("sport")),
        "end_port":   _int_or_none(elem.findtext("eport")),
    }


def list_pan_flow_names(elem: ET.Element | None) -> list[str]:
    """Return every IPSec flow entry name present in a `show vpn flow` response.

    Used to surface the real names on a device when our inventory name doesn't
    match (so the user can see whether it's a config-vs-runtime naming gap)."""
    if elem is None:
        return []
    out: list[str] = []
    for entry in elem.findall(".//IPSec/entry") or elem.findall(".//entry"):
        n = (entry.findtext("name") or "").strip()
        if n:
            out.append(n)
    return out


def _flow_entry_matches(name: str, tunnel_name: str) -> tuple[bool, str]:
    """Match a flow entry name against a tunnel name.

    PAN-OS names per-proxy-id SAs as ``{tunnel_name}:{label}`` (one entry per
    traffic selector). A "match" is therefore the bare name *or* anything with
    a `:` suffix off the same base. Returns (matched, proxy_id_label).
    """
    if not name:
        return False, ""
    tl = tunnel_name.lower()
    nl = name.lower()
    if nl == tl:
        return True, ""
    base, sep, label = name.partition(":")
    if sep and base.lower() == tl:
        return True, label
    return False, ""


def _parse_pan_vpn_entry(entry: ET.Element) -> dict:
    """Parse one `<IPSec><entry>` block from `show vpn flow` into a dict."""
    state_raw = (entry.findtext("state") or "").lower()

    mon = entry.find("monitor")
    monitor = {}
    if mon is not None:
        monitor = {
            "enabled":   (mon.findtext("on") or "").lower() == "true",
            "up":        (mon.findtext("status") or "").lower() == "true",
            "ka_status": _int_or_none(mon.findtext("ka-status")),
            "interval":  _int_or_none(mon.findtext("interval")),
            "threshold": _int_or_none(mon.findtext("threshold")),
            "pkt_sent":  _int_or_none(mon.findtext("pkt-sent")),
            "pkt_recv":  _int_or_none(mon.findtext("pkt-recv")),
        }

    ts_elem = entry.find("ts")
    ts = {}
    if ts_elem is not None:
        ts = {
            "local":  _parse_ts_side(ts_elem.find("local")),
            "remote": _parse_ts_side(ts_elem.find("remote")),
        }

    auth_err  = _int_or_none(entry.findtext("auth-err"))   or 0
    dec_err   = _int_or_none(entry.findtext("dec-err"))    or 0
    replay    = _int_or_none(entry.findtext("pkt-replay")) or 0
    inner_wn  = _int_or_none(entry.findtext("inner-warn")) or 0

    return {
        "name":        (entry.findtext("name") or "").strip(),
        "gwid":        entry.findtext("gwid") or "",
        "peer_ip":     (entry.findtext("peerip") or "").strip(),
        "local_ip":    (entry.findtext("localip") or "").strip(),
        "state":       state_raw,
        "inner_if":    entry.findtext("inner-if") or "",
        "outer_if":    entry.findtext("outer-if") or "",
        # Word-boundary check: "inactive" must NOT count as up (substring trap).
        "status":      "up" if state_raw in ("active", "up", "established") or "estab" in state_raw else "down",
        "enc":         (entry.findtext("enc")  or "").strip(),
        "auth":        (entry.findtext("auth") or "").strip(),
        "proto":       (entry.findtext("proto") or "").strip(),
        "ipsec_mode":  (entry.findtext("ipsec-mode") or "").strip(),
        "local_spi":   (entry.findtext("local-spi")  or "").strip(),
        "remote_spi":  (entry.findtext("remote-spi") or "").strip(),
        "soft_lifetime_sec":      _int_or_none(entry.findtext("softtime")),
        "hard_lifetime_sec":      _int_or_none(entry.findtext("hardtime")),
        "lifetime_remaining_sec": _int_or_none(entry.findtext("remaintime")),
        "last_rekey_sec":         _int_or_none(entry.findtext("last-rekey")),
        "mtu":         _int_or_none(entry.findtext("mtu")),
        "natt":        (entry.findtext("natt") or "").lower() == "true",
        "initiator":   (entry.findtext("initiator") or "").lower() == "true",
        "keytype":     (entry.findtext("keytype") or "").strip(),
        "anti_replay": (entry.findtext("anti-replay") or "").lower() == "true",
        "anti_replay_window": _int_or_none(entry.findtext("anti-replay-window")),
        "encap_pkts":  _int_or_none(entry.findtext("pkt-encap")),
        "decap_pkts":  _int_or_none(entry.findtext("pkt-decap")),
        "encap_bytes": _int_or_none(entry.findtext("byte-encap")),
        "decap_bytes": _int_or_none(entry.findtext("byte-decap")),
        "seq_send":    _int_or_none(entry.findtext("seq-send")),
        "seq_recv":    _int_or_none(entry.findtext("seq-recv")),
        # errors / drops — PAN splits these across four counters
        "errors": {
            "auth":       auth_err,
            "decrypt":    dec_err,
            "replay":     replay,
            "inner_warn": inner_wn,
        },
        # decap drops = sum of the three real drop counters (inner-warn is
        # an anomaly, not a drop)
        "decap_drops": auth_err + dec_err + replay,
        "monitor":     monitor,
        "ts":          ts,
    }


def parse_pan_vpn_flow(elem: ET.Element | None, tunnel_name: str) -> dict:
    """Match every flow entry belonging to this tunnel.

    Returns ``{"found": bool, "primary": dict, "matches": [entry_dict, ...]}``.
    The primary entry is the bare-name match if present, else the first
    proxy-id-suffixed match (e.g. ``CAL_TO_ITE:a``). When the tunnel has
    proxy-IDs, ``matches`` contains one dict per proxy-id; each carries the
    parsed ``proxy_id`` label.

    Matching is case-insensitive on both the bare name and the prefix.
    """
    if elem is None:
        return {"found": False, "matches": [], "primary": {}}
    matches: list[dict] = []
    primary: dict = {}
    for entry in elem.findall(".//IPSec/entry") or elem.findall(".//entry"):
        name = (entry.findtext("name") or "").strip()
        ok, proxy_id = _flow_entry_matches(name, tunnel_name)
        if not ok:
            continue
        parsed = _parse_pan_vpn_entry(entry)
        parsed["proxy_id"] = proxy_id
        matches.append(parsed)
        if not proxy_id and not primary:
            primary = parsed
    if not primary and matches:
        primary = matches[0]
    return {"found": bool(matches), "matches": matches, "primary": primary}


def _spi_hex(raw: str | None) -> str:
    """PAN reports SPIs as decimal integers in `show vpn ipsec-sa`. Convert
    to hex (8-char, zero-padded, uppercase) so they line up with what
    `show vpn flow` shows."""
    v = _int_or_none(raw)
    return f"{v:08X}" if v is not None else (raw or "")


def _parse_pan_sa_entry(entry: ET.Element) -> dict:
    """Parse one `<entries><entry>` from `show vpn ipsec-sa` into a dict."""
    return {
        "name":        (entry.findtext("name") or "").strip(),
        "gateway":     (entry.findtext("gateway") or "").strip(),
        "tid":         _int_or_none(entry.findtext("tid")),
        "proto":       (entry.findtext("proto") or "").strip(),
        "encryption":  (entry.findtext("enc")  or "").strip(),
        "integrity":   (entry.findtext("hash") or "").strip(),
        "pfs":         (entry.findtext("dh")   or "").strip(),
        "spi_in":      _spi_hex(entry.findtext("i_spi")),
        "spi_out":     _spi_hex(entry.findtext("o_spi")),
        "lifetime_sec":           _int_or_none(entry.findtext("life")),
        "lifetime_remaining_sec": _int_or_none(entry.findtext("remain")),
        "lifetime_kb":            (entry.findtext("kb") or "").strip(),
    }


def parse_pan_ipsec_sa(elem: ET.Element | None, tunnel_name: str) -> dict:
    """Parse `show vpn ipsec-sa` — one `<entry>` per SA tunnel.

    Returns ``{"matches": [sa_dict, ...], "primary": sa_dict, "phase2": {...}}``.
    For proxy-ID tunnels, every per-proxy SA is returned in `matches`. The
    `phase2` field reflects the *primary* (bare-name or first) entry, kept
    for backward compatibility with the single-SA call path.
    """
    if elem is None:
        return {"matches": [], "primary": {}, "phase2": {}}
    matches: list[dict] = []
    primary: dict = {}
    for entry in elem.findall(".//entries/entry") or elem.findall(".//entry"):
        name = (entry.findtext("name") or "").strip()
        ok, _ = _flow_entry_matches(name, tunnel_name)
        if not ok:
            continue
        parsed = _parse_pan_sa_entry(entry)
        matches.append(parsed)
        if name.lower() == tunnel_name.lower() and not primary:
            primary = parsed
    if not primary and matches:
        primary = matches[0]
    return {
        "matches": matches,
        "primary": primary,
        # Backward-compatible: a phase2 dict derived from the primary entry.
        "phase2": {
            "encryption":             primary.get("encryption", ""),
            "integrity":              primary.get("integrity", ""),
            "pfs":                    primary.get("pfs", ""),
            "spi_in":                 primary.get("spi_in", ""),
            "spi_out":                primary.get("spi_out", ""),
            "lifetime_sec":           primary.get("lifetime_sec"),
            "lifetime_remaining_sec": primary.get("lifetime_remaining_sec"),
            "lifetime_kb":            primary.get("lifetime_kb", ""),
        } if primary else {},
    }


_IKE_MODE_TS = re.compile(r"^([A-Z][a-z]{2})\.(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
_IKE_MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}


def _ike_lifetime_remaining(created: str, expires: str) -> int | None:
    """PAN reports IKE SA timestamps as ``MMM.D HH:MM:SS`` with no year. The
    difference between created and expires is the configured lifetime; that is
    a reliable, year-independent value to surface as `lifetime_sec`. We don't
    try to compute "remaining" without a year — the caller can show created/
    expires directly for the absolute view."""
    def _to_seconds(s: str) -> int | None:
        m = _IKE_MODE_TS.match((s or "").strip())
        if not m:
            return None
        mon, day, hh, mm, ss = m.groups()
        mon_i = _IKE_MONTHS.get(mon)
        if not mon_i:
            return None
        # Treat the date as occurring in a notional non-leap year. We only use
        # this for diffs, so the absolute origin doesn't matter — as long as
        # both endpoints use the same origin.
        from datetime import datetime
        try:
            return int(datetime(2001, mon_i, int(day),
                                int(hh), int(mm), int(ss)).timestamp())
        except ValueError:
            return None
    a = _to_seconds(created)
    b = _to_seconds(expires)
    if a is None or b is None:
        return None
    # Handle year wrap (expires in next year): if negative, add a year.
    diff = b - a
    if diff < 0:
        diff += 365 * 86400
    return diff if diff > 0 else None


def _parse_ike_algo(algo: str) -> dict:
    """PAN packs the IKE proposal into a single slash-delimited string like
    ``PSK/DH20/AES256-CBC/SHA256``. Split it into named fields. Tokens that
    don't match a known prefix are kept as-is so we don't silently drop info."""
    out = {"auth": "", "dh_group": "", "encryption": "", "integrity": ""}
    for tok in (algo or "").split("/"):
        t = tok.strip()
        if not t:
            continue
        tl = t.lower()
        if tl in ("psk", "rsa", "ecdsa", "cert"):
            out["auth"] = t
        elif tl.startswith("dh") or tl.startswith("group"):
            out["dh_group"] = t
        elif tl.startswith(("aes", "3des", "des", "null")):
            out["encryption"] = t
        elif tl.startswith(("sha", "md5")):
            out["integrity"] = t
    return out


def parse_pan_ike_sa(elem: ET.Element | None, peer_ip: str = "", gwid: str = "") -> dict:
    """Parse `show vpn ike-sa`.

    Real PAN-OS shape: top-level `<entry>` per IKE SA with fields `gwid`,
    `name`, `role` (Init/Resp), `mode` (IKEv1/IKEv2), `algo` (slash-delimited
    proposal), `created`, `expires`. No state/peer-ip/encryption/hash/dh
    fields exist directly — `algo` must be parsed.
    """
    if elem is None:
        return {}
    for entry in elem.findall(".//phase1-sa/entry") or elem.findall(".//entry"):
        e_gwid = (entry.findtext("gwid") or "").strip()
        if gwid and e_gwid and e_gwid != gwid:
            continue
        mode = (entry.findtext("mode") or "").strip()
        algo = (entry.findtext("algo") or "").strip()
        role = (entry.findtext("role") or "").strip()
        created = (entry.findtext("created") or "").strip()
        expires = (entry.findtext("expires") or "").strip()
        crypto = _parse_ike_algo(algo)
        return {
            "protocol":   "ikev2" if mode.lower() == "ikev2" else ("ikev1" if mode else ""),
            "state":      "established" if expires else "",
            "encryption": crypto["encryption"],
            "integrity":  crypto["integrity"],
            "dh_group":   crypto["dh_group"],
            "auth":       crypto["auth"],
            "role":       role,
            "gateway":    (entry.findtext("name") or "").strip(),
            "created":    created,
            "expires":    expires,
            "lifetime_sec": _ike_lifetime_remaining(created, expires),
            "raw_algo":   algo,
        }
    return {}


# ── Aggregation helpers ─────────────────────────────────────────────────────

def merge_ios_state(
    crypto_session: dict,
    ikev2_sa:       dict,
    isakmp_sa:      dict,
    interface_state: dict,
    dmvpn_state:    dict,
    raw:            dict,
) -> dict:
    """Combine the IOS per-command parses into one normalized state dict.

    `crypto_session` is now ``{"sessions": [...], "errors": [...]}`` —
    one entry per peer (a DMVPN hub yields many). We aggregate packet/drop
    counters across sessions, expose the per-peer list for the table view,
    and pick min phase2 lifetime as the conservative "rekey soonest" value.
    """
    state = empty_state()
    state["raw"]    = raw
    state["errors"] = list(crypto_session.get("errors", []))
    sessions: list[dict] = crypto_session.get("sessions", [])
    state["sessions"]      = sessions
    state["session_count"] = len(sessions)

    if sessions:
        encap_pkts  = sum((s.get("encap_pkts")  or 0) for s in sessions)
        decap_pkts  = sum((s.get("decap_pkts")  or 0) for s in sessions)
        encap_drops = sum((s.get("encap_drops") or 0) for s in sessions)
        decap_drops = sum((s.get("decap_drops") or 0) for s in sessions)
        state["encap_pkts"]  = encap_pkts  if any(s.get("encap_pkts")  is not None for s in sessions) else None
        state["decap_pkts"]  = decap_pkts  if any(s.get("decap_pkts")  is not None for s in sessions) else None
        state["encap_drops"] = encap_drops if any(s.get("encap_drops") is not None for s in sessions) else None
        state["decap_drops"] = decap_drops if any(s.get("decap_drops") is not None for s in sessions) else None

        peers_up   = sum(1 for s in sessions if s.get("status") == "up")
        peers_down = sum(1 for s in sessions if s.get("status") == "down")
        state["peers_up"]   = peers_up
        state["peers_down"] = peers_down

        if peers_up == len(sessions):
            state["status"] = "up"
        elif peers_up == 0:
            state["status"] = "down"
        else:
            state["status"] = "degraded"

        # Single-session case: surface the peer in the header.
        if len(sessions) == 1:
            state["peer_ip"] = sessions[0].get("peer", "")
            state["uptime"]  = sessions[0].get("uptime", "")
        else:
            # Many sessions: don't show a single peer IP; uptime = newest peer's
            # uptime (most recent connection = most informative for "is this
            # tunnel actively forming new sessions").
            state["uptime"] = sessions[0].get("uptime", "") if sessions else ""

        # Phase 2 lifetime remaining: min across sessions = the SA that's
        # closest to rekey.
        kb_vals  = [s["p2_lifetime_kb"]  for s in sessions if s.get("p2_lifetime_kb")  is not None]
        sec_vals = [s["p2_lifetime_sec"] for s in sessions if s.get("p2_lifetime_sec") is not None]
        if kb_vals:  state["phase2"]["lifetime_remaining_kb"]  = min(kb_vals)
        if sec_vals: state["phase2"]["lifetime_remaining_sec"] = min(sec_vals)

    # Phase 1 negotiated crypto comes from the dedicated SA show.
    p1 = dict(state.get("phase1") or {})
    p1.update({k: v for k, v in (ikev2_sa or {}).items() if v})
    if not p1.get("encryption"):
        p1.update({k: v for k, v in (isakmp_sa or {}).items() if v})
    # If no negotiated info, inherit phase1.protocol/state from the first session.
    if not p1 and sessions:
        p1 = dict(sessions[0].get("phase1") or {})
    state["phase1"] = p1

    if interface_state:
        state["interface_state"] = interface_state
        if interface_state.get("line") == "down" or interface_state.get("protocol") == "down":
            state["status"] = "down"

    if dmvpn_state.get("dmvpn_peers"):
        state["dmvpn_peers"] = dmvpn_state["dmvpn_peers"]
        if state["status"] == "unknown":
            up = sum(1 for p in dmvpn_state["dmvpn_peers"] if p["state"].upper() == "UP")
            total = len(dmvpn_state["dmvpn_peers"])
            if up == total and total > 0:
                state["status"] = "up"
            elif up > 0:
                state["status"] = "degraded"
            else:
                state["status"] = "down"

    return state


def _ts_label(side: dict) -> str:
    """Short human label for one side of a traffic selector — "any" when wide
    open, otherwise the network range."""
    if not side:
        return ""
    s, e = side.get("start_ip", ""), side.get("end_ip", "")
    if s == "0.0.0.0" and e == "255.255.255.255":
        return "any"
    if s == e:
        return s
    return f"{s}–{e}"


def _ts_pair_label(ts: dict) -> str:
    """`local → remote` label for a traffic-selector pair."""
    if not ts:
        return ""
    l = _ts_label(ts.get("local") or {})
    r = _ts_label(ts.get("remote") or {})
    if not l and not r:
        return ""
    return f"{l or '?'} → {r or '?'}"


def _palo_session_from_entry(entry: dict, ike_protocol: str) -> dict:
    """Build a per-proxy session row in the shape the per-peer table expects."""
    drops = entry.get("decap_drops")
    return {
        # `peer` column doubles as the proxy-id identifier in the table.
        "peer":            entry.get("proxy_id") or entry.get("name", ""),
        "status":          entry.get("status") or "unknown",
        # PAN flow doesn't expose uptime per SA; the TS pair is more useful
        # for identifying which proxy-id this row corresponds to.
        "uptime":          _ts_pair_label(entry.get("ts") or {}),
        "phase1":          {"protocol": ike_protocol} if ike_protocol else {},
        "encap_pkts":      entry.get("encap_pkts"),
        "decap_pkts":      entry.get("decap_pkts"),
        # PAN has no encap-side drop counter; only decap drops are meaningful.
        "encap_drops":     None,
        "decap_drops":     drops,
        "p2_lifetime_sec": entry.get("lifetime_remaining_sec"),
        "p2_lifetime_kb":  None,
    }


def merge_palo_state(
    flow:  dict,
    sa:    dict,
    ike:   dict,
    raw:   dict,
) -> dict:
    """Combine the PAN per-command parses into one normalized state dict.

    `flow` is the source-of-truth for counters, SPIs, the active phase-2
    cipher, lifetime timers, traffic selectors, and drop counters. `sa` adds
    the configured phase-2 lifetime and the gateway label. `ike` carries the
    phase-1 proposal (parsed out of the slash-delimited `algo`).

    When the tunnel has multiple proxy-IDs, `flow["matches"]` contains one
    entry per proxy and we aggregate top-level counters across them while
    surfacing the per-proxy breakdown via the `sessions` list (same shape as
    DMVPN per-peer rendering).
    """
    state = empty_state()
    state["raw"] = raw
    if not flow.get("found"):
        state["status"] = "down"
        state["errors"].append("tunnel not present in vpn flow on this firewall")
        return state

    matches: list[dict] = flow.get("matches") or []
    # `primary` is the bare-name match or first proxy-id match — used for
    # tunnel-level fields that are the same across all proxies (cipher,
    # gateway, peer IP, interfaces).
    primary: dict = flow.get("primary") or (matches[0] if matches else {})
    multi = sum(1 for m in matches if m.get("proxy_id")) > 0 and len(matches) > 1

    state["peer_ip"] = primary.get("peer_ip", "")

    if multi:
        # Aggregate counters across all per-proxy SAs.
        any_encap_pkts = any(m.get("encap_pkts")  is not None for m in matches)
        any_decap_pkts = any(m.get("decap_pkts")  is not None for m in matches)
        any_encap_byte = any(m.get("encap_bytes") is not None for m in matches)
        any_decap_byte = any(m.get("decap_bytes") is not None for m in matches)
        state["encap_pkts"]  = sum(m.get("encap_pkts")  or 0 for m in matches) if any_encap_pkts else None
        state["decap_pkts"]  = sum(m.get("decap_pkts")  or 0 for m in matches) if any_decap_pkts else None
        state["encap_bytes"] = sum(m.get("encap_bytes") or 0 for m in matches) if any_encap_byte else None
        state["decap_bytes"] = sum(m.get("decap_bytes") or 0 for m in matches) if any_decap_byte else None
        state["decap_drops"] = sum(m.get("decap_drops") or 0 for m in matches)
        # Status: all-up → up, all-down → down, mixed → degraded.
        up   = sum(1 for m in matches if m.get("status") == "up")
        down = sum(1 for m in matches if m.get("status") == "down")
        state["peers_up"]      = up
        state["peers_down"]    = down
        state["session_count"] = len(matches)
        if up == len(matches):
            state["status"] = "up"
        elif up == 0:
            state["status"] = "down"
        else:
            state["status"] = "degraded"
        ike_proto = (ike or {}).get("protocol", "")
        state["sessions"] = [_palo_session_from_entry(m, ike_proto) for m in matches]
    else:
        # Single-flow case: surface counters straight from the primary entry.
        state["status"]      = primary.get("status", "unknown")
        state["encap_pkts"]  = primary.get("encap_pkts")
        state["decap_pkts"]  = primary.get("decap_pkts")
        state["encap_bytes"] = primary.get("encap_bytes")
        state["decap_bytes"] = primary.get("decap_bytes")
        state["decap_drops"] = primary.get("decap_drops")

    # Phase 2: start from primary entry (active cipher, SPIs, remaining
    # lifetime), then overlay anything from ipsec-sa (configured lifetime,
    # pfs, kb). For multi-proxy tunnels these are the proxy-id `:a` values —
    # cipher/PFS are shared across proxies; lifetime is per-proxy but `:a`
    # is a reasonable representative and the per-proxy table shows the rest.
    phase2 = {
        "encryption":             primary.get("enc"),
        "integrity":              primary.get("auth"),
        "protocol":               primary.get("proto"),
        "mode":                   primary.get("ipsec_mode"),
        # PAN's `local-spi` is the SPI we receive on (inbound); `remote-spi` is
        # what we put on packets we send (outbound). Cross-checked against
        # `show vpn ipsec-sa` where i_spi == local-spi (hex).
        "spi_in":                 primary.get("local_spi"),
        "spi_out":                primary.get("remote_spi"),
        "lifetime_remaining_sec": primary.get("lifetime_remaining_sec"),
        "soft_lifetime_sec":      primary.get("soft_lifetime_sec"),
        "hard_lifetime_sec":      primary.get("hard_lifetime_sec"),
        "last_rekey_sec":         primary.get("last_rekey_sec"),
    }
    if sa and sa.get("phase2"):
        sa_p2 = sa["phase2"]
        phase2["pfs"]         = sa_p2.get("pfs")
        phase2["lifetime_kb"] = sa_p2.get("lifetime_kb")
        if not phase2["lifetime_remaining_sec"]:
            phase2["lifetime_remaining_sec"] = sa_p2.get("lifetime_remaining_sec")
        if not phase2.get("lifetime_sec"):
            phase2["lifetime_sec"] = sa_p2.get("lifetime_sec")
    if multi:
        # For multi-proxy, surface the min remaining across *active* proxies as
        # "next rekey across all". Inactive proxies report remain=0 and would
        # otherwise drown out the real near-rekey signal.
        rem = [m.get("lifetime_remaining_sec") for m in matches
               if m.get("status") == "up" and m.get("lifetime_remaining_sec")]
        if rem:
            phase2["lifetime_remaining_sec"] = min(rem)
    state["phase2"] = {k: v for k, v in phase2.items() if v not in (None, "")}

    if ike:
        state["phase1"] = {k: v for k, v in ike.items() if v not in (None, "")}

    # Bundle PAN-specific extras that don't fit the cross-platform shape.
    state["palo"] = {
        "gateway":      (sa or {}).get("primary", {}).get("gateway")
                        or (ike or {}).get("gateway", ""),
        "local_ip":     primary.get("local_ip"),
        "inner_if":     primary.get("inner_if"),
        "outer_if":     primary.get("outer_if"),
        "mtu":          primary.get("mtu"),
        "natt":         primary.get("natt"),
        "initiator":    primary.get("initiator"),
        "keytype":      primary.get("keytype"),
        "anti_replay":  primary.get("anti_replay"),
        "anti_replay_window": primary.get("anti_replay_window"),
        "seq_send":     primary.get("seq_send"),
        "seq_recv":     primary.get("seq_recv"),
        "errors":       primary.get("errors") or {},
        "monitor":      primary.get("monitor") or {},
        "ts":           primary.get("ts") or {},
        "proxy_id_count": len([m for m in matches if m.get("proxy_id")]),
        "ike_role":     (ike or {}).get("role", ""),
        "ike_created":  (ike or {}).get("created", ""),
        "ike_expires":  (ike or {}).get("expires", ""),
        "ike_raw_algo": (ike or {}).get("raw_algo", ""),
    }
    return state
