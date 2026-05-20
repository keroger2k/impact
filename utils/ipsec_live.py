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
    "status":      "unknown",
    "peer_ip":     "",
    "uptime":      "",
    "encap_pkts":  None,
    "decap_pkts":  None,
    "encap_bytes": None,
    "decap_bytes": None,
    "phase1":      {},
    "phase2":      {},
    "interface_state": None,
    "dmvpn_peers": None,
    "errors":      [],
    "raw":         {},
}


def empty_state() -> dict:
    """Fresh deep copy of the normalized state skeleton."""
    return {
        **_EMPTY_STATE,
        "phase1":  {},
        "phase2":  {},
        "errors":  [],
        "raw":     {},
    }


# ── IOS: show crypto session detail ─────────────────────────────────────────

_RE_CS_INTERFACE   = re.compile(r"^Interface:\s*(\S+)")
_RE_CS_UPTIME      = re.compile(r"^\s*Uptime:\s*(\S+)")
_RE_CS_STATUS      = re.compile(r"^\s*Session status:\s*(\S+)")
_RE_CS_PEER        = re.compile(r"^\s*Peer:\s*(\S+)")
_RE_CS_IKEV2       = re.compile(
    r"^\s*IKEv2 SA:\s*local\s+(\S+)\s+remote\s+(\S+)\s+(\S+)"
)
_RE_CS_IKEV1       = re.compile(
    r"^\s*IKE SA:\s*local\s+(\S+)\s+remote\s+(\S+)\s+(\S+)"
)
_RE_CS_LIFETIME    = re.compile(r"lifetime[:\s]+(\d+):(\d+):(\d+)", re.I)
_RE_CS_INBOUND     = re.compile(
    r"^\s*Inbound:\s+#pkts\s+dec(?:'|’)ed\s+(\d+).*?life\s*\(KB/Sec\)\s*(\d+)/(\d+)",
    re.I,
)
_RE_CS_OUTBOUND    = re.compile(
    r"^\s*Outbound:\s+#pkts\s+enc(?:'|’)ed\s+(\d+).*?life\s*\(KB/Sec\)\s*(\d+)/(\d+)",
    re.I,
)


def parse_show_crypto_session(text: str, target_iface: str = "") -> dict:
    """Parse `show crypto session detail`.

    If ``target_iface`` is provided, only that interface's block is used.
    Otherwise the first session block found is used. Aggregates encap/decap
    across all IPSEC FLOW entries within the chosen block.
    """
    if not text:
        return {"errors": ["empty output from show crypto session"]}
    if _is_ios_error(text):
        return {"errors": ["device rejected 'show crypto session detail' — IOS version may not support it"]}

    out: dict = {
        "peer_ip":     "",
        "uptime":      "",
        "encap_pkts":  None,
        "decap_pkts":  None,
        "encap_bytes": None,
        "decap_bytes": None,
        "status":      "unknown",
        "phase1":      {},
        "phase2":      {},
        "errors":      [],
    }

    blocks = _split_session_blocks(text)
    block: list[str] | None = None
    if target_iface:
        target_norm = target_iface.lower()
        for b in blocks:
            for line in b[:3]:
                m = _RE_CS_INTERFACE.match(line)
                if m and m.group(1).lower() == target_norm:
                    block = b
                    break
            if block:
                break
        if not block:
            out["errors"].append(f"interface {target_iface} not found in crypto session output")
            return out
    elif blocks:
        block = blocks[0]
    else:
        out["errors"].append("no crypto session blocks found")
        return out

    encap_pkts = decap_pkts = 0
    encap_kb = decap_kb = 0
    lifetime_sec_min: int | None = None
    for line in block:
        if (m := _RE_CS_UPTIME.match(line)):
            out["uptime"] = m.group(1).strip(",")
        elif (m := _RE_CS_STATUS.match(line)):
            s = m.group(1).upper()
            out["status"] = "up" if s.startswith("UP") else "down" if s.startswith("DOWN") else "degraded"
        elif (m := _RE_CS_PEER.match(line)):
            out["peer_ip"] = m.group(1)
        elif (m := _RE_CS_IKEV2.match(line)):
            out["phase1"] = {"protocol": "ikev2", "state": m.group(3).lower()}
        elif (m := _RE_CS_IKEV1.match(line)):
            out["phase1"] = {"protocol": "ikev1", "state": m.group(3).lower()}
        elif (m := _RE_CS_INBOUND.match(line)):
            decap_pkts += int(m.group(1))
            decap_kb   += int(m.group(2))
            sec = int(m.group(3))
            lifetime_sec_min = sec if lifetime_sec_min is None else min(lifetime_sec_min, sec)
        elif (m := _RE_CS_OUTBOUND.match(line)):
            encap_pkts += int(m.group(1))
            encap_kb   += int(m.group(2))
            sec = int(m.group(3))
            lifetime_sec_min = sec if lifetime_sec_min is None else min(lifetime_sec_min, sec)

    out["encap_pkts"]  = encap_pkts or None
    out["decap_pkts"]  = decap_pkts or None
    out["encap_bytes"] = encap_kb * 1024 if encap_kb else None
    out["decap_bytes"] = decap_kb * 1024 if decap_kb else None
    if lifetime_sec_min is not None:
        out["phase2"]["lifetime_remaining_sec"] = lifetime_sec_min

    return out


def _split_session_blocks(text: str) -> list[list[str]]:
    """Split the output into per-interface session blocks. A block starts at
    each ``Interface:`` line."""
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

def parse_pan_vpn_flow(elem: ET.Element | None, tunnel_name: str) -> dict:
    """Parse the result of `<show><vpn><flow></vpn></show>`.

    Find the IPSec entry whose <name> matches tunnel_name. Returns peer_ip,
    state, gwid, monitor status, and interfaces.
    """
    if elem is None:
        return {}
    for entry in elem.findall(".//IPSec/entry") or elem.findall(".//entry"):
        name = (entry.findtext("name") or "").strip()
        if name != tunnel_name:
            continue
        state_raw = (entry.findtext("state") or "").lower()
        return {
            "found":       True,
            "gwid":        entry.findtext("gwid") or "",
            "peer_ip":     entry.findtext("peerip") or "",
            "local_ip":    entry.findtext("localip") or "",
            "state":       state_raw,
            "monitor":     (entry.findtext("mon") or "").lower(),
            "inner_if":    entry.findtext("inner-if") or "",
            "outer_if":    entry.findtext("outer-if") or "",
            "status":      "up" if "active" in state_raw or "estab" in state_raw else "down",
        }
    return {"found": False}


def parse_pan_ipsec_sa(elem: ET.Element | None, tunnel_name: str) -> dict:
    """Parse `<show><vpn><ipsec-sa></vpn></show>` for the entry whose <name>
    starts with the tunnel name (PAN names SAs as 'TUN:TUN-i0' etc.)."""
    if elem is None:
        return {}
    encap_bytes = decap_bytes = 0
    encap_pkts  = decap_pkts  = 0
    enc = integ = pfs = ""
    spi_in = spi_out = ""
    life_rem: int | None = None
    matched = False

    for entry in elem.findall(".//entries/entry") or elem.findall(".//entry"):
        name = (entry.findtext("name") or "").strip()
        if not (name == tunnel_name or name.startswith(tunnel_name + ":") or tunnel_name + ":" in name):
            continue
        matched = True
        direction = (entry.findtext("dir") or "").lower()
        b = entry.findtext("bytes")
        p = entry.findtext("packets")
        try:
            b_int = int(b) if b else 0
            p_int = int(p) if p else 0
        except ValueError:
            b_int = p_int = 0
        if direction in ("inbound", "in"):
            decap_bytes += b_int; decap_pkts += p_int
            spi_in = entry.findtext("spi") or spi_in
        elif direction in ("outbound", "out"):
            encap_bytes += b_int; encap_pkts += p_int
            spi_out = entry.findtext("spi") or spi_out
        else:
            # 'both' or absent: split the counters between in/out
            decap_bytes += b_int; encap_bytes += b_int
            decap_pkts  += p_int; encap_pkts  += p_int
        enc   = enc   or entry.findtext("enc")  or ""
        integ = integ or entry.findtext("hash") or ""
        pfs   = pfs   or entry.findtext("dh")   or ""
        life  = entry.findtext("life")
        if life:
            try:
                life_rem = int(life) if life_rem is None else min(life_rem, int(life))
            except ValueError:
                pass

    if not matched:
        return {}
    return {
        "encap_bytes": encap_bytes or None,
        "decap_bytes": decap_bytes or None,
        "encap_pkts":  encap_pkts  or None,
        "decap_pkts":  decap_pkts  or None,
        "phase2": {
            "encryption": enc,
            "integrity":  integ,
            "pfs":        pfs,
            "spi_in":     spi_in,
            "spi_out":    spi_out,
            "lifetime_remaining_sec": life_rem,
        },
    }


def parse_pan_ike_sa(elem: ET.Element | None, peer_ip: str = "", gwid: str = "") -> dict:
    """Parse `<show><vpn><ike-sa></vpn></show>` for the phase1 SA matching peer
    or gateway id."""
    if elem is None:
        return {}
    for entry in elem.findall(".//phase1-sa/entry") or elem.findall(".//entry"):
        e_peer = entry.findtext("peer-ip") or ""
        e_gwid = entry.findtext("gwid")    or ""
        if peer_ip and e_peer and e_peer != peer_ip:
            continue
        if gwid and e_gwid and e_gwid != gwid:
            continue
        state_raw = (entry.findtext("state") or "").lower()
        lt = entry.findtext("lifetime")
        try:
            lt_int = int(lt) if lt else None
        except ValueError:
            lt_int = None
        return {
            "protocol":   "ikev2" if entry.findtext("ike-version") == "2" else "ikev1",
            "state":      state_raw,
            "encryption": entry.findtext("enc")  or "",
            "integrity":  entry.findtext("hash") or "",
            "dh_group":   entry.findtext("dh")   or "",
            "lifetime_remaining_sec": lt_int,
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
    """Combine the IOS per-command parses into one normalized state dict."""
    state = empty_state()
    state["raw"] = raw
    state.update({k: v for k, v in crypto_session.items() if k != "errors"})
    state["errors"] = list(crypto_session.get("errors", []))

    p1 = dict(state.get("phase1") or {})
    p1.update({k: v for k, v in (ikev2_sa or {}).items() if v})
    if not p1.get("encryption"):
        p1.update({k: v for k, v in (isakmp_sa or {}).items() if v})
    state["phase1"] = p1

    if interface_state:
        state["interface_state"] = interface_state
        # Tunnel line/proto down trumps "session UP" — surface as degraded.
        if interface_state.get("line") == "down" or interface_state.get("protocol") == "down":
            state["status"] = "down"

    if dmvpn_state.get("dmvpn_peers"):
        state["dmvpn_peers"] = dmvpn_state["dmvpn_peers"]
        if state["status"] == "unknown":
            # No crypto session block but DMVPN reports peers → derive status.
            up = sum(1 for p in dmvpn_state["dmvpn_peers"] if p["state"].upper() == "UP")
            total = len(dmvpn_state["dmvpn_peers"])
            if up == total and total > 0:
                state["status"] = "up"
            elif up > 0:
                state["status"] = "degraded"
            else:
                state["status"] = "down"

    return state


def merge_palo_state(
    flow:  dict,
    sa:    dict,
    ike:   dict,
    raw:   dict,
) -> dict:
    """Combine the PAN per-command parses into one normalized state dict."""
    state = empty_state()
    state["raw"] = raw
    if not flow.get("found"):
        state["status"] = "down"
        state["errors"].append("tunnel not present in vpn flow on this firewall")
        return state
    state["status"]      = flow.get("status", "unknown")
    state["peer_ip"]     = flow.get("peer_ip", "")
    if sa:
        state["encap_pkts"]  = sa.get("encap_pkts")
        state["decap_pkts"]  = sa.get("decap_pkts")
        state["encap_bytes"] = sa.get("encap_bytes")
        state["decap_bytes"] = sa.get("decap_bytes")
        state["phase2"]      = sa.get("phase2", {})
    if ike:
        state["phase1"] = ike
    return state
