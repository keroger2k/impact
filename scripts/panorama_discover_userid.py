#!/usr/bin/env python3
"""scripts/panorama_discover_userid.py — does Palo Alto already know which
user is on which IP?

Read-only reconnaissance for the cross-platform endpoint search
(docs/ROADMAP.md item #1). ISE answers "which switch port" for anyone who
authenticated to the network. It says nothing useful about someone working
from home, and — if the fleet turns out to do 802.1X machine auth on wired
ports — it may not name the person at all.

PAN-OS User-ID is a completely independent answer to the same question, built
from AD security-log monitoring rather than RADIUS, and this app already has
everything needed to ask for it (`clients/panorama.py`, an API key, and
`op_via_sdk` at line 271). Two commands are worth the trip:

  1. `show user ip-user-mapping all` — the User-ID table: IP → DOMAIN\\user,
     with the mapping's source (AD server monitoring, GlobalProtect, XML API,
     captive portal) and its idle timeout. If this is well populated it gives
     a user→IP answer for the whole workforce, and IP is something we can then
     resolve through ISE's Session/EndPointIPAddress, the IPAM tree, or DNAC's
     ip-lookup. It also covers people ISE never sees.

  2. `show global-protect-gateway current-user` — remote users, and this one
     is unusually rich: username, the *computer name*, the assigned tunnel IP,
     and the public IP they came from. That is a direct answer to "are they
     remote, and on what workstation", which is precisely the half of the
     question the on-prem tooling cannot reach.

The open questions this settles, none of which are answerable from the code:

  * IS USER-ID CONFIGURED AT ALL? It is licensed-in but optional, and plenty
    of deployments run without it. An unconfigured firewall returns a
    well-formed empty table — the same shape as "nobody is online" — so the
    agent/server-monitor statistics are probed alongside it to tell the two
    apart. This is the same trap dnac_discover_assurance.py was written for.

  * WHERE DOES THE TABLE LIVE? Mappings are held on each firewall, not on
    Panorama, unless Panorama is configured as a redistribution point. So the
    probe asks Panorama first and then a real firewall, and reports which one
    actually answered.

  * DOES THE USERNAME FORMAT MATCH ISE? User-ID typically stores
    `DOMAIN\\user` while an ISE session may hold a bare name or a UPN. Joining
    the two systems on a string that is formatted differently in each is the
    quiet way this feature returns "no results" for a user who is plainly
    online, so the formats are compared explicitly here.

Every command is a `show`. There is no `set`/`commit`/`delete` anywhere in
this file. Commands are built with `panos.string_to_xml` rather than f-string
XML (per CLAUDE.md's Panorama rule) but sent with raw requests rather than
`op_via_sdk`, because that helper returns None on failure and logs the reason
away — and distinguishing "not configured" from "not permitted" from "no such
command on this version" is the whole point of a probe.

⚠️  OUTPUT CONTAINS REAL USERNAMES, IP ADDRESSES AND COMPUTER NAMES. Pass
    --redact before pasting it anywhere.

Env vars (.env): PANORAMA_HOST, DOMAIN_USERNAME, DOMAIN_PASSWORD.

Usage:
    .venv/bin/python -m scripts.panorama_discover_userid --list-devices
    .venv/bin/python -m scripts.panorama_discover_userid
    .venv/bin/python -m scripts.panorama_discover_userid --target 001234567890
    .venv/bin/python -m scripts.panorama_discover_userid --all-devices --redact
"""
from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from clients import verify_ssl  # noqa: E402
import clients.panorama as pc  # noqa: E402

# Probed in order. The statistics commands are what separate "User-ID is off"
# from "User-ID is on and nobody is logged in".
_COMMANDS = [
    ("ip-user-mapping", "show user ip-user-mapping all",
     "The User-ID table itself: IP → user."),
    ("user-id-agent-stats", "show user user-id-agent statistics",
     "Are User-ID agents connected? Empty table + no agents = not configured."),
    ("server-monitor-stats", "show user server-monitor statistics",
     "Agentless AD server monitoring — the other way mappings get learned."),
    ("gp-current-user", "show global-protect-gateway current-user",
     "Remote users: username, computer name, tunnel IP, public IP."),
]


def _mask_user(v: str) -> str:
    if not v:
        return v
    if "\\" in v:
        dom, _, user = v.partition("\\")
        return f"{dom}\\{user[:2]}***"
    if "@" in v:
        local, _, dom = v.partition("@")
        return f"{local[:2]}***@{dom}"
    return v[:2] + "***" if len(v) > 2 else "***"


def _mask_ip(v: str) -> str:
    if not v:
        return v
    if ":" in v:
        return ":".join(v.split(":")[:2]) + ":xxxx::xxxx"
    parts = v.split(".")
    return f"{parts[0]}.{parts[1]}.x.x" if len(parts) == 4 else v


def _mask_host(v: str) -> str:
    return f"{v[:3]}***" if v and len(v) > 3 else v


class Redactor:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def user(self, v: str) -> str:
        return _mask_user(v) if self.enabled else v

    def ip(self, v: str) -> str:
        return _mask_ip(v) if self.enabled else v

    def host(self, v: str) -> str:
        return _mask_host(v) if self.enabled else v


def _hr(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def run_op(cmd: str, api_key: str, target: str | None = None,
           timeout: int = 30) -> tuple[ET.Element | None, str | None]:
    """One operational command. Returns (result_element, error_text).

    The CLI string is tokenized by panos.string_to_xml so we never interpolate
    into XML by hand, but the request goes out over plain requests so that a
    PAN-OS error message survives to the terminal instead of being logged and
    dropped the way op_via_sdk does it.
    """
    from panos import string_to_xml

    host = os.getenv("PANORAMA_HOST")
    xml_cmd = string_to_xml(cmd)
    if isinstance(xml_cmd, bytes):
        xml_cmd = xml_cmd.decode()

    params = {"type": "op", "cmd": xml_cmd, "key": api_key}
    if target:
        params["target"] = target
    try:
        resp = requests.post(f"https://{host}/api/", data=params,
                             verify=verify_ssl(), timeout=timeout)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

    if not resp.text or not resp.text.strip():
        return None, f"HTTP {resp.status_code} with an empty body"
    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as e:
        return None, f"unparseable response: {e} — {resp.text[:300]}"

    if root.attrib.get("status") == "error":
        msg = " ".join(t.strip() for t in root.itertext() if t and t.strip())
        code = root.attrib.get("code", "?")
        return None, f"PAN-OS error code {code}: {msg[:400]}"
    return root.find("result"), None


def step_devices(api_key: str, red: Redactor) -> list[dict]:
    _hr("MANAGED FIREWALLS  —  show devices all")
    result, err = run_op("show devices all", api_key)
    if err:
        print(f"  FAILED — {err}")
        return []
    devices = []
    for dev in result.findall(".//entry"):
        serial = dev.get("name") or dev.findtext("serial", "")
        hostname = dev.findtext("hostname", "")
        if not serial or not hostname:
            continue
        devices.append({
            "serial": serial,
            "hostname": hostname,
            "model": dev.findtext("model", ""),
            "connected": dev.findtext("connected", ""),
            "device_group": dev.findtext("device-group", "") or "—",
        })
    print(f"  {len(devices)} managed firewall(s).\n")
    for d in devices[:40]:
        state = "connected" if d["connected"] == "yes" else d["connected"] or "?"
        print(f"    {d['serial']:<18} {red.host(d['hostname']):<24} "
              f"{d['model']:<12} {state:<10} dg={d['device_group']}")
    if len(devices) > 40:
        print(f"    ... and {len(devices) - 40} more")
    return devices


def _entries(result: ET.Element) -> list[dict]:
    """Flatten <entry> children into dicts. PAN-OS nests results differently
    per command, so this takes any entry anywhere under the result."""
    out = []
    for e in result.findall(".//entry"):
        row = {child.tag: (child.text or "").strip() for child in e}
        for k, v in e.attrib.items():
            row.setdefault(k, v)
        if row:
            out.append(row)
    return out


def probe_ip_user_mapping(result: ET.Element, red: Redactor, full: bool) -> list[dict]:
    rows = _entries(result)
    count_el = result.find(".//count")
    if count_el is not None and count_el.text:
        print(f"  PAN-OS reports count = {count_el.text.strip()}")
    print(f"  {len(rows)} mapping row(s) parsed.")
    if not rows:
        print("\n  EMPTY. This is the ambiguous case the statistics commands below")
        print("  disambiguate: User-ID not configured, versus configured with no")
        print("  current mappings. Do NOT read an empty table as 'nobody is online'.")
        return rows

    users = {r.get("user", "") for r in rows if r.get("user")}
    sources = Counter(r.get("from", r.get("type", "?")) for r in rows)
    print(f"  {len(users)} distinct user(s) across those mappings.")
    print(f"  mapping sources: {dict(sources)}")
    print(f"\n  keys present on a row: {sorted(rows[0].keys())}\n")
    for r in rows[:8]:
        print(f"    {red.ip(r.get('ip', '—')):<20} {red.user(r.get('user', '—')):<28} "
              f"from={r.get('from', r.get('type', '—')):<12} "
              f"idle={r.get('idle_timeout', r.get('timeout', '—'))}")
    if len(rows) > 8:
        print(f"    ... and {len(rows) - 8} more")

    sample = next((r.get("user") for r in rows if r.get("user")), "")
    print()
    if "\\" in sample:
        print(f"  USERNAME FORMAT: DOMAIN\\user (e.g. {red.user(sample)}).")
        print("  ISE sessions commonly store a bare name or a UPN — the search must")
        print("  normalise before joining, or the two systems will never match.")
    elif "@" in sample:
        print(f"  USERNAME FORMAT: UPN (e.g. {red.user(sample)}). If AD's mail equals")
        print("  the UPN, a typed email matches this table directly.")
    else:
        print(f"  USERNAME FORMAT: bare (e.g. {red.user(sample)}).")

    if full:
        print(f"\n  ALL {len(rows)} ROWS:")
        for r in rows:
            print(f"    {red.ip(r.get('ip', '—')):<20} {red.user(r.get('user', '—'))}")
    return rows


def probe_gp_users(result: ET.Element, red: Redactor, full: bool) -> list[dict]:
    rows = _entries(result)
    print(f"  {len(rows)} current GlobalProtect user(s).")
    if not rows:
        print("\n  EMPTY. Either nobody is connected right now, or GlobalProtect is")
        print("  not run from this firewall. Check on a gateway firewall specifically")
        print("  — a branch firewall will legitimately report nothing here.")
        return rows
    print(f"\n  keys present on a row: {sorted(rows[0].keys())}\n")
    for r in rows[:8]:
        print(f"    user      {red.user(r.get('username', r.get('domain-user', '—')))}")
        print(f"    computer  {red.host(r.get('computer', '—'))}")
        print(f"    tunnel ip {red.ip(r.get('virtual-ip', r.get('assigned-ip', '—')))}")
        print(f"    public ip {red.ip(r.get('public-ip', r.get('client-ip', '—')))}")
        print(f"    client    {r.get('client', '—')}   since {r.get('login-time', '—')}")
        print()
    if len(rows) > 8:
        print(f"    ... and {len(rows) - 8} more")
    if any(r.get("computer") for r in rows):
        print("  → `computer` IS populated. For remote users this answers the")
        print("    workstation question outright, with no CMDB and no AD lookup.")
    else:
        print("  → `computer` is empty on these rows; only the username and IPs are")
        print("    usable for a remote user.")
    if full:
        print(f"\n  ALL {len(rows)} ROWS:")
        for r in rows:
            print(f"    {r}")
    return rows


def probe_target(api_key: str, target: str | None, label: str,
                 red: Redactor, full: bool) -> dict:
    _hr(f"USER-ID PROBE  —  {label}")
    findings = {"label": label, "mappings": 0, "gp_users": 0, "userid_configured": None}

    for key, cmd, why in _COMMANDS:
        print(f"\n  ── {cmd}")
        print(f"     {why}")
        result, err = run_op(cmd, api_key, target=target)
        if err:
            print(f"     FAILED — {err}")
            if "No such node" in str(err) or "Invalid" in str(err):
                print("     → This PAN-OS version does not have that command.")
            elif "not connected" in str(err):
                print("     → Firewall is not currently connected to Panorama.")
            continue

        if key == "ip-user-mapping":
            rows = probe_ip_user_mapping(result, red, full)
            findings["mappings"] = len(rows)
        elif key == "gp-current-user":
            rows = probe_gp_users(result, red, full)
            findings["gp_users"] = len(rows)
        else:
            rows = _entries(result)
            text = " ".join(t.strip() for t in result.itertext() if t and t.strip())
            if rows:
                print(f"     {len(rows)} row(s): {rows[:3]}")
                findings["userid_configured"] = True
            elif text:
                print(f"     {text[:300]}")
                findings["userid_configured"] = findings["userid_configured"] or bool(text)
            else:
                print("     empty — no agents / no monitored servers reported.")
    return findings


def summarise(all_findings: list[dict]) -> None:
    _hr("VERDICT")
    total_maps = sum(f["mappings"] for f in all_findings)
    total_gp = sum(f["gp_users"] for f in all_findings)
    for f in all_findings:
        print(f"  {f['label']:<34} {f['mappings']:>5} mappings   {f['gp_users']:>4} GP users")
    print()
    if total_maps == 0 and total_gp == 0:
        print("  Nothing found anywhere probed. If the statistics commands above also")
        print("  came back empty, User-ID is not in use and this data source is out —")
        print("  the search must rely on ISE alone, and remote users stay invisible.")
        print("  If they showed agents/servers, re-run against a firewall that actually")
        print("  sees user traffic; Panorama itself holds no mappings unless it is")
        print("  configured as a redistribution point.")
        return
    if total_maps:
        print(f"  {total_maps} IP→user mapping(s) available. This is a genuine second")
        print("  identity source, independent of RADIUS, and it covers users ISE never")
        print("  authenticates. Wire it as: user → IP (here) → session/port (ISE")
        print("  Session/EndPointIPAddress) or → subnet/site (the IPAM tree).")
    if total_gp:
        print(f"  {total_gp} GlobalProtect user(s) online — this is the remote-worker")
        print("  answer, and the `computer` field may make the workstation question")
        print("  trivial for anyone off-site.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--list-devices", action="store_true",
                    help="List managed firewall serials and exit")
    ap.add_argument("--target", help="Probe this firewall serial (via Panorama)")
    ap.add_argument("--all-devices", action="store_true",
                    help="Probe every connected managed firewall")
    ap.add_argument("--limit", type=int, default=5,
                    help="Max firewalls to probe with --all-devices (default 5)")
    ap.add_argument("--redact", action="store_true",
                    help="Mask users/IPs/hostnames — use before pasting output anywhere")
    ap.add_argument("--full", action="store_true", help="Print every row, not a sample")
    args = ap.parse_args()

    if not os.getenv("PANORAMA_HOST"):
        print("ERROR: PANORAMA_HOST must be set (see .env.template).")
        return 1

    red = Redactor(args.redact)
    print(f"Panorama User-ID probe — {os.getenv('PANORAMA_HOST')}")
    print("Read-only: every command below is a `show`.")
    if not args.redact:
        print("NOTE: output will contain real usernames/IPs/computer names. Re-run")
        print("      with --redact before pasting it anywhere it will be stored.")

    try:
        api_key = pc.get_api_key()
    except Exception as e:
        print(f"\nERROR: could not get a Panorama API key — {type(e).__name__}: {e}")
        return 1
    if not api_key:
        print("\nERROR: Panorama returned no API key.")
        return 1

    devices = step_devices(api_key, red)
    if args.list_devices:
        return 0

    findings = []
    if args.target:
        match = next((d for d in devices if d["serial"] == args.target), None)
        label = f"{match['hostname']} ({args.target})" if match else args.target
        findings.append(probe_target(api_key, args.target, label, red, args.full))
    elif args.all_devices:
        connected = [d for d in devices if d["connected"] == "yes"][:args.limit]
        if not connected:
            print("\n  No connected firewalls to probe.")
        for d in connected:
            findings.append(probe_target(api_key, d["serial"],
                                         f"{red.host(d['hostname'])} ({d['serial']})",
                                         red, args.full))
    else:
        # Panorama itself first — it only holds mappings if it is configured as
        # a redistribution point, and knowing that is itself a design input.
        findings.append(probe_target(api_key, None, "Panorama (no target)", red, args.full))
        first = next((d for d in devices if d["connected"] == "yes"), None)
        if first:
            print("\n  Panorama holds mappings only as a redistribution point; probing")
            print(f"  one real firewall too ({red.host(first['hostname'])}).")
            findings.append(probe_target(api_key, first["serial"],
                                         f"{red.host(first['hostname'])} ({first['serial']})",
                                         red, args.full))

    summarise(findings)

    _hr("NEXT")
    print("  ise_discover_user_sessions   Session/EndPointIPAddress turns an IP from")
    print("                               the mapping table back into a switch + port")
    return 0


if __name__ == "__main__":
    sys.exit(main())
