#!/usr/bin/env python3
"""scripts/ise_discover_user_sessions.py — can ISE answer "where is this user?"

Read-only reconnaissance for the cross-platform endpoint search in
docs/ROADMAP.md item #1 ("Where is this MAC / IP / user?"), specifically the
variant that starts from a person's email address and has to end at a switch
port. Everything downstream of ISE is a dict join against caches we already
warm (`devices`, `device_site_map`, `dnac_interfaces` — datasets.py:30), so
ISE is the hop that decides whether the whole feature is possible.

Two questions, and the first one is fatal if it goes the wrong way:

  1. WHAT IS IN `user_name`?  If this fleet does 802.1X *machine* auth on
     wired ports, every session reads `host/PC1234.example.local` and no
     email address will ever match one. If it does *user* auth with EAP-TLS
     and a UPN in the SAN, `user_name` may literally BE the email address and
     the AD lookup hop disappears entirely. If a port is MAB'd, `user_name`
     is just the MAC again. Realistically it is a mix, and the mix is the
     design input — so this script samples real sessions and classifies them
     rather than assuming.

     NOTE this cannot be answered from Session/ActiveList alone. On ISE 3.x
     ActiveList returns only four fields per row (calling_station_id,
     audit_session_id, server, framed_ipv6_address — see the comment at
     clients/ise.py:186) and `user_name` is not among them. Full detail needs
     a per-MAC follow-up to Session/MACAddress/{mac}, which is exactly what
     routers/ise.py::_enrich_many already does for the sessions page. So we
     sample N MACs and fan out, the same way.

  2. DO THE BY-USER AND BY-IP MNT ENDPOINTS EXIST HERE?  clients/ise.py wraps
     Session/MACAddress but never Session/UserName/{name} or
     Session/EndPointIPAddress/{ip}. Both are documented MNT endpoints and
     both would be near-copies of get_session_by_mac (clients/ise.py:201) —
     but "documented" and "returns 200 on this deployment" are different
     claims, and MNT has burned us before: Session/AuthList returns HTTP 500
     on ISE 3.x and had to be removed from the client outright
     (docs/ROADMAP.md:58). So we probe them against a real value harvested
     from question 1 rather than a guess.

Also emits a FIELD INVENTORY: every key seen across the sampled session
records with a fill rate. That is the real design input for the search UI —
`nas_port_id` populated on 12% of sessions means something very different for
"what port are they plugged into" than 98% does, and neither is knowable from
the ISE documentation.

Calls MNT directly with raw requests rather than through clients.ise, which
logs-and-swallows every failure into an empty list (clients/ise.py:196). An
empty list is indistinguishable from "endpoint answered with no rows", and
telling those two apart is this script's entire job — so status codes and
response bodies are printed verbatim, same reasoning as the SolarWinds and
SNA discovery probes before it.

Every call is a GET. Nothing here mutates ISE, and no CoA/session-delete
endpoint is referenced anywhere in this file.

⚠️  OUTPUT CONTAINS REAL USERNAMES, MAC ADDRESSES AND IP ADDRESSES. Pass
    --redact before pasting the output into a ticket, a chat window or
    anywhere else it will be stored (see docs/IP_ADDRESS_POLICY.md).

Env vars (.env): ISE_HOST, DOMAIN_USERNAME, DOMAIN_PASSWORD.

Usage:
    .venv/bin/python -m scripts.ise_discover_user_sessions
    .venv/bin/python -m scripts.ise_discover_user_sessions --sample 60 --redact
    .venv/bin/python -m scripts.ise_discover_user_sessions --user jsmith
    .venv/bin/python -m scripts.ise_discover_user_sessions --ip 1.2.3.4 --full
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from clients import verify_ssl  # noqa: E402
from clients.ise import _xml_list_to_dicts, _xml_to_dict  # noqa: E402

# Fields that decide whether the search feature can render a useful answer.
# Listed here so the inventory can call out a low fill rate on one of them
# instead of burying it in an alphabetical dump of forty keys.
_CRITICAL = [
    "user_name",
    "calling_station_id",
    "nas_ip_address",
    "network_device_name",
    "nas_port_id",
    "framed_ip_address",
    "vlan",
    "endpoint_profile",
    "identity_group",
    "identity_store",
    "auth_method",
    "selected_azn_profiles",
    "cts_security_group",
    "called_station_id",
    "acct_session_time",
    "nas_identifier",
    "ap_mac",
    "ssid",
    "posture_status",
]

_MAC_RE = re.compile(r"^[0-9a-fA-F]{12}$")
_HEX_SEPS = str.maketrans("", "", ":-.")


# ──────────────────────────────────────────────────────────────────────────────
# REDACTION
# ──────────────────────────────────────────────────────────────────────────────

def _redact_mac(v: str) -> str:
    raw = v.translate(_HEX_SEPS)
    if len(raw) == 12:
        return f"{raw[:6]}-XXXXXX"
    return v


def _redact_ip(v: str) -> str:
    if ":" in v:                       # IPv6
        head = v.split(":")[:2]
        return ":".join(head) + ":xxxx::xxxx"
    parts = v.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return v


def _redact_user(v: str) -> str:
    if not v:
        return v
    if "@" in v:
        local, _, dom = v.partition("@")
        return f"{local[:2]}***@{dom}"
    if "\\" in v:
        dom, _, user = v.partition("\\")
        return f"{dom}\\{user[:2]}***"
    if v.startswith("host/"):
        return "host/" + v[5:][:3] + "***"
    return v[:2] + "***" if len(v) > 2 else "***"


class Redactor:
    """Field-aware masking. Off by default — the operator running this owns
    the data; the flag exists for when the output leaves the terminal."""

    _IPISH = ("ip_address", "framed_ip", "nas_ip", "ipv6")
    _MACISH = ("mac", "calling_station_id", "called_station_id")
    _USERISH = ("user_name", "user", "identity")

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def value(self, key: str, val: str) -> str:
        if not self.enabled or not isinstance(val, str) or not val:
            return val
        k = key.lower()
        if any(t in k for t in self._MACISH):
            return _redact_mac(val)
        if any(t in k for t in self._IPISH):
            return _redact_ip(val)
        if any(t in k for t in self._USERISH):
            return _redact_user(val)
        return val

    def user(self, val: str) -> str:
        return _redact_user(val) if self.enabled else val

    def mac(self, val: str) -> str:
        return _redact_mac(val) if self.enabled else val

    def ip(self, val: str) -> str:
        return _redact_ip(val) if self.enabled else val


# ──────────────────────────────────────────────────────────────────────────────
# RAW MNT
# ──────────────────────────────────────────────────────────────────────────────

def _mnt(path: str, timeout: int = 25) -> tuple[int | None, str]:
    """One GET against MNT. Returns (status_code, body) — never raises, never
    swallows. A None status means the request itself failed (DNS/TLS/timeout)
    and the body carries the exception text."""
    host = os.getenv("ISE_HOST")
    user = os.getenv("DOMAIN_USERNAME")
    pw = os.getenv("DOMAIN_PASSWORD")
    url = f"https://{host}{path}"
    try:
        r = requests.get(
            url,
            auth=(user, pw),
            verify=verify_ssl(),
            headers={"Accept": "application/xml"},
            timeout=timeout,
        )
        return r.status_code, r.text or ""
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _norm_mac(mac: str) -> str:
    m = (mac or "").upper().replace("-", ":").replace(".", ":")
    if ":" not in m and len(m) == 12:
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    return m


def _hr(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _show_failure(status: int | None, body: str) -> None:
    if status is None:
        print(f"  REQUEST FAILED — {body}")
        return
    print(f"  HTTP {status}")
    snippet = body.strip()[:600]
    if snippet:
        print("  body:")
        for line in snippet.splitlines():
            print(f"    {line}")
    if status == 404:
        print("  → 404: this MNT path does not exist on this ISE version.")
    elif status == 500:
        print("  → 500: path exists but errors on this version — same failure mode as")
        print("    Session/AuthList, which had to be dropped from clients/ise.py.")
    elif status in (401, 403):
        print("  → auth: DOMAIN_USERNAME needs the MNT/Monitoring role in ISE.")


# ──────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION
# ──────────────────────────────────────────────────────────────────────────────

def classify_user_name(name: str) -> str:
    """Bucket a session's user_name into an auth style. This is the single
    most important output of the script — see the module docstring."""
    if not name:
        return "empty"
    n = name.strip()
    if _MAC_RE.match(n.translate(_HEX_SEPS)):
        return "mac (MAB)"
    if n.lower().startswith("host/"):
        return "host/... (machine auth)"
    if "@" in n:
        return "user@domain (UPN — may match email directly)"
    if "\\" in n:
        return "DOMAIN\\user (user auth)"
    if n.startswith("#") or n.lower() in ("invalid", "unknown"):
        return "sentinel/unknown"
    return "bare username (user auth)"


_MATCHABLE = (
    "user@domain (UPN — may match email directly)",
    "DOMAIN\\user (user auth)",
    "bare username (user auth)",
)


# ──────────────────────────────────────────────────────────────────────────────
# STEPS
# ──────────────────────────────────────────────────────────────────────────────

def step_active_list(red: Redactor, full: bool) -> list[dict]:
    _hr("STEP 1  —  GET /admin/API/mnt/Session/ActiveList")
    status, body = _mnt("/admin/API/mnt/Session/ActiveList")
    if status != 200:
        _show_failure(status, body)
        return []
    rows = _xml_list_to_dicts(body, record_tag="activeSession") or _xml_list_to_dicts(body)
    print(f"  HTTP 200 — {len(rows)} active session(s).")
    if not rows:
        print("  EMPTY. Either nothing is authenticated right now, or this account")
        print("  cannot see sessions. Not the same as 'the endpoint is broken'.")
        return []
    print(f"\n  Fields present per ActiveList row: {sorted(rows[0].keys())}")
    if "user_name" in rows[0]:
        print("  → user_name IS in ActiveList on this version. That is better than the")
        print("    4-field shape clients/ise.py:186 documents — a by-user search could")
        print("    filter the cached list directly, no per-MAC fan-out needed.")
    else:
        print("  → user_name is NOT in ActiveList (matches the documented 3.x shape).")
        print("    Per-MAC enrichment is required; that is what step 2 measures.")
    if full:
        print("\n  raw (first 800 chars):")
        print("  " + body[:800].replace("\n", "\n  "))
    return rows


def step_enrich(rows: list[dict], sample: int, workers: int, red: Redactor) -> list[dict]:
    _hr(f"STEP 2  —  per-MAC detail, Session/MACAddress/{{mac}}  (sample of {sample})")
    macs = [r.get("calling_station_id") for r in rows if r.get("calling_station_id")]
    macs = macs[:sample]
    if not macs:
        print("  No calling_station_id values in ActiveList — nothing to enrich.")
        return []
    print(f"  Fetching {len(macs)} session records with {workers} workers...")

    def one(mac: str) -> dict:
        status, body = _mnt(f"/admin/API/mnt/Session/MACAddress/{_norm_mac(mac)}", timeout=20)
        if status == 200 and body:
            return _xml_to_dict(body)
        return {}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        details = [d for d in ex.map(one, macs) if d]
    print(f"  {len(details)}/{len(macs)} returned a session record.")
    if len(details) < len(macs):
        print("  → Gaps are normal: a session can end between the ActiveList read and")
        print("    the per-MAC follow-up. A large gap means the fan-out is unreliable")
        print("    and the search should query by user/IP directly instead.")
    return details


def step_field_inventory(details: list[dict], red: Redactor) -> None:
    _hr("STEP 3  —  FIELD INVENTORY  (fill rate across sampled sessions)")
    if not details:
        print("  No session records to inventory.")
        return
    n = len(details)
    counts: Counter = Counter()
    for d in details:
        for k, v in d.items():
            if v not in (None, "", "-"):
                counts[k] += 1

    print(f"  {len(counts)} distinct populated field(s) across {n} session(s).\n")
    print("  CRITICAL FIELDS FOR THIS FEATURE")
    print("  " + "-" * 60)
    for key in _CRITICAL:
        c = counts.get(key, 0)
        pct = 100.0 * c / n
        flag = "  " if pct >= 90 else ("??" if pct > 0 else "XX")
        sample_val = next((d[key] for d in details if d.get(key)), "")
        shown = red.value(key, str(sample_val))[:34]
        print(f"  {flag} {key:<24} {c:>3}/{n} ({pct:5.1f}%)  e.g. {shown}")
    print()
    print("     XX = never populated — anything relying on it cannot be built.")
    print("     ?? = partially populated — usable, but the UI must handle absence.")

    extra = sorted(k for k in counts if k not in _CRITICAL)
    if extra:
        print(f"\n  OTHER POPULATED FIELDS ({len(extra)}):")
        for i in range(0, len(extra), 3):
            print("    " + "".join(f"{k:<26}" for k in extra[i:i + 3]))


def step_classify(details: list[dict], red: Redactor) -> list[str]:
    _hr("STEP 4  —  WHAT IS IN user_name?  (the make-or-break question)")
    if not details:
        print("  No session records to classify.")
        return []
    buckets: Counter = Counter()
    examples: dict[str, str] = {}
    matchable: list[str] = []
    for d in details:
        name = (d.get("user_name") or "").strip()
        kind = classify_user_name(name)
        buckets[kind] += 1
        examples.setdefault(kind, name)
        if kind in _MATCHABLE and name:
            matchable.append(name)

    total = sum(buckets.values())
    for kind, count in buckets.most_common():
        pct = 100.0 * count / total
        print(f"  {count:>4} ({pct:5.1f}%)  {kind}")
        print(f"              e.g. {red.user(examples[kind])}")

    print()
    user_auth = sum(c for k, c in buckets.items() if k in _MATCHABLE)
    upn = buckets.get("user@domain (UPN — may match email directly)", 0)
    pct_user = 100.0 * user_auth / total
    if pct_user == 0:
        print("  VERDICT: NO session carries a human username. Email → session is a")
        print("  DEAD END on this deployment. The feature would need a user→workstation")
        print("  source outside the network stack (SCCM / CMDB / AD computer objects)")
        print("  before ISE could be joined at all. See the AD probe for that path.")
    elif pct_user < 25:
        print(f"  VERDICT: only {pct_user:.0f}% of sessions carry a human username —")
        print("  most likely user auth on wireless, machine auth on wired. The search")
        print("  will find people on Wi-Fi and miss them at their desk. Worth checking")
        print("  whether the wired sessions correlate to a workstation another way.")
    else:
        print(f"  VERDICT: {pct_user:.0f}% of sessions carry a human username. Email →")
        print("  session is viable.")
    if upn:
        print(f"  BONUS: {upn} session(s) use a UPN. If the UPN equals the mail attribute")
        print("  in AD, the email can be matched against user_name with NO LDAP hop.")
        print("  Confirm with the AD probe — UPN and mail differ more often than expected.")
    return matchable


def step_by_user(name: str, red: Redactor, full: bool) -> None:
    _hr(f"STEP 5  —  GET /admin/API/mnt/Session/UserName/{{name}}   [{red.user(name)}]")
    print("  Not wrapped in clients/ise.py today. If this works it is a ~20-line")
    print("  copy of get_session_by_mac and the by-user search needs nothing else.\n")

    variants = [name]
    if "\\" in name:
        variants.append(name.split("\\", 1)[1])
    if "@" in name:
        variants.append(name.split("@", 1)[0])
    seen = set()

    for v in variants:
        if v in seen:
            continue
        seen.add(v)
        print(f"  → trying {red.user(v)!r}")
        status, body = _mnt(f"/admin/API/mnt/Session/UserName/{v}")
        if status == 200:
            parsed = _xml_to_dict(body)
            rows = _xml_list_to_dicts(body)
            if parsed or rows:
                print(f"    HTTP 200 — WORKS. {len(parsed)} field(s), {len(rows)} row(s).")
                interesting = {k: red.value(k, str(parsed[k]))
                               for k in _CRITICAL if parsed.get(k)}
                for k, val in interesting.items():
                    print(f"      {k:<24} {val}")
                if full:
                    print("    raw (first 900 chars):")
                    print("    " + body[:900].replace("\n", "\n    "))
                return
            print("    HTTP 200 but EMPTY — the path exists and this name did not match.")
            print("    Try a different variant, or the name format ISE stores differs.")
        else:
            _show_failure(status, body)


def step_by_ip(ip: str, red: Redactor, full: bool) -> None:
    _hr(f"STEP 6  —  GET /admin/API/mnt/Session/EndPointIPAddress/{{ip}}   [{red.ip(ip)}]")
    print("  Also unwrapped today. This is the hop that turns a Panorama User-ID or")
    print("  GlobalProtect mapping (an IP) back into a full ISE session.\n")
    status, body = _mnt(f"/admin/API/mnt/Session/EndPointIPAddress/{ip}")
    if status == 200:
        parsed = _xml_to_dict(body)
        if parsed:
            print(f"    HTTP 200 — WORKS. {len(parsed)} field(s).")
            for k in _CRITICAL:
                if parsed.get(k):
                    print(f"      {k:<24} {red.value(k, str(parsed[k]))}")
            if full:
                print("    raw (first 900 chars):")
                print("    " + body[:900].replace("\n", "\n    "))
        else:
            print("    HTTP 200 but EMPTY — path exists, no session for that IP.")
    else:
        _show_failure(status, body)


def step_switch_join(details: list[dict], red: Redactor) -> None:
    """The payoff check: does a session actually name a switch AND a port?"""
    _hr("STEP 7  —  CAN WE NAME THE SWITCH AND PORT?")
    if not details:
        print("  No session records.")
        return
    both = [d for d in details
            if (d.get("nas_ip_address") or d.get("network_device_name")) and d.get("nas_port_id")]
    print(f"  {len(both)}/{len(details)} session(s) carry both a NAS identity and a port.\n")
    for d in both[:5]:
        print(f"    user      {red.user(d.get('user_name', '—'))}")
        print(f"    mac       {red.mac(d.get('calling_station_id', '—'))}")
        print(f"    switch    {d.get('network_device_name') or red.ip(d.get('nas_ip_address', '—'))}")
        print(f"    port      {d.get('nas_port_id', '—')}")
        print(f"    ip        {red.ip(d.get('framed_ip_address', '—'))}")
        print(f"    vlan      {d.get('vlan', '—')}   profile: {d.get('endpoint_profile', '—')}")
        print()
    if both:
        print("  → This is the answer the feature exists to give, and ISE hands it over")
        print("    directly. Site/model/description enrichment is a dict join against")
        print("    the already-warmed `devices` and `dnac_interfaces` caches.")
    else:
        print("  → No session names both. Without nas_port_id the port must come from")
        print("    somewhere else — SolarWinds UDT, or CAM/ARP off the switch (neither")
        print("    of which the app collects today).")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sample", type=int, default=25,
                    help="How many active sessions to pull full detail for (default 25)")
    ap.add_argument("--workers", type=int, default=8,
                    help="Parallel MNT requests (default 8, matches routers/ise.py)")
    ap.add_argument("--user", help="Probe Session/UserName with this name instead of a harvested one")
    ap.add_argument("--ip", help="Probe Session/EndPointIPAddress with this IP instead of a harvested one")
    ap.add_argument("--redact", action="store_true",
                    help="Mask usernames/MACs/IPs — use before pasting output anywhere")
    ap.add_argument("--full", action="store_true", help="Dump raw XML snippets too")
    args = ap.parse_args()

    missing = [v for v in ("ISE_HOST", "DOMAIN_USERNAME", "DOMAIN_PASSWORD") if not os.getenv(v)]
    if missing:
        print(f"ERROR: missing env var(s): {', '.join(missing)} (see .env.template).")
        return 1

    red = Redactor(args.redact)
    print(f"ISE MNT identity-chain probe — host {os.getenv('ISE_HOST')}")
    print("Read-only: every call below is a GET.")
    if not args.redact:
        print("NOTE: output will contain real usernames/MACs/IPs. Re-run with --redact")
        print("      before pasting it anywhere it will be stored.")

    rows = step_active_list(red, args.full)
    details = step_enrich(rows, args.sample, args.workers, red) if rows else []
    step_field_inventory(details, red)
    matchable = step_classify(details, red)

    probe_user = args.user or (matchable[0] if matchable else None)
    if probe_user:
        step_by_user(probe_user, red, args.full)
    else:
        _hr("STEP 5  —  Session/UserName  (SKIPPED)")
        print("  No human username found in the sample to probe with. Pass --user NAME")
        print("  with a known-good account to test the endpoint itself.")

    probe_ip = args.ip or next((d.get("framed_ip_address") for d in details
                                if d.get("framed_ip_address")), None)
    if probe_ip:
        step_by_ip(probe_ip, red, args.full)
    else:
        _hr("STEP 6  —  Session/EndPointIPAddress  (SKIPPED)")
        print("  No framed_ip_address in the sample. Pass --ip ADDR to test the endpoint.")

    step_switch_join(details, red)

    _hr("NEXT")
    print("  ad_discover_user_lookup      email → sAMAccountName (the hop before this)")
    print("  panorama_discover_userid     IP → user, and remote/GlobalProtect sessions")
    print("  solarwinds_discover_udt      port history, if UDT is licensed")
    print("  dnac_discover_clients        richest per-client record, if Assurance is on")
    return 0


if __name__ == "__main__":
    sys.exit(main())
