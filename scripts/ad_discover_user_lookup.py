#!/usr/bin/env python3
"""scripts/ad_discover_user_lookup.py — can we turn an email address into
something ISE will recognise?

Read-only reconnaissance for the cross-platform endpoint search
(docs/ROADMAP.md item #1). scripts/ise_discover_user_sessions.py answers what
ISE stores in a session's `user_name`; this script answers whether we can get
*from an email address to that value*, which is the hop the whole feature
starts with.

auth.py today does exactly one LDAP operation: a SIMPLE bind to check a
password (auth.py:165). It never searches. So every question below is
unanswered in this codebase:

  1. CAN THE SERVICE ACCOUNT SEARCH AT ALL? A bind proves the credential is
     valid; it proves nothing about read rights on the directory. Some
     hardened AD deployments deny directory reads to ordinary accounts. If
     this fails the feature needs a dedicated read-only service account, and
     that is a request to make of the AD team, not a code change.

  2. WHICH ATTRIBUTE HOLDS THE EMAIL? `mail` is the obvious one, but
     `userPrincipalName` frequently differs from it, and mail aliases live in
     `proxyAddresses` as `smtp:` entries. An address that only ever appears as
     a secondary proxyAddress will not be found by a `mail=` filter — so all
     three are tried separately and the script reports which one actually
     matched.

  3. IS THE UPN THE SAME AS THE EMAIL? This is worth real money. If ISE
     sessions carry a UPN (the ise probe's step 4 reports that) *and* the UPN
     equals the mail attribute, the whole LDAP hop can be skipped: match the
     typed email straight against `user_name`. They are equal in many
     tenants and different in plenty of others, so it is checked here rather
     than assumed either way.

  4. WHAT ELSE IS POPULATED? The ask is "everything there is to know about
     that user", and AD is where the human context lives — department, title,
     office, manager, phone. But which of those are actually filled in varies
     enormously per organisation, so this dumps every populated attribute on
     a real account instead of guessing at a schema.

  5. IS THERE A USER → WORKSTATION LINK? This is the fallback that matters if
     the ISE probe reports mostly machine auth (`host/PC1234...`), because in
     that world no email will ever match a session directly. AD does not
     model "this person uses this PC" natively, but organisations improvise:
     managedBy on the computer object, a username in `description`, an
     extensionAttribute. If none of that is populated, the honest conclusion
     is that the link lives in SCCM/Intune/a CMDB and this feature cannot
     close the loop on wired machine-auth ports without it.

Every operation is a search or a read. There is no add/modify/delete call
anywhere in this file, and `raise_exceptions=False` keeps a denied read as a
reportable result rather than a traceback.

⚠️  OUTPUT CONTAINS REAL DIRECTORY DATA — names, emails, phone numbers,
    office locations. Pass --redact before pasting it anywhere.

Env vars (.env): AD_LDAP_URL, AD_DOMAIN, DOMAIN_USERNAME, DOMAIN_PASSWORD.

Usage:
    .venv/bin/python -m scripts.ad_discover_user_lookup --email someone@example.gov
    .venv/bin/python -m scripts.ad_discover_user_lookup --user jsmith --redact
    .venv/bin/python -m scripts.ad_discover_user_lookup --computer PC1234
    .venv/bin/python -m scripts.ad_discover_user_lookup --email a@b.gov --full
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

# Attributes worth calling out by name in the summary — the ones a "who is
# this person and where do they sit" panel would actually render. Everything
# else still gets dumped, just without the commentary.
_PERSON_ATTRS = [
    "sAMAccountName", "userPrincipalName", "mail", "displayName", "cn",
    "givenName", "sn", "title", "department", "company", "manager",
    "physicalDeliveryOfficeName", "streetAddress", "l", "st", "postalCode", "co",
    "telephoneNumber", "mobile", "ipPhone", "employeeID", "employeeType",
    "description", "distinguishedName", "userAccountControl", "lastLogonTimestamp",
    "whenCreated", "memberOf",
]

# Where an organisation might have improvised a user↔workstation link.
_LINK_ATTRS = ["managedBy", "description", "info", "comment"] + [
    f"extensionAttribute{i}" for i in range(1, 16)
]

_SENSITIVE = ("mail", "userprincipalname", "telephonenumber", "mobile", "ipphone",
              "displayname", "cn", "givenname", "sn", "streetaddress",
              "distinguishedname", "manager", "employeeid", "samaccountname",
              "proxyaddresses", "name", "dnshostname")


def _mask(val: str) -> str:
    s = str(val)
    if "@" in s:
        local, _, dom = s.partition("@")
        return f"{local[:2]}***@{dom}"
    if len(s) > 6:
        return f"{s[:3]}***{s[-2:]}"
    return "***"


class Redactor:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def attr(self, key: str, val) -> str:
        if not self.enabled:
            return str(val)
        if key.lower() in _SENSITIVE:
            if isinstance(val, (list, tuple)):
                return ", ".join(_mask(v) for v in val)
            return _mask(val)
        return str(val)

    def plain(self, val) -> str:
        return _mask(val) if self.enabled else str(val)


def _hr(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _escape(value: str) -> str:
    """RFC 4515 filter escaping. A probe is still a place where an unescaped
    '*' or ')' in an input silently changes the query's meaning."""
    out = []
    for ch in value:
        if ch in "\\*()\0":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def connect(allow_plaintext: bool):
    """Bind with the service account, trying the forms AD commonly accepts.
    Returns (connection, base_dn) or (None, None)."""
    from ldap3 import ALL, Connection, NTLM, SIMPLE, SYNC, Server

    url = os.getenv("AD_LDAP_URL", "")
    domain = os.getenv("AD_DOMAIN", "")
    user = os.getenv("DOMAIN_USERNAME", "")
    pw = os.getenv("DOMAIN_PASSWORD", "")

    if not url.lower().startswith("ldaps://"):
        print(f"  AD_LDAP_URL is {url!r} — not ldaps://.")
        if not allow_plaintext:
            print("  REFUSING to bind: this sends the service-account password in the")
            print("  clear. auth.py:175 enforces the same rule in the app. Re-run with")
            print("  --allow-plaintext only on a network you control end to end.")
            return None, None
        print("  --allow-plaintext given; continuing over cleartext LDAP.")

    server = Server(url, get_info=ALL, connect_timeout=8)

    # Bind form varies by deployment; try the three that actually occur.
    candidates = []
    if "@" in user or "\\" in user:
        candidates.append((user, SIMPLE, "as-configured"))
    else:
        if domain:
            candidates.append((f"{user}@{domain}", SIMPLE, "UPN"))
            short = domain.split(".")[0].upper()
            candidates.append((f"{short}\\{user}", NTLM, "NTLM"))
        candidates.append((user, SIMPLE, "bare"))

    for bind_user, mech, label in candidates:
        try:
            conn = Connection(server, user=bind_user, password=pw,
                              authentication=mech, client_strategy=SYNC,
                              raise_exceptions=False, auto_bind=False)
            if conn.bind():
                print(f"  BOUND as {bind_user!r} ({label}).")
                base = _base_dn(server, conn)
                return conn, base
            print(f"  bind failed ({label}): {conn.result.get('description')} "
                  f"— {conn.result.get('message', '')[:120]}")
        except Exception as e:
            print(f"  bind error ({label}): {type(e).__name__}: {e}")
    return None, None


def _base_dn(server, conn) -> str:
    """Read the naming context from RootDSE rather than hardcoding a DN —
    the same instinct as reading SolarWinds' custom properties from
    Orion.CustomProperty instead of guessing field names."""
    try:
        info = server.info
        if info and info.other:
            for key in ("defaultNamingContext", "rootDomainNamingContext"):
                val = info.other.get(key)
                if val:
                    base = val[0] if isinstance(val, (list, tuple)) else val
                    print(f"  base DN from RootDSE.{key}: {base}")
                    return str(base)
        if info and info.naming_contexts:
            base = str(info.naming_contexts[0])
            print(f"  base DN from namingContexts[0]: {base}")
            return base
    except Exception as e:
        print(f"  RootDSE read failed: {type(e).__name__}: {e}")
    domain = os.getenv("AD_DOMAIN", "")
    base = ",".join(f"DC={p}" for p in domain.split(".") if p)
    print(f"  base DN derived from AD_DOMAIN: {base}")
    return base


def _search(conn, base: str, flt: str, attrs, size: int = 10):
    from ldap3 import SUBTREE
    ok = conn.search(search_base=base, search_filter=flt, search_scope=SUBTREE,
                     attributes=attrs, size_limit=size)
    if not ok:
        res = conn.result or {}
        return None, f"{res.get('description')} — {str(res.get('message', ''))[:200]}"
    return [e for e in conn.entries], None


def _populated(entry) -> dict:
    out = {}
    for name in entry.entry_attributes:
        try:
            val = entry[name].value
        except Exception:
            continue
        if val in (None, "", [], ()):
            continue
        out[name] = val
    return out


# ──────────────────────────────────────────────────────────────────────────────
# STEPS
# ──────────────────────────────────────────────────────────────────────────────

def step_find_user(conn, base: str, email: str | None, samname: str | None,
                   red: Redactor, full: bool):
    _hr("STEP 2  —  FIND THE USER")
    from ldap3 import ALL_ATTRIBUTES

    filters = []
    if email:
        e = _escape(email)
        filters = [
            (f"(&(objectClass=user)(mail={e}))", "mail"),
            (f"(&(objectClass=user)(userPrincipalName={e}))", "userPrincipalName"),
            (f"(&(objectClass=user)(proxyAddresses=smtp:{e}))", "proxyAddresses (alias)"),
        ]
    elif samname:
        s = _escape(samname)
        filters = [(f"(&(objectClass=user)(sAMAccountName={s}))", "sAMAccountName")]

    matched_by = None
    entries = None
    for flt, label in filters:
        print(f"  → {label}: {flt}")
        found, err = _search(conn, base, flt, ALL_ATTRIBUTES, size=5)
        if err:
            print(f"    SEARCH FAILED — {err}")
            if "insufficientAccessRights" in err or "operationsError" in err:
                print("    → The bind account cannot read the directory. This is the")
                print("      blocking answer to question 1: ask the AD team for a")
                print("      read-only service account before building anything.")
            continue
        if found:
            print(f"    MATCHED {len(found)} entry(ies).")
            matched_by, entries = label, found
            break
        print("    no match.")

    if not entries:
        print("\n  No user found. Either the address is wrong, or none of mail/UPN/")
        print("  proxyAddresses carries it on this directory. Try --user with a known")
        print("  sAMAccountName to separate 'cannot search' from 'wrong attribute'.")
        return None

    entry = entries[0]
    attrs = _populated(entry)
    print(f"\n  MATCHED BY: {matched_by}")
    print(f"  {len(attrs)} populated attribute(s) on this account.\n")

    print("  IDENTITY / LOCATION FIELDS")
    print("  " + "-" * 60)
    for key in _PERSON_ATTRS:
        actual = next((k for k in attrs if k.lower() == key.lower()), None)
        if actual is None:
            continue
        val = attrs[actual]
        if isinstance(val, (list, tuple)):
            shown = f"[{len(val)} values] " + red.attr(actual, val[:2])
        else:
            shown = red.attr(actual, val)
        print(f"     {actual:<28} {str(shown)[:60]}")

    missing = [k for k in _PERSON_ATTRS
               if not any(a.lower() == k.lower() for a in attrs)]
    if missing:
        print(f"\n  NOT POPULATED ({len(missing)}): {', '.join(missing)}")
        print("  → Anything in that list cannot appear in the user panel.")

    if full:
        others = {k: v for k, v in attrs.items()
                  if not any(k.lower() == p.lower() for p in _PERSON_ATTRS)}
        if others:
            print(f"\n  ALL OTHER POPULATED ATTRIBUTES ({len(others)}):")
            for k, v in sorted(others.items()):
                print(f"     {k:<28} {red.attr(k, v)[:60]}")

    _check_upn_equals_mail(attrs, red)
    _check_workstation_hints(attrs, red)
    return attrs


def _get(attrs: dict, name: str):
    actual = next((k for k in attrs if k.lower() == name.lower()), None)
    return attrs.get(actual) if actual else None


def _check_upn_equals_mail(attrs: dict, red: Redactor) -> None:
    _hr("STEP 3  —  DOES THE UPN EQUAL THE EMAIL?")
    upn = _get(attrs, "userPrincipalName")
    mail = _get(attrs, "mail")
    sam = _get(attrs, "sAMAccountName")
    print(f"  sAMAccountName     {red.plain(sam) if sam else '— (not readable)'}")
    print(f"  userPrincipalName  {red.plain(upn) if upn else '— (not populated)'}")
    print(f"  mail               {red.plain(mail) if mail else '— (not populated)'}")
    print()
    if upn and mail and str(upn).lower() == str(mail).lower():
        print("  EQUAL. If ISE sessions carry a UPN (check step 4 of the ISE probe),")
        print("  a typed email can be matched straight against `user_name` and the")
        print("  LDAP hop becomes optional enrichment rather than a hard dependency.")
    elif upn and mail:
        print("  DIFFERENT. The email cannot be matched against a UPN-style session")
        print("  name directly — the LDAP lookup is REQUIRED to translate it.")
    else:
        print("  Cannot compare — one side is not readable on this account.")


def _check_workstation_hints(attrs: dict, red: Redactor) -> None:
    _hr("STEP 4  —  ANY USER → WORKSTATION LINK ON THE USER OBJECT?")
    print("  Only matters if ISE turns out to be mostly machine auth. AD has no")
    print("  native 'this person uses this PC' attribute, so this looks for the")
    print("  places organisations improvise one.\n")
    hits = {}
    for key in _LINK_ATTRS:
        val = _get(attrs, key)
        if val:
            hits[key] = val
    if not hits:
        print("  NONE of managedBy / description / info / extensionAttribute1-15 is")
        print("  populated on this user.")
        print("  → If ISE is machine-auth-heavy, the user↔workstation link is NOT in")
        print("    AD and must come from SCCM / Intune / a CMDB. That is a scope")
        print("    decision to make before building, not a detail to discover later.")
        return
    for k, v in hits.items():
        print(f"     {k:<28} {red.attr(k, v)[:60]}")
    print("\n  → Inspect these by eye: a hostname here is the missing link, anything")
    print("    else is coincidence. Free-text fields are not a contract — if the link")
    print("    lives in `description`, treat parsing it as best-effort.")


def step_computer(conn, base: str, name: str, red: Redactor, full: bool) -> None:
    _hr(f"STEP 5  —  COMPUTER OBJECT  [{name}]")
    print("  The machine-auth path: ISE reports host/PC1234.domain, and we ask AD")
    print("  what PC1234 is and whether anything ties it to a person.\n")
    from ldap3 import ALL_ATTRIBUTES

    short = name.split(".")[0].removeprefix("host/")
    flt = f"(&(objectClass=computer)(|(cn={_escape(short)})(sAMAccountName={_escape(short)}$)))"
    print(f"  filter: {flt}")
    found, err = _search(conn, base, flt, ALL_ATTRIBUTES, size=5)
    if err:
        print(f"  SEARCH FAILED — {err}")
        return
    if not found:
        print("  No computer object with that name.")
        return
    attrs = _populated(found[0])
    print(f"  {len(attrs)} populated attribute(s).\n")
    for key in ("cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                "lastLogonTimestamp", "whenCreated", "managedBy", "description",
                "location", "distinguishedName"):
        val = _get(attrs, key)
        if val:
            print(f"     {key:<28} {red.attr(key, val)[:60]}")
    print()
    if _get(attrs, "managedBy"):
        print("  managedBy IS populated — this is a real user↔workstation link and")
        print("  makes the machine-auth path viable. Confirm it is maintained rather")
        print("  than a one-time import before depending on it.")
    else:
        print("  managedBy is empty (the common case). No link from this computer")
        print("  back to a person inside AD.")
    if full:
        print(f"\n  ALL ATTRIBUTES ({len(attrs)}):")
        for k, v in sorted(attrs.items()):
            print(f"     {k:<28} {red.attr(k, v)[:60]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--email", help="Email address to resolve (the real entry point)")
    ap.add_argument("--user", help="sAMAccountName to look up instead — use to test "
                                   "search rights when an email finds nothing")
    ap.add_argument("--computer", help="Computer name to inspect, e.g. PC1234 or "
                                       "host/PC1234.example.local")
    ap.add_argument("--redact", action="store_true",
                    help="Mask names/emails/phones — use before pasting output anywhere")
    ap.add_argument("--full", action="store_true", help="Dump every populated attribute")
    ap.add_argument("--allow-plaintext", action="store_true",
                    help="Permit a bind over ldap:// (sends the password in the clear)")
    args = ap.parse_args()

    if not (args.email or args.user or args.computer):
        ap.error("give at least one of --email / --user / --computer")

    missing = [v for v in ("AD_LDAP_URL", "DOMAIN_USERNAME", "DOMAIN_PASSWORD")
               if not os.getenv(v)]
    if missing:
        print(f"ERROR: missing env var(s): {', '.join(missing)} (see .env.template).")
        return 1
    try:
        import ldap3  # noqa: F401
    except ImportError:
        print("ERROR: ldap3 is not installed — pip install -r requirements.txt")
        return 1

    red = Redactor(args.redact)
    print(f"AD directory probe — {os.getenv('AD_LDAP_URL')}")
    print("Read-only: searches and reads only, no directory writes.")
    if not args.redact:
        print("NOTE: output will contain real directory data. Re-run with --redact")
        print("      before pasting it anywhere it will be stored.")

    _hr("STEP 1  —  BIND AND BASE DN")
    conn, base = connect(args.allow_plaintext)
    if not conn:
        print("\n  Could not bind. Everything downstream is blocked on this.")
        return 1

    try:
        attrs = None
        if args.email or args.user:
            attrs = step_find_user(conn, base, args.email, args.user, red, args.full)

        computer = args.computer
        if not computer and attrs:
            hint = _get(attrs, "description") or ""
            if isinstance(hint, str) and hint.strip() and " " not in hint.strip():
                print(f"\n  (description looks like a hostname: {red.plain(hint)} — "
                      f"re-run with --computer to inspect it)")
        if computer:
            step_computer(conn, base, computer, red, args.full)
    finally:
        conn.unbind()

    _hr("NEXT")
    print("  ise_discover_user_sessions   what ISE stores in user_name (run this first")
    print("                               if you have not — it decides the whole design)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
