#!/usr/bin/env python3
"""scripts/solarwinds_test_api2_auth.py — does /api2/ (the Orion Web Console's
own internal REST API) accept plain HTTP Basic Auth?

The "Scheduled Maintenance" dialog (Settings > All Settings > Manage
Maintenance Schedules) submits to POST https://<web-console-host>/api2/schedules/
createOneTime, authenticated by the browser's own logged-in session cookies
(.ASPXAUTH + a matching XSRF token pair) — not the per-call Basic Auth every
other client in this app uses. A manual curl retest is easy to mistype
(domain\\username, quoting, etc.) when it has to be retyped by hand rather
than copy-pasted between machines — this script removes that risk: pull it
via git and run it with just a hostname, no retyping of credentials or curl
flags required.

This is read-only (a single GET, no schedule created) — safe to run as many
times as needed. It only answers the auth question; it does not test
createOneTime itself.

Note: --host is the Orion **web console** hostname (what you type into a
browser to reach SolarWinds), which is NOT necessarily the same host as
SOLARWINDS_URL in .env — that variable points at whatever host serves SWIS
(often a specific polling engine), which this app's real production .env
here resolves to a different host entirely than the web console. Pass the
web console hostname explicitly; it's not read from .env or hardcoded here.

Env vars (.env): SOLARWINDS_DOMAIN (optional NTLM prefix, default "network"),
SOLARWINDS_USERNAME/PASSWORD (default to DOMAIN_USERNAME/PASSWORD),
SOLARWINDS_VERIFY_SSL (default false).

Usage:
    python -m scripts.solarwinds_test_api2_auth --host <your-orion-web-console-host>
    python -m scripts.solarwinds_test_api2_auth --host <host> --path /api2/schedules/someOtherPath
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from requests.auth import HTTPBasicAuth  # noqa: E402

load_dotenv()


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "y")


def _format_username(username: str) -> str:
    if "\\" in username or "@" in username:
        return username
    domain = os.getenv("SOLARWINDS_DOMAIN", "network")
    return f"{domain}\\{username}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True, help="Orion web console hostname (e.g. what you browse to, not SOLARWINDS_URL)")
    ap.add_argument("--path", default="/api2/schedules", help="Path to GET (default: /api2/schedules)")
    args = ap.parse_args()

    username = os.getenv("SOLARWINDS_USERNAME") or os.getenv("DOMAIN_USERNAME", "")
    password = os.getenv("SOLARWINDS_PASSWORD") or os.getenv("DOMAIN_PASSWORD", "")
    verify_ssl = _bool_env("SOLARWINDS_VERIFY_SSL", False)

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not username or not password:
        print("ERROR: SOLARWINDS_USERNAME/SOLARWINDS_PASSWORD (or DOMAIN_USERNAME/DOMAIN_PASSWORD) must be set.")
        sys.exit(1)

    host = args.host.strip()
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    url = host.rstrip("/") + args.path

    formatted_user = _format_username(username)
    print(f"GET {url}")
    print(f"Auth: Basic, user={formatted_user!r}\n")

    try:
        resp = requests.get(url, auth=HTTPBasicAuth(formatted_user, password), verify=verify_ssl, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        sys.exit(1)

    print(f"← HTTP {resp.status_code}")
    print("Response headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    print("\nBody (first 2000 chars):")
    print(resp.text[:2000])

    print()
    print("=" * 78)
    if resp.status_code == 200:
        print("200 — Basic Auth works against /api2/ directly. No session/cookie flow needed.")
    elif resp.status_code in (401, 403):
        print(f"{resp.status_code} — Basic Auth alone is rejected here; a real login/cookie+XSRF")
        print("session is genuinely required for this endpoint.")
    else:
        print(f"Unexpected status {resp.status_code} — see body above (may be a redirect to a login page, wrong path, etc).")
    print("=" * 78)


if __name__ == "__main__":
    main()
