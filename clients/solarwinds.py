"""clients/solarwinds.py — SolarWinds Orion SWIS (SWQL) read client.

Thin wrapper over the Orion Information Service's JSON query endpoint. The
only operation exposed is `query()`, which POSTs a SWQL SELECT and returns
the result rows — there is no create/update/delete verb here, matching the
read-only posture of the other infrastructure clients.

Auth: like F5 (`clients/f5.py`), this uses the logged-in user's own AD
credentials via HTTP Basic Auth rather than a dedicated service account —
passed in per call, never read from the environment. SolarWinds expects
NTLM-style `DOMAIN\\username`, so a domain prefix is added unless the caller
already supplied one (`user@domain` or `domain\\user`).
"""
import os

import requests
from requests.auth import HTTPBasicAuth

from clients import verify_ssl


def _base_url() -> str:
    url = os.getenv("SOLARWINDS_URL", "").strip()
    if not url:
        raise RuntimeError("SOLARWINDS_URL is not configured")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _format_username(username: str) -> str:
    if "\\" in username or "@" in username:
        return username
    domain = os.getenv("SOLARWINDS_DOMAIN", "network")
    return f"{domain}\\{username}"


def query(swql: str, username: str, password: str, timeout: int | None = None) -> list[dict]:
    """Run a SWQL SELECT against Orion and return the result rows.

    `timeout` overrides SOLARWINDS_TIMEOUT (default 180s) for this call. That
    default is sized for the CDRL49 report's heavy fleet-wide queries; a
    caller backing an interactive control (e.g. the Bandwidth report's
    interface dropdown) should pass something short so a slow/unreachable
    Orion surfaces as a quick inline message instead of a hung UI element.
    """
    if not username or not password:
        raise RuntimeError("SolarWinds credentials are required")

    port = os.getenv("SOLARWINDS_PORT", "17774")
    if timeout is None:
        timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))
    endpoint = f"{_base_url()}:{port}/SolarWinds/InformationService/v3/Json/Query"

    resp = requests.post(
        endpoint,
        json={"query": swql},
        auth=HTTPBasicAuth(_format_username(username), password),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    return resp.json().get("results", [])
