"""clients/solarwinds.py — SolarWinds Orion SWIS (SWQL) read client.

Thin wrapper over the Orion Information Service's JSON query endpoint. The
only operation exposed is `query()`, which POSTs a SWQL SELECT and returns
the result rows — there is no create/update/delete verb here, matching the
read-only posture of the other infrastructure clients.
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


def query(swql: str) -> list[dict]:
    """Run a SWQL SELECT against Orion and return the result rows."""
    username = os.getenv("SOLARWINDS_USERNAME")
    password = os.getenv("SOLARWINDS_PASSWORD")
    if not username or not password:
        raise RuntimeError("SOLARWINDS_USERNAME / SOLARWINDS_PASSWORD are not configured")

    port = os.getenv("SOLARWINDS_PORT", "17774")
    timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))
    endpoint = f"{_base_url()}:{port}/SolarWinds/InformationService/v3/Json/Query"

    resp = requests.post(
        endpoint,
        json={"query": swql},
        auth=HTTPBasicAuth(username, password),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    return resp.json().get("results", [])
