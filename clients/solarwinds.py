"""clients/solarwinds.py — SolarWinds Orion SWIS (SWQL) client.

Thin wrapper over the Orion Information Service's JSON endpoints. Two
operations are exposed:

  - `query()` — POSTs a SWQL SELECT and returns the result rows. Backs every
    report on the `/reports` pages.
  - `unmanage_node()` — the app's **one** deliberate write verb, invoking
    Orion's `Orion.Nodes/Unmanage` to schedule maintenance mode for a node.
    Backs the Maintenance Mode Scheduler report, gated behind
    `SOLARWINDS_WRITES_ENABLED` at the router layer (see routers/reports.py).

There is no generic "invoke any entity/verb" passthrough — the write surface
is exactly this one hardcoded call, kept as structurally narrow and
grep-able as the F5 client's GET-only guarantee is (`clients/f5.py`), just
inverted: instead of zero mutating verbs, there is exactly one, explicit and
named, rather than a parameterized function that could reach any verb.

Auth: like F5 (`clients/f5.py`), this uses the logged-in user's own AD
credentials via HTTP Basic Auth rather than a dedicated service account —
passed in per call, never read from the environment. SolarWinds expects
NTLM-style `DOMAIN\\username`, so a domain prefix is added unless the caller
already supplied one (`user@domain` or `domain\\user`).
"""
import os
from datetime import datetime

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


def _raise_for_error(resp: requests.Response, action: str) -> None:
    if resp.status_code < 400:
        return
    # raise_for_status() alone drops the response body, which is where Orion
    # puts the actual error detail ("Cannot resolve property X", "no viable
    # alternative at input '*'", or an Unmanage failure's Message field).
    # Losing that turns a one-line schema typo or bad NodeID into a blind
    # guessing exercise — it's why scripts/solarwinds_discover_site_properties.py
    # had to bypass query() entirely. Keep the detail for both verbs.
    detail = resp.text.strip()[:500]
    raise RuntimeError(f"SolarWinds {action} failed (HTTP {resp.status_code}): {detail}")


def _endpoint(frag: str) -> str:
    port = os.getenv("SOLARWINDS_PORT", "17774")
    return f"{_base_url()}:{port}/SolarWinds/InformationService/v3/Json/{frag}"


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

    if timeout is None:
        timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    resp = requests.post(
        _endpoint("Query"),
        json={"query": swql},
        auth=HTTPBasicAuth(_format_username(username), password),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    _raise_for_error(resp, "query")
    return resp.json().get("results", [])


def unmanage_node(
    node_id: int, start: datetime, end: datetime,
    username: str, password: str, timeout: int | None = None,
) -> None:
    """Schedule Orion maintenance mode for one node between `start` and `end`.

    The app's one write verb — see the module docstring for why it's kept
    this narrow. Invokes `Orion.Nodes/Unmanage` with the exact positional
    argument shape SolarWinds' own reference client uses (confirmed against
    `solarwinds/orionsdk-python`'s `samples/unmanage_node.py` and
    `SwisClient.invoke`, not guessed): `[netObjectId, start, end,
    isRelative]`, where `netObjectId` is `"N:<NodeID>"` and `isRelative` is
    `False` so `start`/`end` are treated as absolute times rather than a
    duration.

    `start`/`end` must be timezone-aware — callers should pass UTC
    datetimes (see utils/maintenance_report.py, which converts the UTC ISO
    strings the browser submits). This hasn't yet been exercised against
    this org's specific Orion version, so a first-run signature mismatch
    should surface via the HTTP error detail below rather than fail silently.
    """
    if not username or not password:
        raise RuntimeError("SolarWinds credentials are required")
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("start and end must be timezone-aware")

    if timeout is None:
        timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    args = [f"N:{node_id}", start.isoformat(), end.isoformat(), False]
    resp = requests.post(
        _endpoint("Invoke/Orion.Nodes/Unmanage"),
        json=args,
        auth=HTTPBasicAuth(_format_username(username), password),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    _raise_for_error(resp, "unmanage")
