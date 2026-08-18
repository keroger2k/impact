"""clients/solarwinds.py — SolarWinds Orion SWIS (SWQL) client.

Thin wrapper over the Orion Information Service's JSON endpoints. Three
operations are exposed:

  - `query()` — POSTs a SWQL SELECT and returns the result rows. Backs every
    report on the `/reports` pages.
  - `suppress_alerts()` / `resume_alerts()` — the app's deliberate write
    verbs, both on `Orion.AlertSuppression`: the first mutes alerts for an
    entity, the second cancels an active/pending mute early. Together they
    back the Maintenance Mode Scheduler report's schedule + cancel actions,
    gated behind `SOLARWINDS_WRITES_ENABLED` at the router layer (see
    routers/reports.py). See `suppress_alerts()`'s docstring for why this
    entity specifically, and not the classic `Orion.Nodes/Unmanage` verb
    this was originally built against — short version: Unmanage doesn't
    show up in SolarWinds' own "Manage Maintenance Schedules" screen
    either, and getting an entry to appear there requires a cookie-session
    web API this app doesn't have a login flow for.

There is no generic "invoke any entity/verb" passthrough — the write surface
is exactly these two hardcoded calls, kept as structurally narrow and
grep-able as the F5 client's GET-only guarantee is (`clients/f5.py`), just
inverted: instead of zero mutating verbs, there is a small, fixed, explicitly
named set, rather than a parameterized function that could reach any verb.

Auth: unlike F5 (`clients/f5.py`), this now uses a dedicated service account
read from the environment (`SOLARWINDS_USERNAME`/`SOLARWINDS_PASSWORD`)
rather than the logged-in user's own AD credentials — the Orion instance
moved off per-user AD auth, so there's no longer a live user credential to
pass through per call. SolarWinds expects NTLM-style `DOMAIN\\username`, so a
domain prefix is added unless the configured username already supplied one
(`user@domain` or `domain\\user`).
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


def _credentials() -> HTTPBasicAuth:
    username = os.getenv("SOLARWINDS_USERNAME", "").strip()
    password = os.getenv("SOLARWINDS_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("SOLARWINDS_USERNAME/SOLARWINDS_PASSWORD are not configured")
    return HTTPBasicAuth(_format_username(username), password)


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


def query(swql: str, timeout: int | None = None) -> list[dict]:
    """Run a SWQL SELECT against Orion and return the result rows.

    `timeout` overrides SOLARWINDS_TIMEOUT (default 180s) for this call. That
    default is sized for the CDRL49 report's heavy fleet-wide queries; a
    caller backing an interactive control (e.g. the Bandwidth report's
    interface dropdown) should pass something short so a slow/unreachable
    Orion surfaces as a quick inline message instead of a hung UI element.
    """
    if timeout is None:
        timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    resp = requests.post(
        _endpoint("Query"),
        json={"query": swql},
        auth=_credentials(),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    _raise_for_error(resp, "query")
    return resp.json().get("results", [])


def suppress_alerts(
    uri: str, start: datetime, end: datetime, timeout: int | None = None,
) -> None:
    """Mute alerts for one entity between `start` and `end`.

    The app's one write verb — see the module docstring for why it's kept
    this narrow. Invokes `Orion.AlertSuppression/SuppressAlerts`, confirmed
    against a real instance rather than guessed: `Metadata.Verb` lists
    SuppressAlerts/ResumeAlerts/GetAlertSuppressionState on
    `Orion.AlertSuppression`, and a live test call with this exact argument
    shape — `[[uri], start.isoformat(), end.isoformat()]` — actually
    suppressed alerts (confirmed via a follow-up GetAlertSuppressionState
    read and SolarWinds' own audit log, which recorded "scheduled muting
    alerts on <node> ... because 'Unknown' reason").

    `uri` is the target entity's own SWIS Uri (e.g. from `SELECT Uri FROM
    Orion.Nodes WHERE ...`) — NOT a NodeID. This verb is keyed by Uri, unlike
    the classic `Orion.Nodes/Unmanage` verb (which used a `"N:<id>"`
    netObjectId string and was this function's original implementation).

    This mutes alerts only ("Mute alerts on this object" in Orion's own
    Scheduled Maintenance dialog) — it does not stop polling, and critically,
    it does **not** create an entry visible in Settings > All Settings >
    Manage Maintenance Schedules. That screen is backed by a separate
    mechanism: SolarWinds' own audit log shows its entries as "assigned new
    entity to '<name>' schedule" (a named, persistent object), while
    AlertSuppression calls are logged generically with no schedule name — a
    real `Orion.MaintenancePlan` + `Orion.MaintenancePlanAssignment` SWIS
    Create was also tried and tested working at the database level (real
    IDs returned, no errors) but produced *zero* audit trail and never
    appeared on that screen either, meaning direct SWIS writes bypass
    whatever service actually wires a plan into that UI. Getting an entry to
    actually appear there requires the Orion Web Console's own internal
    REST API (`/api2/schedules/createOneTime`), which needs a cookie+XSRF
    web session (confirmed: plain Basic Auth gets a 401) this app doesn't
    have a login flow for — a deliberate scope decision, not an oversight.

    `start`/`end` must be timezone-aware — callers should pass UTC
    datetimes (see utils/maintenance_report.py, which converts the UTC ISO
    strings the browser submits).
    """
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("start and end must be timezone-aware")

    if timeout is None:
        timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    args = [[uri], start.isoformat(), end.isoformat()]
    resp = requests.post(
        _endpoint("Invoke/Orion.AlertSuppression/SuppressAlerts"),
        json=args,
        auth=_credentials(),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    _raise_for_error(resp, "suppress alerts")


def resume_alerts(uri: str, timeout: int | None = None) -> None:
    """Cancel an active or pending alert suppression for one entity early.

    Invokes `Orion.AlertSuppression/ResumeAlerts` — confirmed to exist via a
    real `Metadata.Verb` query (`SuppressAlerts`/`ResumeAlerts`/
    `GetAlertSuppressionState` are the only three verbs on this entity), but
    the single-argument shape here (`[[uri]]`, no start/end) is inferred by
    symmetry with `SuppressAlerts` and with how `Remanage` relates to
    `Unmanage` on the classic verb — not yet exercised with a real call. A
    first-run signature mismatch should surface via the HTTP error detail
    below rather than fail silently.

    `uri` is the same entity Uri passed to the original `suppress_alerts()`
    call.
    """
    if timeout is None:
        timeout = int(os.getenv("SOLARWINDS_TIMEOUT", "180"))

    resp = requests.post(
        _endpoint("Invoke/Orion.AlertSuppression/ResumeAlerts"),
        json=[[uri]],
        auth=_credentials(),
        verify=verify_ssl(),
        timeout=timeout,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    _raise_for_error(resp, "resume alerts")
