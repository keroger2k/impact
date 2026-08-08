"""utils/maintenance_report.py — Maintenance Mode Scheduler (SolarWinds Orion Unmanage).

Backs the paste-a-list Maintenance Mode Scheduler report: the user pastes
`<node>,<start-time>,<stop-time>` rows, the browser comma-splits them and
converts each local start/stop into UTC before ever hitting the server (see
templates/pages/reports_maintenance_content.html), and this module owns the
three server-side steps — parse/validate, resolve node names to Orion
NodeIDs, and schedule one already-resolved node. routers/reports.py owns
per-row SSE progress; keeping each step here (rather than inline in the
router) makes them independently testable and mirrors how
utils/bandwidth_report.py separates SWQL resolution from
routers/reports.py's HTTP surface.

Node resolution is a single batched SWQL query for every distinct name in
the paste, not one query per row — same reasoning as
utils/device_comparison_report.py's identity matching: a name that matches
zero or 2+ Orion nodes is never silently guessed, since this schedules a
real write against whatever NodeID it resolves to.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import clients.solarwinds as solarwinds
from utils.bandwidth_report import short_hostname

# Same charset allowlist as utils/bandwidth_report.py's _SWQL_NAME_RE and
# routers/firewall.py's _CLI_NAME_RE — untrusted web input reaching a SWQL
# query string. This repo duplicates this trio per-module rather than
# centralizing it, so following that precedent here too.
_SWQL_NAME_RE = re.compile(r"^[\w .:/-]{1,63}$")


class RowError(ValueError):
    """A pasted row failed validation before any network call."""


def _escape_literal(value: str) -> str:
    return value.replace("'", "''")


def _validate_node_name(value: str) -> str:
    name = short_hostname(value)
    if not name or not _SWQL_NAME_RE.match(name):
        raise RowError(f"invalid node name: {value!r}")
    return name


def _parse_utc(value: str, label: str) -> datetime:
    # The browser sends `Date.toISOString()` output ("...Z"); fromisoformat()
    # only accepts a numeric offset before Python 3.11, so normalize "Z"
    # ourselves rather than assuming a modern interpreter.
    try:
        dt = datetime.fromisoformat((value or "").strip().replace("Z", "+00:00"))
    except ValueError:
        raise RowError(f"{label} is not a valid timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_rows(raw_rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Validate posted rows before any network call.

    Returns `(valid, errors)`. `valid` rows carry a normalized `node` name
    plus tz-aware UTC `start`/`stop` datetimes; `errors` rows carry the
    original node text plus a `message`. One malformed row never blocks the
    rest — same per-item isolation as routers/import_.py's process_entry.
    """
    valid: list[dict] = []
    errors: list[dict] = []
    for raw in raw_rows:
        node_in = (raw.get("node") or "").strip()
        try:
            node = _validate_node_name(node_in)
            start = _parse_utc(raw.get("start_utc", ""), "start time")
            stop = _parse_utc(raw.get("stop_utc", ""), "stop time")
            if stop <= start:
                raise RowError("stop time must be after start time")
        except RowError as e:
            errors.append({"node": node_in, "message": str(e)})
            continue
        valid.append({"node": node, "start": start, "stop": stop})
    return valid, errors


def resolve_node_ids(names: list[str], username: str, password: str) -> dict[str, dict]:
    """Resolve distinct node (Caption) names to Orion NodeIDs, one batched query.

    Returns a map of lowercased name -> `{"node_id": int}` on a unique
    match, or `{"error": "..."}` on zero or 2+ matches.
    """
    distinct = sorted({n.lower(): n for n in names}.values())
    if not distinct:
        return {}

    clauses = " OR ".join(f"Caption = '{_escape_literal(n)}'" for n in distinct)
    swql = f"SELECT NodeID, Caption FROM Orion.Nodes WHERE {clauses}"
    rows = solarwinds.query(swql, username, password)

    by_name: dict[str, list[dict]] = {}
    for row in rows:
        caption = (row.get("Caption") or "").lower()
        by_name.setdefault(caption, []).append(row)

    result: dict[str, dict] = {}
    for name in distinct:
        matches = by_name.get(name.lower(), [])
        if not matches:
            result[name.lower()] = {"error": "not found in SolarWinds"}
        elif len(matches) > 1:
            captions = ", ".join(m.get("Caption") or "?" for m in matches)
            result[name.lower()] = {"error": f"ambiguous — matches {captions}"}
        else:
            result[name.lower()] = {"node_id": matches[0]["NodeID"]}
    return result


def schedule_one(node_id: int, start: datetime, stop: datetime, username: str, password: str) -> None:
    """Schedule maintenance for one already-resolved node."""
    solarwinds.unmanage_node(node_id, start, stop, username, password)
