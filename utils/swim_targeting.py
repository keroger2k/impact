"""utils/swim_targeting.py — device-targeting engine for SWIM jobs.

Backs all three input modes the job wizard offers (see CLAUDE.md plan
§4): a filter+multi-select picker, a site+platform/family group-select, and
a CSV paste. Modes (a)/(b) share `search_devices()` — they differ only in
wizard UI affordances (a faceted table vs. two dropdowns + "target
everything"), not in how devices are actually resolved. Mode (c) has its
own `resolve_csv_lines()`.

Everything here reads the already-warmed `devices` cache (no live DNAC
calls) — this module is deliberately synchronous and cheap, since the job
wizard needs to stay responsive at 2,600-device scale. `routers/swim.py`
wraps these in the async request handlers.
"""
from __future__ import annotations

from collections import Counter

from utils.bandwidth_report import short_hostname
from utils.device_sites import resolve_site_code

# Hard sanity cap, matching CONFIG_MAX_DEVICES's pattern for the SSH command
# runner — but higher, since a 2,600-device job is the explicit use case here,
# not an edge case. Overridable so an operator can raise/lower it without a
# code change.
import os

MAX_DEVICES_PER_JOB = int(os.getenv("SWIM_MAX_DEVICES_PER_JOB", "3000"))


def _q(field: str | None, val: str | None) -> bool:
    return bool(val) and val.lower() in (field or "").lower()


def list_facets(devices: list[dict], device_site_map: dict[str, str]) -> dict:
    """Distinct site codes, platform IDs, and families present in the
    devices cache — populates the picker's filter controls."""
    site_codes: set[str] = set()
    platforms: set[str] = set()
    families: set[str] = set()
    for d in devices:
        code, _source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
        if code:
            site_codes.add(code)
        if d.get("platformId"):
            platforms.add(d["platformId"])
        family = d.get("family") or d.get("deviceFamily")
        if family:
            families.add(family)
    return {
        "site_codes": sorted(site_codes),
        "platforms": sorted(platforms),
        "families": sorted(families),
    }


def search_devices(
    devices: list[dict],
    device_site_map: dict[str, str],
    *,
    site_codes: list[str] | None = None,
    platforms: list[str] | None = None,
    families: list[str] | None = None,
    hostname_contains: str | None = None,
    reachability: str | None = None,
) -> list[dict]:
    """Filter the devices cache by the wizard's criteria. Shared by mode (a)
    (filter picker) and mode (b) (site+family auto-target — pass a single
    site_code/platform as one-element lists). Returns raw device dicts as
    they came from the cache, unmodified — callers snapshot the fields they
    need via snapshot_for_job()."""
    site_set = {s.upper() for s in site_codes} if site_codes else None
    platform_set = set(platforms) if platforms else None
    family_set = set(families) if families else None

    out = []
    for d in devices:
        if platform_set and d.get("platformId") not in platform_set:
            continue
        family = d.get("family") or d.get("deviceFamily")
        if family_set and family not in family_set:
            continue
        if hostname_contains and not _q(d.get("hostname"), hostname_contains):
            continue
        if reachability:
            if reachability.lower() == "reachable" and d.get("reachabilityStatus") != "Reachable":
                continue
            if reachability.lower() == "unreachable" and d.get("reachabilityStatus") == "Reachable":
                continue
        if site_set is not None:
            code, _source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
            if code.upper() not in site_set:
                continue
        out.append(d)
    return out


def resolve_csv_lines(
    lines: list[str], devices: list[dict]
) -> tuple[list[dict], list[str]]:
    """Resolve pasted hostname-or-IP lines against the devices cache.

    Format: one hostname-or-management-IP per line, extra CSV columns
    ignored (only the first comma-separated field is read, so a fuller
    export — hostname,site,ip — still works by taking its first column).
    Returns (matched_devices, unmatched_lines).
    """
    by_ip = {d.get("managementIpAddress"): d for d in devices if d.get("managementIpAddress")}
    by_short_hostname: dict[str, dict] = {}
    for d in devices:
        h = short_hostname(d.get("hostname") or "")
        if h:
            by_short_hostname.setdefault(h.lower(), d)

    matched: list[dict] = []
    unmatched: list[str] = []
    seen_ids: set[str] = set()
    for raw in lines:
        token = raw.strip()
        if not token:
            continue
        first_field = token.split(",")[0].strip()
        if not first_field:
            continue

        d = by_ip.get(first_field) or by_short_hostname.get(short_hostname(first_field).lower())
        if d and d.get("id") not in seen_ids:
            matched.append(d)
            seen_ids.add(d.get("id"))
        elif not d:
            unmatched.append(token)
    return matched, unmatched


def snapshot_for_job(devices: list[dict], device_site_map: dict[str, str]) -> list[dict]:
    """Shape raw device-cache dicts into job_devices rows (clients.swim_jobs
    .add_devices' expected shape), resolving and snapshotting each device's
    site code at job-creation time — a stable record even if the site map
    cache changes later."""
    rows = []
    for d in devices:
        code, source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
        rows.append({
            "device_id": d.get("id"),
            "hostname": d.get("hostname"),
            "management_ip": d.get("managementIpAddress"),
            "platform_id": d.get("platformId"),
            "family": d.get("family") or d.get("deviceFamily"),
            "site_code": code or "UNKNOWN",
            "site_code_source": source,
            "current_software_version": d.get("softwareVersion"),
        })
    return rows


def homogeneity_warning(rows: list[dict]) -> str | None:
    """Non-blocking nudge: this job's devices should typically be one
    platform (same device type, per the original ask). Returns a
    human-readable warning if more than one distinct platformId is present,
    or None if the set is homogeneous."""
    counts = Counter(r.get("platform_id") or "(unknown)" for r in rows)
    if len(counts) <= 1:
        return None
    parts = ", ".join(f"{p} ({n})" for p, n in counts.most_common())
    return f"This job targets {len(counts)} platforms: {parts} — confirm this is intentional."


def unresolved_site_count(rows: list[dict]) -> int:
    return sum(1 for r in rows if r.get("site_code_source") == "unresolved")
