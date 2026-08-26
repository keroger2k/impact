"""utils/device_sites.py — resolve a DNAC device to its short site code.

DNAC's device inventory has no native `siteId`/`site_code` field — site
association only exists via the separately-built `device_site_map` cache
(`clients.dnac.build_device_site_map`, a device-id -> full hierarchy-path
string). `resolve_site_code()` is the one place in the codebase that turns
that hierarchy string (or, failing that, the hostname) into the short code
(`K024`, `SDCZ`, ...) used everywhere else.

Shared unchanged by every SWIM caller that needs a device's site — e.g.
utils/swim_targeting.py snapshots a site_code onto each job_devices row at
job-creation time, so a job's per-site batching plan is stable even if the
site map cache changes later.

"Which site is this device in" should never be answered a second way.
"""
from __future__ import annotations

from utils.site_code import site_code_from_hostname, site_code_strict


def resolve_site_code(
    device_id: str, hostname: str | None, device_site_map: dict[str, str]
) -> tuple[str, str]:
    """Return (code, source). `source` is one of:
      'device_site_map' — resolved from DNAC's own site assignment (authoritative)
      'hostname'         — DNAC has no site assignment; fell back to the
                            hostname-embedded code convention
      'unresolved'        — neither worked; caller should bucket this device
                            under an explicit "UNKNOWN" site key rather than
                            silently dropping it from per-site throttling.
    """
    site_name = device_site_map.get(device_id, "")
    if site_name:
        code = site_code_strict(site_name)
        if code:
            return code, "device_site_map"

    code = site_code_from_hostname(hostname or "")
    if code:
        return code, "hostname"

    return "", "unresolved"
