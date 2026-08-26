"""clients/swim.py — DNAC Software Image Management (SWIM) client.

Wraps `dnac.software_image_management_swim` for the golden-image
distribution/activation feature (see /software in routers/pages.py,
utils/swim_scheduler.py). Split out from clients/dnac.py rather than added
there because it carries this feature's entire mutating DNAC surface and
deserves the same auditable-narrowness treatment clients/solarwinds.py got
for its one write verb — tests/test_swim.py greps this module for exactly
the two mutating SDK calls used (trigger_software_image_distribution /
trigger_software_image_activation) and fails the build if a broader
passthrough is ever introduced.

Confirmed by reading the actual payload/JSON-schema validators shipped in
every installed `dnacentersdk` version (2.3.5.3 through 3.1.6.0) — not
guessed:
  * `trigger_software_image_distribution(payload=[{"deviceUuid","imageUuid"}])`
    → POST /dna/intent/api/v1/image/distribution. One call can carry many
    devices; this app submits one device per call so each job_devices row
    maps to exactly one DNAC call and one task id (see swim_scheduler.py for
    why — per-device retry/cancel bookkeeping stays simple that way).
  * `trigger_software_image_activation(schedule_validate=bool,
    payload=[{"deviceUuid","imageUuidList","smuImageUuidList",
    "activateLowerImageVersion","deviceUpgradeMode","distributeIfNeeded"}])`
    → POST /dna/intent/api/v1/image/activation/device. Reboots the device.
  * Neither call, nor the newer v3.1.x bulk endpoints
    (`/networkDeviceImages/distribute|activate/bulk`), nor the generic
    `dnac.task` category, expose any schedule-for-later or cancel/abort
    capability — confirmed exhaustively, not assumed. DNAC's own "Schedule
    Now/Later" GUI is backed by a separate, undocumented endpoint
    (`POST /api/v1/scheduled-job`) this app deliberately does not use for
    v1 — see the plan's fast-follow note. There is likewise no DNAC-side
    cancel: once a device is submitted here, it cannot be stopped through
    any API, which is why utils/swim_scheduler.py's "cancel" only ever means
    "stop submitting devices that haven't been sent yet".
  * **No task-naming field exists anywhere in the public SWIM trigger
    surface either** — checked every SWIM POST/PUT in Cisco's own published
    OpenAPI spec (Catalyst Center Intent API 3.1.6: the old single-device
    endpoints above, the newer bulk ones, and the newer single-device
    `/networkDeviceImages/{id}/distribute|activate`), and none accept a
    name/description/label. This is why jobs created through this app show
    up unnamed in DNAC's own Provision > Inventory > Image Update Status
    screen (confirmed with the user, 2026-08-13) — it isn't something this
    app's request is missing, DNAC's public API has nowhere to put it. The
    one place a name does exist is the same undocumented `scheduled-job`
    wrapper mentioned above (its payload has a `description` field, almost
    certainly what backs DNAC's own GUI-created task names) — so
    investigating that endpoint would resolve naming and native scheduling
    together, not two separate efforts. Deliberately not pursued for now
    (user decision, 2026-08-13); this app's own job list/detail pages
    (`/software/distribution`, `/software/activation`) remain the place to
    identify a job by name in the meantime.

`get_network_device_image_updates` is per-device *update-job* status
(`FAILURE|SUCCESS|IN_PROGRESS|PENDING`, filterable by `network_device_id`
and a `start_time`/`end_time` window) — a far better progress-tracking
primitive than parsing DNAC's generic task tree, since it's already keyed by
device and carries a clear terminal/non-terminal status. It is historical,
not job-scoped, so `poll_device_status` always passes `start_time` (this
job's own submission instant) to exclude a device's rows from any earlier
job that happened to touch the same device.

`get_assigned_products` (the image/device compatibility gate backing job
creation) is built on
`retrieves_network_device_product_names_assigned_to_a_software_image`, whose
response shape was pulled directly from Cisco's own published OpenAPI spec
(Catalyst Center Intent API 3.1.6) rather than inferred from the SDK's
docstring — an earlier version of this function guessed a singular
`productId` field that doesn't exist (the real field is `productIds`, a
list) and filtered to `assigned=ASSIGNED` only, which undercounted devices
whose compatibility came from golden-tagging alone. See that function's own
docstring for the full story.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _dictify(obj) -> dict:
    if isinstance(obj, dict):
        return obj
    try:
        return dict(obj)
    except Exception:
        return {}


def _epoch_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


# Mock golden versions keyed by dev.py's MOCK_DEVICES platformIds — deliberately
# a mix of matching and non-matching current versions, so DEV_MODE exercises
# both the compatible and incompatible paths through the job compatibility
# gate without needing a real DNAC instance.
_DEV_GOLDEN_VERSIONS = {
    "C9300-48U": "17.9.3",
    "C9300-24P": "17.9.3",
    "C9500-40X": "17.12.4",
    "C9600-LC-40YL4": "17.12.1",
    "ISR4451-X/K9": "17.9.5",
}

# Human-readable product/family names DNAC would normally supply via
# get_assigned_products() below — mocked here so DEV_MODE exercises the same
# image/device compatibility gate a real instance provides, without needing
# live DNAC access. Two distinct platformIds (C9300-48U/C9300-24P)
# intentionally share one family name, the same many-PIDs-one-family shape
# DNAC's real productName data has.
_DEV_PRODUCT_FAMILIES = {
    "C9300-48U": "Cisco Catalyst 9300 Series Switches",
    "C9300-24P": "Cisco Catalyst 9300 Series Switches",
    "C9500-40X": "Cisco Catalyst 9500 Series Switches",
    "C9600-LC-40YL4": "Cisco Catalyst 9600 Series Switches",
    "ISR4451-X/K9": "Cisco 4000 Series Integrated Services Routers",
}


def trigger_distribution(dnac, device_uuid: str, image_uuid: str) -> str | None:
    """Distribute one image to one device. Returns DNAC's taskId (for
    reference/debugging only — progress tracking uses poll_device_status,
    not this task id, since the update-updates API is the richer source)."""
    from dev import DEV_MODE
    if DEV_MODE:
        return f"mock-task-{device_uuid[:8]}"

    start_time = time.time()
    try:
        resp = dnac.software_image_management_swim.trigger_software_image_distribution(
            payload=[{"deviceUuid": device_uuid, "imageUuid": image_uuid}]
        )
        duration = int((time.time() - start_time) * 1000)
        task_id = getattr(getattr(resp, "response", None), "taskId", None)
        logger.info(f"SWIM distribution triggered for {device_uuid}", extra={
            "target": "DNAC", "action": "SWIM_TRIGGER_DISTRIBUTION",
            "status": 200, "duration_ms": duration,
        })
        return task_id
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        logger.error(f"SWIM distribution trigger failed for {device_uuid}: {e}", extra={
            "target": "DNAC", "action": "SWIM_TRIGGER_DISTRIBUTION",
            "status": 500, "duration_ms": duration,
        })
        raise


def trigger_activation(
    dnac,
    device_uuid: str,
    image_uuid: str,
    *,
    activate_lower_image_version: bool = False,
    device_upgrade_mode: str | None = None,
    distribute_if_needed: bool = False,
    schedule_validate: bool | None = None,
) -> str | None:
    """Activate one image on one device (reboots it). Returns DNAC's taskId
    (reference only, same caveat as trigger_distribution). `smuImageUuidList`
    is deliberately omitted — Software Maintenance Update images are out of
    scope for v1, a documented simplification, not a structural gap."""
    from dev import DEV_MODE
    if DEV_MODE:
        return f"mock-task-{device_uuid[:8]}"

    payload = {
        "deviceUuid": device_uuid,
        "imageUuidList": [image_uuid],
        "smuImageUuidList": [],
        "activateLowerImageVersion": activate_lower_image_version,
        "distributeIfNeeded": distribute_if_needed,
    }
    if device_upgrade_mode:
        payload["deviceUpgradeMode"] = device_upgrade_mode

    start_time = time.time()
    try:
        kwargs = {"payload": [payload]}
        if schedule_validate is not None:
            kwargs["schedule_validate"] = schedule_validate
        resp = dnac.software_image_management_swim.trigger_software_image_activation(**kwargs)
        duration = int((time.time() - start_time) * 1000)
        task_id = getattr(getattr(resp, "response", None), "taskId", None)
        logger.info(f"SWIM activation triggered for {device_uuid}", extra={
            "target": "DNAC", "action": "SWIM_TRIGGER_ACTIVATION",
            "status": 200, "duration_ms": duration,
        })
        return task_id
    except Exception as e:
        duration = int((time.time() - start_time) * 1000)
        logger.error(f"SWIM activation trigger failed for {device_uuid}: {e}", extra={
            "target": "DNAC", "action": "SWIM_TRIGGER_ACTIVATION",
            "status": 500, "duration_ms": duration,
        })
        raise


def list_images(dnac, golden: bool | None = None, site_id: str | None = None) -> list[dict]:
    """Every image DNAC knows about (imported + Cisco.com-suggested),
    optionally filtered to golden-tagged only. Paginated like
    clients/dnac.py's other list functions. Used by the job wizard's image
    picker (defaults to golden=True there, but the picker also offers an
    unfiltered browse — see utils/swim_targeting.py)."""
    from dev import DEV_MODE
    if DEV_MODE:
        if golden is False:
            return []
        # id = platformId here (not a random UUID) so the mock
        # get_assigned_products() below can key off it directly — see that
        # function's DEV_MODE branch.
        return [
            {"id": platform, "name": f"{platform}-golden.bin", "version": version,
             "productNames": [{"productName": _DEV_PRODUCT_FAMILIES.get(platform, platform)}],
             "family": "Switches and Hubs"}
            for platform, version in _DEV_GOLDEN_VERSIONS.items()
        ]

    images, limit, offset = [], 500, 1
    while True:
        try:
            kwargs: dict = {"limit": limit, "offset": offset}
            if golden is not None:
                kwargs["golden"] = golden
            if site_id:
                kwargs["site_id"] = site_id
            page = dnac.software_image_management_swim.returns_list_of_software_images(**kwargs)
            items = page.response if hasattr(page, "response") else page
            if not items:
                break
            images.extend([_dictify(i) for i in items])
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            logger.error(f"SWIM image list fetch failed at offset {offset}: {e}")
            if not images:
                raise
            break
    return images


def list_golden_images(dnac, site_id: str | None = None) -> list[dict]:
    """Convenience wrapper — golden-tagged images only. Backs the job
    wizard's default image filter. First cut pulls global (no site_id)
    golden images grouped by platform — DNAC's golden designation *can* be
    site-scoped, and it's not confirmed this fleet differentiates by site;
    a known simplification to revisit if results look wrong against a real
    instance.

    Each returned image carries an `assigned_products` dict (pid -> product
    name, see get_assigned_products) — the compatibility gate is built from
    this, not from platformId string-matching.
    """
    images = list_images(dnac, golden=True, site_id=site_id)
    return attach_assigned_products(dnac, images)


def get_assigned_products(dnac, image_id: str) -> dict[str, str]:
    """DNAC's own authoritative list of which device product IDs (PIDs —
    the same value a device reports as its own `platformId`) this image
    applies to, each paired with its human-readable product/family name
    (e.g. "Cisco Catalyst 9300 Series Switches").

    Confirmed present on the pinned DNAC version via
    `retrieves_network_device_product_names_assigned_to_a_software_image` —
    this is the authoritative source the distribution/activation
    compatibility gate (routers/swim.py) is built on, replacing an earlier
    model-number-substring heuristic that could tell "looks similar" but
    never "DNAC actually says this image applies to this device" — which is
    what actually matters before pushing an image to a device.

    Response shape confirmed against Cisco's own published OpenAPI spec
    (Catalyst Center Intent API 3.1.6, `retrievesNetworkDeviceProductNames
    AssignedToASoftwareImageResponse` — pulled and inspected directly, not
    guessed from the SDK docstring the way an earlier version of this
    function did): each row carries `productName` plus **`productIds`, a
    LIST of PIDs, not a singular `productId`** — one product name commonly
    covers several exact PIDs. That earlier singular-field guess is why
    this returned empty against a real instance even for images with real,
    correct assignments: the row shape genuinely didn't have the field
    being read.

    No `assigned` filter is applied, deliberately: the endpoint's own spec
    describes `ASSIGNED` as "associated with the given image" and
    `NOT_ASSIGNED` as "have not yet been associated ... but apply to it" —
    both states mean the product applies to this image, and most golden-
    image workflows (tag by device family/role) never touch the separate,
    optional formal-assignment step. Filtering to `ASSIGNED` only, as an
    earlier version of this function did, silently dropped every device
    whose compatibility came from golden-tagging alone rather than that
    extra manual step, undercounting real compatibility.

    Never cached: this backs a safety gate (which devices an operator is
    even allowed to target), not a display value, so it always asks DNAC
    fresh rather than act on a possibly-stale answer — same "live verify
    over local logic" posture as the Firewall Policy Tester. An empty
    result (no assigned products found, or the call failed) is treated by
    callers as "compatibility unknown" and blocks the action — silently
    allowing everything when this can't be determined would defeat the
    entire point of the gate.
    """
    from dev import DEV_MODE
    if DEV_MODE:
        if image_id in _DEV_GOLDEN_VERSIONS:
            return {image_id: _DEV_PRODUCT_FAMILIES.get(image_id, image_id)}
        return {}

    pids: dict[str, str] = {}
    limit, offset = 500, 1
    while True:
        try:
            page = dnac.software_image_management_swim.retrieves_network_device_product_names_assigned_to_a_software_image(
                image_id=image_id, limit=limit, offset=offset,
            )
            items = page.response if hasattr(page, "response") else page
            if not items:
                break
            for row in items:
                d = _dictify(row)
                name = d.get("productName") or ""
                for pid in (d.get("productIds") or []):
                    if pid:
                        pids[pid] = name or pid
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            logger.warning(f"Assigned-products fetch failed for image {image_id}: {e}", extra={
                "target": "DNAC", "action": "SWIM_ASSIGNED_PRODUCTS", "status": 500,
            })
            break
    return pids


def attach_assigned_products(dnac, images: list[dict]) -> list[dict]:
    """Fetch and attach `assigned_products` (see get_assigned_products) onto
    each image dict in place. Bounded parallel fetch — one extra call per
    image — mirroring clients/dnac.py's per-site parallel-fetch pattern
    (_build_via_per_site_parallel) for the same class of N+1 problem."""
    if not images:
        return images

    from concurrent.futures import ThreadPoolExecutor

    def _fetch(image: dict) -> None:
        image_id = image.get("id") or image.get("imageId") or image.get("name")
        image["assigned_products"] = get_assigned_products(dnac, image_id) if image_id else {}

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(_fetch, images))
    return images


def poll_device_status(dnac, device_id: str, since: datetime) -> dict:
    """Latest known DNAC-reported status for `device_id`'s image update,
    restricted to rows at/after `since` (this job's own submission instant —
    see the module docstring for why this filter matters).

    Returns {"status": "success"|"failed"|"in_progress"|"pending",
             "failure_reason": str|None}. "pending" means DNAC has no rows
    yet for this device since `since` — not an error, just "nothing to
    report" (the caller keeps polling).
    """
    from dev import DEV_MODE
    if DEV_MODE:
        # Deterministic on device_id so repeated polls (and a resumed job)
        # see a stable outcome rather than re-rolling every call. ~1 in 10
        # "fails" so DEV_MODE exercises the error-handling path too.
        if hash(device_id) % 10 == 0:
            return {"status": "failed", "failure_reason": "[MOCK] Simulated image validation failure"}
        return {"status": "success", "failure_reason": None}

    try:
        resp = dnac.software_image_management_swim.get_network_device_image_updates(
            network_device_id=device_id,
            start_time=_epoch_ms(since),
            limit=50,
        )
        rows = [_dictify(r) for r in (resp.response if hasattr(resp, "response") else resp) or []]
    except Exception as e:
        logger.warning(f"SWIM status poll failed for {device_id}: {e}", extra={
            "target": "DNAC", "action": "SWIM_POLL_STATUS", "status": 500,
        })
        return {"status": "pending", "failure_reason": None}

    if not rows:
        return {"status": "pending", "failure_reason": None}

    statuses = {(r.get("status") or "").upper() for r in rows}
    if "FAILURE" in statuses:
        failed_row = next((r for r in rows if (r.get("status") or "").upper() == "FAILURE"), {})
        reason = failed_row.get("failureReason") or failed_row.get("statusMessage") or "Unknown failure"
        return {"status": "failed", "failure_reason": reason}
    if "SUCCESS" in statuses:
        return {"status": "success", "failure_reason": None}
    if statuses & {"IN_PROGRESS", "PENDING"}:
        return {"status": "in_progress", "failure_reason": None}
    return {"status": "pending", "failure_reason": None}
