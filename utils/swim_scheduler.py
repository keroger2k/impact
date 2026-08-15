"""utils/swim_scheduler.py — two-level concurrency execution/resume engine
for SWIM distribution/activation jobs.

This is the core of the feature (see the plan's §5). It answers the actual
operational problem: distributing an image to many devices at one site
saturates that site's WAN circuit, so concurrency must be bounded **per
site**, while different sites should proceed in parallel. At the same time,
this app's "no background pollers" rule means the whole execution loop only
runs for the lifetime of an open SSE connection — nothing here is a
scheduler that keeps running unattended. `run_job()` is a resumable async
generator: every call re-derives what still needs doing from
`clients.swim_jobs`' persisted `job_devices` rows, never from in-memory
state, so closing a browser tab mid-job and reopening it later picks back up
correctly with no double-submission.

Two concurrency levels, held for **different durations** — this is the part
that's easy to get backwards and defeats the whole feature if you do:

  * A **per-site** `asyncio.Semaphore` (capacity = that site's circuit-derived
    concurrency from `clients.swim_jobs.list_site_limits()` — see
    `utils/swim_site_circuit.py` — clamped to never exceed the operator's
    `jobs.site_concurrency` ceiling; falls back to the flat ceiling itself for
    jobs created before that feature existed, see `legacy_job` below; fresh
    per `run_job()` call, never shared across jobs — see the module
    docstring's "known v1 limitation" note below) is held for a device's
    **entire lifecycle**, submission through terminal DNAC status. The
    WAN-saturation risk is the download itself, which happens over the whole
    distribution window, not at the moment of the trigger call — releasing
    the site slot right after submitting would let unlimited devices be
    simultaneously mid-distribution at one site, which is exactly what this
    feature exists to prevent.
  * The **global** `GLOBAL_SEM` (process-wide, module-level singleton, sized
    from `SWIM_GLOBAL_CONCURRENCY`) is held only **around each individual
    DNAC HTTP call** — the submission POST, and each periodic poll GET. If
    it were held for a device's whole lifecycle instead, a worker asleep
    between polls (>99% of a device's lifetime) would occupy a global slot
    doing nothing, capping *total in-flight devices across the whole job* at
    the global cap regardless of how many sites are involved. `GLOBAL_SEM`
    is process-wide rather than per-job specifically so two jobs running at
    once can't each independently believe they have their own N slots and
    stack past `clients/dnac.py`'s actual DNAC connection pool capacity.

Known v1 limitation, accepted deliberately: per-site semaphores are built
fresh for each `run_job()` call and are **not** shared across concurrently
running jobs. If two different jobs both target the same site at the same
time, each enforces its own `site_concurrency` independently, so the site
could see up to `site_concurrency x number of concurrent jobs` devices in
flight. Coordinating per-site throttling *across* jobs would need a shared,
site-keyed semaphore registry with cross-job capacity negotiation — real
complexity for a scenario that should be rare given jobs are operator-driven
one at a time.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

import clients.swim as swim_client
import clients.swim_jobs as swim_jobs

logger = logging.getLogger(__name__)

SWIM_POLL_INTERVAL = int(os.getenv("SWIM_POLL_INTERVAL", "15"))
# Generous on purpose: releasing a site slot before DNAC reports a terminal
# status is unsafe (see module docstring), so the safety valve that finally
# gives up on a stuck poll has to be sized in hours, not minutes.
SWIM_POLL_TIMEOUT_HOURS = int(os.getenv("SWIM_POLL_TIMEOUT_HOURS", "6"))

_SITE_CONCURRENCY_CEILING = 10

GLOBAL_SEM = asyncio.Semaphore(int(os.getenv("SWIM_GLOBAL_CONCURRENCY", "20")))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_since(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def _submit(dnac, job: dict, row: dict) -> str | None:
    """Fire the one DNAC trigger call for this job's type. Runs the blocking
    SDK call in the default executor, same pattern as routers/import_.py's
    _wait_for_discovery. Returns DNAC's taskId (reference only)."""
    loop = asyncio.get_event_loop()
    if job["job_type"] == "distribution":
        return await loop.run_in_executor(
            None, lambda: swim_client.trigger_distribution(dnac, row["device_id"], job["image_uuid"])
        )
    return await loop.run_in_executor(
        None,
        lambda: swim_client.trigger_activation(
            dnac, row["device_id"], job["image_uuid"],
            activate_lower_image_version=bool(job.get("activate_lower_image_version")),
            device_upgrade_mode=job.get("device_upgrade_mode"),
            distribute_if_needed=bool(job.get("distribute_if_needed")),
            schedule_validate=(None if job.get("schedule_validate") is None else bool(job["schedule_validate"])),
        ),
    )


async def _poll_once(dnac, device_id: str, since: datetime) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: swim_client.poll_device_status(dnac, device_id, since))


async def _run_cleanup(row: dict, ssh_username: str, ssh_password: str) -> dict:
    """Run `install remove inactive` on one device via SSH before its
    distribution trigger fires — see utils/device_ssh.py for why this has
    to be a device-CLI operation rather than a DNAC API call (there is no
    flash-management endpoint anywhere in DNAC's SWIM API surface, checked
    directly against Cisco's own published spec). Not gated by GLOBAL_SEM:
    that semaphore bounds concurrent DNAC HTTP calls specifically, and SSH
    to a device doesn't touch DNAC's connection pool at all."""
    from utils.device_ssh import guess_device_type, run_flash_cleanup
    loop = asyncio.get_event_loop()
    device_type = guess_device_type(row.get("platform_id") or "")
    return await loop.run_in_executor(
        None,
        lambda: run_flash_cleanup(row["management_ip"], ssh_username, ssh_password, device_type),
    )


async def _device_worker(
    dnac, job: dict, row: dict, site_sem: asyncio.Semaphore, queue: asyncio.Queue, skip_submit: bool,
    ssh_username: str | None = None, ssh_password: str | None = None,
):
    """Run one device row to a terminal state (or until cancelled/interrupted).

    `skip_submit=True` for rows resumed in status 'in_progress' — they were
    already submitted in a previous run; this worker only polls (flash
    cleanup, if enabled, only ever runs once per device — on a resume from
    'in_progress' the device is already past that point).
    """
    async with site_sem:
        # Race safety: a concurrent cancel-queued call may have flipped this
        # row to 'cancelled' between when the job list was loaded and now.
        current = swim_jobs.get_device_status(row["id"])
        if current == "cancelled":
            return
        if current not in ("queued", "submitting", "in_progress"):
            return  # already terminal somehow — nothing to do

        since = _parse_since(row.get("submitted_at") or row.get("created_at"))

        if not skip_submit:
            if job.get("flash_cleanup"):
                await queue.put({
                    "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                    "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                    "status": "submitting", "message": "Running flash cleanup (install remove inactive)…",
                })
                cleanup = await _run_cleanup(row, ssh_username or "", ssh_password or "")
                if cleanup["status"] != "success":
                    reason = f"Flash cleanup failed: {cleanup.get('error') or 'unknown error'}"
                    swim_jobs.set_device_status(row["id"], "failed", error_message=reason[:500], completed_at=_now_iso())
                    await queue.put({
                        "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                        "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                        "status": "failed", "message": reason,
                    })
                    return
                await queue.put({
                    "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                    "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                    "status": "submitting", "message": "Flash cleanup complete",
                })

            swim_jobs.set_device_status(row["id"], "submitting")
            try:
                async with GLOBAL_SEM:
                    task_id = await _submit(dnac, job, row)
            except Exception as e:
                swim_jobs.set_device_status(row["id"], "failed", error_message=str(e)[:500], completed_at=_now_iso())
                await queue.put({
                    "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                    "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                    "status": "failed", "message": f"Submit failed: {str(e)[:200]}",
                })
                return
            since = datetime.now(timezone.utc)
            swim_jobs.set_device_status(row["id"], "in_progress", dnac_task_id=task_id, submitted_at=since.isoformat())
            await queue.put({
                "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                "status": "in_progress", "message": "Submitted to DNAC",
            })

        deadline = asyncio.get_event_loop().time() + SWIM_POLL_TIMEOUT_HOURS * 3600
        while True:
            await asyncio.sleep(SWIM_POLL_INTERVAL)
            async with GLOBAL_SEM:
                result = await _poll_once(dnac, row["device_id"], since)

            if result["status"] == "success":
                swim_jobs.set_device_status(row["id"], "success", completed_at=_now_iso(), last_polled_at=_now_iso())
                await queue.put({
                    "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                    "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                    "status": "success", "message": "Completed successfully",
                })
                return
            if result["status"] == "failed":
                swim_jobs.set_device_status(
                    row["id"], "failed", completed_at=_now_iso(), last_polled_at=_now_iso(),
                    error_message=(result.get("failure_reason") or "")[:500],
                )
                await queue.put({
                    "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                    "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                    "status": "failed", "message": result.get("failure_reason") or "DNAC reported failure",
                })
                return

            swim_jobs.set_device_status(row["id"], "in_progress", last_polled_at=_now_iso())
            if asyncio.get_event_loop().time() > deadline:
                swim_jobs.set_device_status(
                    row["id"], "failed", completed_at=_now_iso(),
                    error_message="No terminal status from DNAC within the poll timeout — check DNAC directly.",
                )
                await queue.put({
                    "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                    "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                    "status": "failed", "message": "Poll timeout — check DNAC directly",
                })
                return


async def run_job(job_id: int, dnac, ssh_username: str | None = None, ssh_password: str | None = None):
    """Resumable execution generator for one job. Yields plain event dicts
    (the caller — routers/swim.py — wraps each in the app's standard SSE
    `emit()` helper). See the module docstring for the concurrency model and
    the resume semantics below.

    `ssh_username`/`ssh_password` are the operator's own session credentials
    (same "no dedicated service account" posture as every other SSH surface
    in this app — routers/commands.py, the Nexus collector) — only actually
    used when `job["flash_cleanup"]` is set; harmless to pass (or omit) for
    a job that doesn't need them.

    On every call (fresh Start or Resume — same code path):
      1. queued rows          -> new work, submitted fresh.
      2. in_progress rows     -> poll-only resumption; never re-submitted.
      3. submitting rows      -> genuinely ambiguous (process died between
         "about to POST" and "recorded a task_id"). Resolved by asking DNAC
         rather than guessing: if it has any update record for the device
         since the row's created_at, treat as submitted and poll; otherwise
         requeue for normal re-submission.
      4. success/failed/cancelled rows are left untouched.

    If the SSE connection drops (this generator is closed/cancelled), the
    `finally` block cancels any still-running worker tasks and marks the job
    'paused' — not required for correctness (resume always re-derives from
    job_devices, never trusts jobs.status), but keeps the UI honest.
    """
    job = swim_jobs.get_job(job_id)
    if job is None:
        yield {"type": "error", "message": f"Job {job_id} not found"}
        return

    queued = swim_jobs.list_job_devices(job_id, status="queued")
    in_progress = swim_jobs.list_job_devices(job_id, status="in_progress")
    submitting = swim_jobs.list_job_devices(job_id, status="submitting")

    yield {"type": "log", "level": "info", "message":
           f"Resuming job {job_id}: {len(queued)} queued, {len(in_progress)} in progress, "
           f"{len(submitting)} to reconcile"}

    # Reconcile the ambiguous 'submitting' rows up front, synchronously,
    # before spawning any workers — each becomes either an in_progress
    # resume or a requeue.
    resumed_in_progress: list[dict] = []
    for row in submitting:
        since = _parse_since(row.get("created_at"))
        result = await _poll_once(dnac, row["device_id"], since)
        if result["status"] == "pending":
            swim_jobs.set_device_status(row["id"], "queued")
            row["status"] = "queued"
            queued.append(row)
            yield {"type": "log", "level": "warn", "message":
                   f"{row.get('hostname') or row['device_id']}: no DNAC record found for a prior "
                   f"submit attempt — requeued"}
        else:
            swim_jobs.set_device_status(row["id"], "in_progress", submitted_at=since.isoformat())
            row["status"] = "in_progress"
            resumed_in_progress.append(row)
            yield {"type": "log", "level": "info", "message":
                   f"{row.get('hostname') or row['device_id']}: found a prior submit already in "
                   f"progress at DNAC — resuming polling"}

    work = [(r, False) for r in queued] + [(r, True) for r in in_progress + resumed_in_progress]

    if not work:
        yield {"type": "log", "level": "info", "message": "Nothing to resume — job already drained"}
        counts = swim_jobs.device_status_counts(job_id)
        final_status = "completed" if counts["failed"] == 0 else "completed_with_errors"
        swim_jobs.set_job_status(job_id, final_status, completed_at=_now_iso())
        yield {"type": "complete", "job_id": job_id, "status": final_status, "counts": counts}
        return

    # Per-site concurrency is normally sized per site from that site's
    # SolarWinds circuit speed (utils/swim_site_circuit.py), snapshotted into
    # job_site_limits at job-creation time — see that module's docstring.
    # `jobs.site_concurrency` is the operator's ceiling, never a floor: a
    # circuit-derived value never gets to exceed it.
    #
    # `legacy_job` covers jobs created before this feature shipped (still
    # draft/paused with zero job_site_limits rows at deploy time) — without
    # this branch every one of their sites would silently drop from their
    # original flat site_concurrency to 1, a safe direction but a surprising
    # regression for in-flight jobs. It's distinct from "some sites present,
    # this one missing" below, which still defends to 1 for just that site.
    site_limits = {r["site_code"]: r for r in swim_jobs.list_site_limits(job_id)}
    legacy_job = not site_limits
    operator_ceiling = min(max(1, job.get("site_concurrency") or 3), _SITE_CONCURRENCY_CEILING)
    site_sems: dict[str, asyncio.Semaphore] = {}

    def sem_for(site_code: str) -> asyncio.Semaphore:
        key = site_code or "UNKNOWN"
        if key not in site_sems:
            if legacy_job:
                capacity = operator_ceiling
            else:
                row = site_limits.get(key)
                capacity = min(max(1, row["concurrency"] if row else 1), operator_ceiling)
            site_sems[key] = asyncio.Semaphore(capacity)
        return site_sems[key]

    swim_jobs.set_job_status(job_id, "running", started_at=job.get("started_at") or _now_iso())

    queue: asyncio.Queue = asyncio.Queue()
    sentinel = object()
    total = len(work)
    done = 0

    async def worker(row: dict, skip_submit: bool):
        try:
            await _device_worker(
                dnac, job, row, sem_for(row.get("site_code")), queue, skip_submit,
                ssh_username=ssh_username, ssh_password=ssh_password,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"SWIM worker crashed for device {row.get('device_id')}: {e}")
            swim_jobs.set_device_status(row["id"], "failed", error_message=str(e)[:500], completed_at=_now_iso())
            await queue.put({
                "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                "status": "failed", "message": f"Internal error: {str(e)[:200]}",
            })
        finally:
            await queue.put(sentinel)

    tasks = [asyncio.create_task(worker(row, skip)) for row, skip in work]

    try:
        finished = 0
        while finished < len(tasks):
            msg = await queue.get()
            if msg is sentinel:
                finished += 1
                done += 1
                yield {"type": "progress", "done": done, "total": total}
            else:
                yield msg

        counts = swim_jobs.device_status_counts(job_id)
        remaining = counts["queued"] + counts["submitting"] + counts["in_progress"]
        if remaining == 0:
            final_status = "completed" if counts["failed"] == 0 else "completed_with_errors"
            swim_jobs.set_job_status(job_id, final_status, completed_at=_now_iso())
        else:
            final_status = "running"
        yield {"type": "complete", "job_id": job_id, "status": final_status, "counts": counts}
    finally:
        # Either we finished normally (every task already done, cancel() is
        # a no-op) or the SSE connection dropped early — stop this app's
        # orchestration either way. Already-submitted DNAC work is
        # unaffected; DNAC has no idea our poll loop stopped watching.
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        job_now = swim_jobs.get_job(job_id)
        if job_now and job_now["status"] == "running":
            swim_jobs.set_job_status(job_id, "paused")


async def run_single_device(
    job_id: int, device_row_id: int, dnac,
    ssh_username: str | None = None, ssh_password: str | None = None,
):
    """Manually submit exactly one still-queued device row, independent of a
    full run_job() pass — for nudging one specific device (e.g. the couple
    left behind after a job paused mid-run) without resuming the job's whole
    concurrency-bounded batch, which would also re-submit every other
    still-queued device.

    Deliberately bypasses the per-site semaphore entirely (a fresh
    `asyncio.Semaphore(1)` scoped to just this call): site_concurrency
    exists to bound how many devices *at one site* are simultaneously
    mid-distribution over that site's shared WAN circuit, and a single
    hand-triggered device can't cause that problem on its own. Still goes
    through GLOBAL_SEM for each individual DNAC call, and the same
    flash-cleanup step as a normal run — this is "run _device_worker for one
    row right now," not a different execution path.

    Callers (routers/swim.py) own the policy guards — job already confirmed
    once, and no full batch run currently active for this job in this
    process — since those aren't this function's concern. The one race this
    function does re-check itself is the device row's own status, matching
    _device_worker's own re-check: a concurrent cancel-queued call is
    possible right up until submission.

    Unlike run_job(), finding queued/submitting/in_progress work left after
    this single device finishes is the *expected* case (every other
    still-queued row is untouched), not a defensive fallback — so the job
    goes back to 'paused' rather than staying 'running'.
    """
    job = swim_jobs.get_job(job_id)
    if job is None:
        yield {"type": "error", "message": f"Job {job_id} not found"}
        return

    row = next((r for r in swim_jobs.list_job_devices(job_id) if r["id"] == device_row_id), None)
    if row is None:
        yield {"type": "error", "message": f"Device row {device_row_id} not found on job {job_id}"}
        return
    if row["status"] != "queued":
        yield {"type": "error", "message": f"Device is not queued (current status: {row['status']})"}
        return

    yield {"type": "log", "level": "info", "message":
           f"Manually starting {row.get('hostname') or row['device_id']}"}

    swim_jobs.set_job_status(job_id, "running", started_at=job.get("started_at") or _now_iso())

    queue: asyncio.Queue = asyncio.Queue()
    sentinel = object()
    solo_sem = asyncio.Semaphore(1)

    async def worker():
        try:
            await _device_worker(
                dnac, job, row, solo_sem, queue, False,
                ssh_username=ssh_username, ssh_password=ssh_password,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"SWIM manual start crashed for device {row.get('device_id')}: {e}")
            swim_jobs.set_device_status(row["id"], "failed", error_message=str(e)[:500], completed_at=_now_iso())
            await queue.put({
                "type": "device_update", "device_row_id": row["id"], "device_id": row["device_id"],
                "hostname": row.get("hostname"), "site_code": row.get("site_code"),
                "status": "failed", "message": f"Internal error: {str(e)[:200]}",
            })
        finally:
            await queue.put(sentinel)

    task = asyncio.create_task(worker())

    try:
        while True:
            msg = await queue.get()
            if msg is sentinel:
                break
            yield msg

        counts = swim_jobs.device_status_counts(job_id)
        remaining = counts["queued"] + counts["submitting"] + counts["in_progress"]
        if remaining == 0:
            final_status = "completed" if counts["failed"] == 0 else "completed_with_errors"
            swim_jobs.set_job_status(job_id, final_status, completed_at=_now_iso())
        else:
            final_status = "paused"
            swim_jobs.set_job_status(job_id, final_status)
        yield {"type": "complete", "job_id": job_id, "status": final_status, "counts": counts}
    finally:
        # Same "stop watching either way" posture as run_job()'s finally —
        # if the SSE connection dropped before the block above ran, make
        # sure the solo worker task is actually stopped and the job doesn't
        # get stuck reporting 'running' with nothing behind it.
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        job_now = swim_jobs.get_job(job_id)
        if job_now and job_now["status"] == "running":
            swim_jobs.set_job_status(job_id, "paused")
