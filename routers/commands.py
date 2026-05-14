"""routers/commands.py — Ad-hoc SSH command runner with SSE streaming.

Show-mode (`/run`) executes a single read-only command per device via Netmiko.
Config-mode (`/config-deploy`, `/config-continue`, `/config-rollback`) pushes a
multi-line script through DNAC Template Programmer with a canary stage and an
archive-based rollback path.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import auth as auth_module
import clients.dnac as dc
from auth import SessionEntry, require_auth
from cache import cache
from logger_config import run_with_context

SSH_TIMEOUT = 30
SSH_MAX_WORKERS = 10

router = APIRouter()
logger = logging.getLogger(__name__)

ALLOWED_PREFIXES = {
    "show ", "display ", "get ", "ping ", "traceroute ",
    "tracert ",
}
DISALLOWED_CHARS = {";", "&", "`", "$", "(", ")", "{", "}", ">", "<", "\n", "\r", "\t"}

PLATFORM_MAP = [
    ("N9K", "cisco_nxos"), ("N7K", "cisco_nxos"), ("N5K", "cisco_nxos"), ("N3K", "cisco_nxos"),
    ("C9",  "cisco_ios"),  ("C8",  "cisco_ios"),  ("ISR", "cisco_ios"),  ("ASR", "cisco_ios"),
    ("CSR", "cisco_ios"),  ("C38", "cisco_ios"),  ("C36", "cisco_ios"),  ("C35", "cisco_ios"),
    ("CISCO39", "cisco_ios"), ("CISCO38", "cisco_ios"),
    ("ASA", "cisco_asa"), ("FTD", "cisco_ftd"), ("WLC", "cisco_wlc"),
]


def guess_device_type(platform_id: str) -> str:
    if not platform_id:
        return "cisco_ios"
    pid = platform_id.upper()
    for substr, dtype in PLATFORM_MAP:
        if substr in pid:
            return dtype
    return "cisco_ios"


def _run_on_device(
    ip: str,
    command: str,
    username: str,
    password: str,
    device_type: str,
    timeout: int,
) -> dict:
    """SSH to one device, run one command. Returns result dict."""
    from dev import DEV_MODE
    if DEV_MODE:
        # In DEV_MODE we simulate latency synchronously since we're in ThreadPool
        # simulate synchronously in threadpool
        pass # simulated delay
        return {
            "ip": ip, "status": "success",
            "output": f"Mock output for '{command}' on {ip}\n(Simulated connection success)",
            "elapsed": 1.0, "error": None,
        }

    start = time.time()
    try:
        from netmiko import ConnectHandler
        with ConnectHandler(
            device_type=device_type,
            host=ip,
            username=username,
            password=password,
            timeout=timeout,
            conn_timeout=timeout,
            fast_cli=False,
        ) as conn:
            output = conn.send_command(command, read_timeout=timeout)
        return {
            "ip": ip, "status": "success",
            "output": output, "elapsed": round(time.time() - start, 1), "error": None,
        }
    except Exception as e:
        return {
            "ip": ip, "status": "error",
            "output": None, "elapsed": round(time.time() - start, 1),
            "error": f"{type(e).__name__}: {str(e)[:200]}",
        }


class CommandRequest(BaseModel):
    devices:              list[dict]   # [{ip, hostname, platform}]
    command:              str
    device_type_override: Optional[str] = None
    max_workers:          int = SSH_MAX_WORKERS
    timeout:              int = SSH_TIMEOUT


@router.post("/run")
async def run_command(req: CommandRequest, session: SessionEntry = Depends(require_auth)):
    """Execute a command on multiple devices. Streams SSE progress."""
    from os import getenv
    if getenv("COMMANDS_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Command execution is disabled")

    command = req.command.strip()
    req.command = command

    if len(command) > 256:
        raise HTTPException(400, "Command too long (max 256 chars)")

    username, password = session.username, session.password

    if not any(command.lower().startswith(p) for p in ALLOWED_PREFIXES):
        raise HTTPException(400, "Only read-only show/display commands are permitted")

    if any(c in command for c in DISALLOWED_CHARS):
        raise HTTPException(400, "Command contains disallowed characters")

    import shlex
    try:
        parts = shlex.split(command)
        for p in parts:
            if any(c in p for c in DISALLOWED_CHARS):
                raise HTTPException(400, "Command contains disallowed characters")
    except ValueError as e:
        raise HTTPException(400, f"Invalid command format: {e}")

    # Log each command execution
    for dev in req.devices:
        logger.info(f"User {session.username} executing command on {dev.get('ip')}: {req.command}")

    async def generate():
        total = len(req.devices)
        done  = 0

        def make_result(device: dict) -> dict:
            dtype = (
                req.device_type_override
                if req.device_type_override and req.device_type_override != "auto"
                else guess_device_type(device.get("platform", ""))
            )
            result = _run_on_device(
                ip=device.get("ip", ""),
                command=req.command,
                username=username,
                password=password,
                device_type=dtype,
                timeout=req.timeout,
            )
            result["hostname"] = device.get("hostname", device.get("ip", ""))
            result["platform"] = device.get("platform", "")
            return result

        with ThreadPoolExecutor(max_workers=req.max_workers) as executor:
            futures = {executor.submit(make_result, dev): dev for dev in req.devices}
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                done += 1
                yield f"data: {json.dumps({'type':'progress','done':done,'total':total,**result})}\n\n"

        succeeded = sum(1 for r in results if r["status"] == "success")
        yield f"data: {json.dumps({'type':'complete','total':total,'succeeded':succeeded,'failed':total-succeeded})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Config mode (DNAC Template Programmer) ───────────────────────────────────

CONFIG_MAX_DEVICES   = int(os.getenv("CONFIG_MAX_DEVICES", "500"))
CONFIG_CANARY_SIZE   = int(os.getenv("CONFIG_CANARY_SIZE", "3"))
CONFIG_DEPLOY_POLL_S = float(os.getenv("CONFIG_DEPLOY_POLL_S", "2.0"))
CONFIG_DEPLOY_MAX_S  = int(os.getenv("CONFIG_DEPLOY_MAX_S", "1800"))  # 30 min
CONFIG_KEEP_LAST_N   = int(os.getenv("CONFIG_KEEP_LAST_N", "20"))

# Platform → DNAC softwareType filter
PLATFORM_LABELS = {"cisco_ios": "IOS-XE", "cisco_nxos": "NX-OS"}


def _config_enabled():
    if os.getenv("CONFIG_CHANGES_ENABLED", "false").lower() != "true":
        raise HTTPException(403, "Config-mode deploys are disabled")


def _resolve_devices(ips: list[str], platform_key: str) -> tuple[list[dict], list[dict]]:
    """Map a list of IPs to DNAC inventory entries. Returns (matched, skipped).
    matched entries include the DNAC instanceUuid and resolved family.
    skipped entries explain why (not_in_dnac / wrong_platform).
    """
    devices = cache.get("devices") or []
    by_ip   = {d.get("managementIpAddress"): d for d in devices}

    matched, skipped = [], []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        d = by_ip.get(ip)
        if not d:
            skipped.append({"ip": ip, "reason": "not_in_dnac"})
            continue
        dtype = guess_device_type(d.get("platformId", ""))
        if dtype != platform_key:
            skipped.append({"ip": ip, "reason": "wrong_platform",
                            "detected": dtype, "hostname": d.get("hostname", "")})
            continue
        matched.append({
            "ip": ip,
            "hostname": d.get("hostname", ""),
            "uuid": d.get("id") or d.get("instanceUuid"),
            "platformId": d.get("platformId", ""),
        })
    return matched, skipped


def _audit_log(action: str, session: SessionEntry, **fields) -> None:
    logger.info(f"CONFIG_DEPLOY {action} user={session.username} " +
                " ".join(f"{k}={v}" for k, v in fields.items()))


def _script_hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _snapshot_configs(dnac, device_uuids: list[str]) -> dict:
    """Pull running-config for each device in parallel; return {uuid: text}.
    Missing/empty configs are stored as empty strings so the caller can detect
    them and refuse to roll back that device."""
    out: dict[str, str] = {}
    if not device_uuids:
        return out
    with ThreadPoolExecutor(max_workers=min(20, len(device_uuids))) as pool:
        futures = {pool.submit(dc.get_device_config, dnac, uuid): uuid
                   for uuid in device_uuids}
        for fut in as_completed(futures):
            uuid = futures[fut]
            try:
                out[uuid] = fut.result() or ""
            except Exception as e:
                logger.warning(f"Snapshot failed for {uuid}: {e}")
                out[uuid] = ""
    return out


def _cleanup_old_templates(dnac, project_id: str) -> None:
    """Keep the most recent CONFIG_KEEP_LAST_N ad-hoc templates; delete the rest."""
    try:
        templates = dc.list_adhoc_templates(dnac, project_id)
        ours = [t for t in templates if (t.get("name") or "").startswith("impact_adhoc_")]
        # Names embed a timestamp, so lexicographic sort = chronological
        ours.sort(key=lambda t: t.get("name", ""), reverse=True)
        for t in ours[CONFIG_KEEP_LAST_N:]:
            dc.delete_template(dnac, t["id"])
    except Exception as e:
        logger.debug(f"Template cleanup skipped: {e}")


class ConfigDeployRequest(BaseModel):
    ips:         list[str]                          # raw IP list pasted by the user
    platform:    Literal["cisco_ios", "cisco_nxos"] # forced single-platform per design
    script:      str                                # multi-line config block
    confirm:     str                                # must equal "DEPLOY"
    canary:      bool = True                        # canary first batch?
    pre_show:    Optional[str] = None               # optional pre/post show command
    approval:    bool = False                       # require DNAC approval workflow
    # Optional UI hint: if a continuation deploy_id is supplied, we skip canary
    parent_deploy_id: Optional[str] = None


class ConfigContinueRequest(BaseModel):
    deploy_id: str   # the canary's stage id; fan out to the remaining devices


class ConfigRollbackRequest(BaseModel):
    deploy_id: str
    device_ids: Optional[list[str]] = None  # subset to roll back; None = all


def _stage_key(stage_id: str) -> str:
    return f"config_deploy_stage:{stage_id}"


@router.post("/config-deploy")
async def config_deploy(req: ConfigDeployRequest, session: SessionEntry = Depends(require_auth)):
    """Stage a config-mode deploy. Creates an ephemeral DNAC template, optionally
    runs a canary, and streams per-device deployment progress."""
    _config_enabled()

    if req.confirm != "DEPLOY":
        raise HTTPException(400, "Confirmation phrase incorrect")
    if not req.script.strip():
        raise HTTPException(400, "Script is empty")
    if len(req.ips) == 0:
        raise HTTPException(400, "No IPs provided")
    if len(req.ips) > CONFIG_MAX_DEVICES:
        raise HTTPException(400, f"Too many devices (max {CONFIG_MAX_DEVICES})")

    matched, skipped = _resolve_devices(req.ips, req.platform)
    if not matched:
        raise HTTPException(400, "No matching devices found in DNAC inventory")

    # Decide canary vs full deploy
    use_canary = req.canary and not req.parent_deploy_id and len(matched) > CONFIG_CANARY_SIZE
    canary_set = matched[:CONFIG_CANARY_SIZE] if use_canary else matched
    remainder  = matched[CONFIG_CANARY_SIZE:] if use_canary else []

    dnac = auth_module.get_dnac_for_session(session)
    software_type = PLATFORM_LABELS[req.platform]
    script_hash = _script_hash(req.script)
    stage_id = f"{int(time.time())}_{script_hash}"
    template_name = f"impact_adhoc_{stage_id}"

    _audit_log("STAGE_REQUESTED", session,
               platform=req.platform, devices=len(matched),
               canary=use_canary, script_hash=script_hash)

    async def generate():
        loop = asyncio.get_event_loop()
        def emit(d): return f"data: {json.dumps(d)}\n\n"

        yield emit({"type": "log", "message": f"Resolved {len(matched)} devices "
                    f"({len(skipped)} skipped). "
                    f"{'Canary first: ' + str(len(canary_set)) + ' devices.' if use_canary else 'Full deploy.'}"})

        if skipped:
            yield emit({"type": "skipped", "items": skipped})

        try:
            yield emit({"type": "log", "message": "Ensuring ad-hoc template project in DNAC…"})
            project_id = await loop.run_in_executor(None, run_with_context(
                lambda: dc.ensure_adhoc_project(dnac)))

            yield emit({"type": "log", "message": f"Creating ephemeral template {template_name}…"})
            template_id = await loop.run_in_executor(None, run_with_context(
                lambda: dc.create_adhoc_template(dnac, project_id, template_name,
                                                 req.script, software_type)))

            target_uuids = [d["uuid"] for d in canary_set if d.get("uuid")]
            yield emit({"type": "log", "message": f"Snapshotting pre-deploy configs for {len(target_uuids)} device(s)…"})
            snapshots = await loop.run_in_executor(None, run_with_context(
                lambda: _snapshot_configs(dnac, target_uuids)))

            yield emit({"type": "log", "message": f"Deploying to {len(target_uuids)} device(s)…"})
            deployment_id = await loop.run_in_executor(None, run_with_context(
                lambda: dc.deploy_template(dnac, template_id, target_uuids)))

            # DEV_MODE: stash the device list so the mock status loader can reflect it
            from dev import DEV_MODE
            if DEV_MODE:
                cache.set(f"dev_deploy_devices:{deployment_id}",
                          [d["uuid"] for d in canary_set], ttl=600)

            # Persist stage so /config-continue and /config-rollback can resume
            cache.set(_stage_key(stage_id), {
                "template_id": template_id,
                "project_id":  project_id,
                "deployment_ids": [deployment_id],
                "canary_set":  canary_set,
                "remainder":   remainder,
                "platform":    req.platform,
                "script":      req.script,
                "script_hash": script_hash,
                "snapshots":   snapshots,  # {uuid: pre_deploy_running_config}
                "user":        session.username,
                "created_at":  time.time(),
                "phase":       "canary" if use_canary else "full",
            }, ttl=3600 * 4)

            yield emit({"type": "deploy_started", "stage_id": stage_id,
                        "deployment_id": deployment_id, "phase": "canary" if use_canary else "full",
                        "total_devices": len(matched), "in_flight": len(target_uuids)})

            # Poll deployment status
            async for ev in _poll_deployment(dnac, loop, deployment_id, canary_set):
                yield ev

            yield emit({"type": "phase_complete",
                        "stage_id": stage_id,
                        "phase": "canary" if use_canary else "full",
                        "remainder": len(remainder)})

            if not use_canary:
                # Full deploy: clean up old templates and we're done
                await loop.run_in_executor(None, run_with_context(
                    lambda: _cleanup_old_templates(dnac, project_id)))
                _audit_log("STAGE_COMPLETE", session, stage_id=stage_id,
                           script_hash=script_hash, devices=len(matched))

        except Exception as e:
            logger.exception("config-deploy failed")
            yield emit({"type": "error", "message": f"{type(e).__name__}: {str(e)[:200]}"})

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def _poll_deployment(dnac, loop, deployment_id: str, device_set: list[dict]):
    """Yield SSE events while polling a single DNAC deployment. Terminates when
    every device has reached a terminal state or CONFIG_DEPLOY_MAX_S elapses."""
    def emit(d): return f"data: {json.dumps(d)}\n\n"

    uuid_to_meta = {d["uuid"]: d for d in device_set}
    seen_terminal = set()
    deadline = time.time() + CONFIG_DEPLOY_MAX_S

    while time.time() < deadline:
        try:
            status = await loop.run_in_executor(None, run_with_context(
                lambda: dc.get_deployment_status(dnac, deployment_id)))
        except Exception as e:
            yield emit({"type": "log", "message": f"Status poll failed: {e}"})
            await asyncio.sleep(CONFIG_DEPLOY_POLL_S)
            continue

        devices = status.get("devices") or []
        for d in devices:
            dev_id = d.get("deviceId") or d.get("id")
            dstate = (d.get("status") or "").upper()
            if dev_id in seen_terminal:
                continue
            if dstate in ("SUCCESS", "FAILURE", "FAILED"):
                seen_terminal.add(dev_id)
                meta = uuid_to_meta.get(dev_id, {})
                yield emit({
                    "type": "device_result",
                    "deployment_id": deployment_id,
                    "device_id": dev_id,
                    "ip": meta.get("ip", ""),
                    "hostname": meta.get("hostname", ""),
                    "status": "success" if dstate == "SUCCESS" else "failure",
                    "message": d.get("statusMessage") or "",
                })

        overall = (status.get("status") or "").upper()
        if overall in ("SUCCESS", "FAILURE", "FAILED") or len(seen_terminal) >= len(device_set):
            break
        await asyncio.sleep(CONFIG_DEPLOY_POLL_S)


@router.post("/config-continue")
async def config_continue(req: ConfigContinueRequest, session: SessionEntry = Depends(require_auth)):
    """After a canary completes, fan out to the remaining devices."""
    _config_enabled()
    stage = cache.get(_stage_key(req.deploy_id))
    if not stage:
        raise HTTPException(404, "Stage not found or expired")
    if stage["user"] != session.username:
        raise HTTPException(403, "Stage owned by another user")
    if not stage["remainder"]:
        raise HTTPException(400, "Nothing left to deploy in this stage")

    dnac = auth_module.get_dnac_for_session(session)
    remainder = stage["remainder"]
    template_id = stage["template_id"]
    _audit_log("CONTINUE_REQUESTED", session, stage_id=req.deploy_id,
               script_hash=stage["script_hash"], devices=len(remainder))

    async def generate():
        loop = asyncio.get_event_loop()
        def emit(d): return f"data: {json.dumps(d)}\n\n"

        target_uuids = [d["uuid"] for d in remainder if d.get("uuid")]
        yield emit({"type": "log", "message": f"Snapshotting pre-deploy configs for {len(target_uuids)} device(s)…"})
        try:
            new_snapshots = await loop.run_in_executor(None, run_with_context(
                lambda: _snapshot_configs(dnac, target_uuids)))
            stage["snapshots"] = {**stage.get("snapshots", {}), **new_snapshots}

            yield emit({"type": "log", "message": f"Fanning out to {len(target_uuids)} remaining devices…"})
            deployment_id = await loop.run_in_executor(None, run_with_context(
                lambda: dc.deploy_template(dnac, template_id, target_uuids)))

            from dev import DEV_MODE
            if DEV_MODE:
                cache.set(f"dev_deploy_devices:{deployment_id}", target_uuids, ttl=600)

            stage["deployment_ids"].append(deployment_id)
            stage["phase"] = "full"
            cache.set(_stage_key(req.deploy_id), stage, ttl=3600 * 4)

            yield emit({"type": "deploy_started", "stage_id": req.deploy_id,
                        "deployment_id": deployment_id, "phase": "fanout",
                        "in_flight": len(target_uuids)})

            async for ev in _poll_deployment(dnac, loop, deployment_id, remainder):
                yield ev

            await loop.run_in_executor(None, run_with_context(
                lambda: _cleanup_old_templates(dnac, stage["project_id"])))
            yield emit({"type": "phase_complete", "stage_id": req.deploy_id,
                        "phase": "fanout", "remainder": 0})
            _audit_log("CONTINUE_COMPLETE", session, stage_id=req.deploy_id,
                       script_hash=stage["script_hash"])
        except Exception as e:
            logger.exception("config-continue failed")
            yield emit({"type": "error", "message": f"{type(e).__name__}: {str(e)[:200]}"})

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/config-rollback")
async def config_rollback(req: ConfigRollbackRequest, session: SessionEntry = Depends(require_auth)):
    """Roll back a deploy by pushing each device's pre-deploy running-config back via
    a one-off template per device. Subset via `device_ids`; default is all-in-stage."""
    _config_enabled()
    stage = cache.get(_stage_key(req.deploy_id))
    if not stage:
        raise HTTPException(404, "Stage not found or expired")
    if stage["user"] != session.username:
        raise HTTPException(403, "Stage owned by another user")

    dnac = auth_module.get_dnac_for_session(session)
    all_devs = stage["canary_set"] + stage["remainder"]
    target = ([d for d in all_devs if d["uuid"] in set(req.device_ids)]
              if req.device_ids else all_devs)
    if not target:
        raise HTTPException(400, "No matching devices to roll back")

    _audit_log("ROLLBACK_REQUESTED", session, stage_id=req.deploy_id,
               script_hash=stage["script_hash"], devices=len(target))

    async def generate():
        loop = asyncio.get_event_loop()
        def emit(d): return f"data: {json.dumps(d)}\n\n"
        yield emit({"type": "log", "message": f"Rollback started for {len(target)} device(s). "
                    "Pulling pre-deploy snapshots from DNAC archive…"})

        # We captured each device's pre-deploy running-config into stage["snapshots"]
        # during the deploy phase; push that text back as a one-off template.
        software_type = PLATFORM_LABELS[stage["platform"]]
        snapshots = stage.get("snapshots", {})
        for d in target:
            try:
                pre_cfg = snapshots.get(d["uuid"])
                if not pre_cfg:
                    yield emit({"type": "device_result", "device_id": d["uuid"],
                                "ip": d["ip"], "hostname": d["hostname"],
                                "status": "failure",
                                "message": "no pre-deploy snapshot stored for this device"})
                    continue

                rb_name = f"impact_adhoc_rollback_{int(time.time())}_{d['uuid'][:8]}"
                template_id = await loop.run_in_executor(None, run_with_context(
                    lambda: dc.create_adhoc_template(dnac, stage["project_id"],
                                                     rb_name, pre_cfg, software_type)))
                deployment_id = await loop.run_in_executor(None, run_with_context(
                    lambda: dc.deploy_template(dnac, template_id, [d["uuid"]])))

                from dev import DEV_MODE
                if DEV_MODE:
                    cache.set(f"dev_deploy_devices:{deployment_id}", [d["uuid"]], ttl=600)

                async for ev in _poll_deployment(dnac, loop, deployment_id, [d]):
                    yield ev
                # Best-effort cleanup of the one-off rollback template
                await loop.run_in_executor(None, run_with_context(
                    lambda: dc.delete_template(dnac, template_id)))
            except Exception as e:
                yield emit({"type": "device_result", "device_id": d["uuid"],
                            "ip": d["ip"], "hostname": d["hostname"],
                            "status": "failure",
                            "message": f"{type(e).__name__}: {str(e)[:120]}"})

        yield emit({"type": "phase_complete", "stage_id": req.deploy_id,
                    "phase": "rollback", "remainder": 0})
        _audit_log("ROLLBACK_COMPLETE", session, stage_id=req.deploy_id,
                   script_hash=stage["script_hash"], devices=len(target))

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
