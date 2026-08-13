"""utils/device_ssh.py — shared Netmiko SSH primitives for Cisco device CLI
operations.

`guess_device_type`/`PLATFORM_MAP` originated in routers/commands.py (the
SSH Command Runner) and were already being imported directly from there by
routers/routing.py and routers/tunnels.py — router-to-router imports for
shared SSH mechanics. That pattern doesn't extend to utils/swim_scheduler.py
(the SWIM flash-cleanup pre-step below): a utils module importing from a
router would be a real layering inversion (routers depend on utils/clients,
never the other way around), where router-to-router at least stays within
one layer. Moving the shared piece here fixes it for every caller, not just
the new one — routers/commands.py, routers/routing.py, and
routers/tunnels.py all import from here now instead of from each other.
"""
from __future__ import annotations

import logging
import re
import time

logger = logging.getLogger(__name__)

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


def run_flash_cleanup(ip: str, username: str, password: str, device_type: str, timeout: int = 120) -> dict:
    """SSH to one device and run `install remove inactive`, answering the
    interactive [y/n] confirmation IOS-XE prompts with before it touches
    flash. Returns {"status": "success"|"error", "output": str|None,
    "error": str|None, "elapsed": float} — same result shape
    routers/commands.py's SSH helpers use, so callers can log/render it the
    same way.

    This can take a while on a device with a lot of accumulated inactive
    packages, hence the longer default timeout than the 30s used for a
    plain show command elsewhere in this app.
    """
    from dev import DEV_MODE
    if DEV_MODE:
        return {
            "ip": ip, "status": "success",
            "output": f"[DEV_MODE] Would run 'install remove inactive' on {ip}",
            "elapsed": 0.5, "error": None,
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
            # A device with nothing inactive to remove never shows the
            # [y/n] prompt at all — it just returns straight to the normal
            # prompt. Waiting on `expect_string=r"[y/n]"` alone would then
            # sit for the full timeout on every already-clean device.
            # Expecting *either* pattern returns as soon as whichever one
            # actually appears; only send the confirmation if the prompt
            # was the one that showed up.
            base_prompt = conn.find_prompt()
            expect_either = rf"(\[y/n\]|{re.escape(base_prompt)})"
            output = conn.send_command(
                "install remove inactive",
                expect_string=expect_either,
                read_timeout=timeout,
            )
            if "[y/n]" in output:
                output += "\n" + conn.send_command_timing("y", read_timeout=timeout)
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
