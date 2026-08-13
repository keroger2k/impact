"""tests/test_device_ssh.py — utils/device_ssh.py: guess_device_type()
(moved here from routers/commands.py, now the shared source for
routers/commands.py, routers/routing.py, routers/tunnels.py, and
utils/swim_scheduler.py's flash-cleanup pre-step) and run_flash_cleanup()
(the `install remove inactive` SSH pre-flight for SWIM distribution jobs).
"""
from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

import utils.device_ssh as device_ssh


# ── guess_device_type() ──────────────────────────────────────────────────────

def test_guess_device_type_ios():
    assert device_ssh.guess_device_type("C9300-48U") == "cisco_ios"
    assert device_ssh.guess_device_type("ISR4451-X/K9") == "cisco_ios"


def test_guess_device_type_nxos():
    assert device_ssh.guess_device_type("N9K-C93180YC-EX") == "cisco_nxos"


def test_guess_device_type_defaults_to_ios_when_unknown_or_empty():
    assert device_ssh.guess_device_type("") == "cisco_ios"
    assert device_ssh.guess_device_type(None) == "cisco_ios"
    assert device_ssh.guess_device_type("SOME-UNKNOWN-PID") == "cisco_ios"


# ── run_flash_cleanup() ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _force_live_path(monkeypatch):
    # conftest.py defaults DEV_MODE=true; these tests want the real
    # Netmiko-calling path.
    monkeypatch.setattr("dev.DEV_MODE", False)


def _fake_conn(prompt: str, first_response: str, confirm_response: str = ""):
    conn = MagicMock()
    conn.find_prompt.return_value = prompt
    conn.send_command.return_value = first_response
    conn.send_command_timing.return_value = confirm_response
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


def test_run_flash_cleanup_answers_yn_prompt_when_shown():
    conn = _fake_conn("router#", "Proceed with removing inactive files? [y/n]", "Files removed.\nrouter#")
    with patch("netmiko.ConnectHandler", return_value=conn):
        result = device_ssh.run_flash_cleanup("1.2.3.4", "user", "pass", "cisco_ios")
    assert result["status"] == "success"
    assert "Files removed" in result["output"]
    conn.send_command_timing.assert_called_once()
    args, kwargs = conn.send_command_timing.call_args
    assert args[0] == "y"


def test_run_flash_cleanup_skips_confirmation_when_nothing_to_clean():
    # No [y/n] ever appears — the command returned straight to the normal
    # prompt because there was nothing inactive to remove. Must not send a
    # "y" confirmation that was never prompted for.
    conn = _fake_conn("router#", "No inactive software images.\nrouter#")
    with patch("netmiko.ConnectHandler", return_value=conn):
        result = device_ssh.run_flash_cleanup("1.2.3.4", "user", "pass", "cisco_ios")
    assert result["status"] == "success"
    conn.send_command_timing.assert_not_called()


def test_run_flash_cleanup_uses_expect_string_covering_both_outcomes():
    conn = _fake_conn("switch#", "No inactive software images.\nswitch#")
    with patch("netmiko.ConnectHandler", return_value=conn):
        device_ssh.run_flash_cleanup("1.2.3.4", "user", "pass", "cisco_ios")
    args, kwargs = conn.send_command.call_args
    assert args[0] == "install remove inactive"
    assert "y/n" in kwargs["expect_string"]
    assert re.escape("switch#") in kwargs["expect_string"]


def test_run_flash_cleanup_returns_error_on_connection_failure():
    with patch("netmiko.ConnectHandler", side_effect=RuntimeError("connection refused")):
        result = device_ssh.run_flash_cleanup("1.2.3.4", "user", "pass", "cisco_ios")
    assert result["status"] == "error"
    assert "connection refused" in result["error"]
