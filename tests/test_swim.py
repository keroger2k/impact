"""tests/test_swim.py — clients/swim.py's mutating surface.

Mirrors tests/test_solarwinds.py's structure: the most important test here
is `test_write_surface_is_narrow_and_explicit`, confirming the module calls
exactly the two documented SDK trigger methods and nothing broader (no
generic invoke-style passthrough)."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import clients.swim as swim

_SRC = Path(__file__).resolve().parent.parent / "clients" / "swim.py"


# ── Write-surface narrowness ─────────────────────────────────────────────────

def test_write_surface_is_narrow_and_explicit():
    """The only mutating SDK calls in this module are the two documented
    trigger methods — no generic invoke/verb passthrough exists."""
    src = _SRC.read_text(encoding="utf-8")
    trigger_calls = sorted(set(re.findall(
        r"software_image_management_swim\.(trigger_\w+)\(", src
    )))
    assert trigger_calls == ["trigger_software_image_activation", "trigger_software_image_distribution"]
    assert "def invoke(" not in src
    assert ".cancel(" not in src and ".abort(" not in src


# ── trigger_distribution() / trigger_activation() ────────────────────────────

@pytest.fixture(autouse=True)
def _force_live_path(monkeypatch):
    # conftest.py defaults DEV_MODE=true so the rest of the suite exercises
    # mock fixtures; these tests specifically want the real DNAC-calling
    # path, so force it off — clients/swim.py re-reads dev.DEV_MODE on every
    # call (`from dev import DEV_MODE` inside each function body), so
    # patching the already-imported module's attribute is picked up.
    monkeypatch.setattr("dev.DEV_MODE", False)


def _fake_dnac(response_obj=None):
    dnac = MagicMock()
    resp = MagicMock()
    resp.response = response_obj if response_obj is not None else MagicMock(taskId="task-123")
    dnac.software_image_management_swim.trigger_software_image_distribution.return_value = resp
    dnac.software_image_management_swim.trigger_software_image_activation.return_value = resp
    return dnac


def test_trigger_distribution_posts_single_device_payload():
    dnac = _fake_dnac()
    task_id = swim.trigger_distribution(dnac, "device-uuid-1", "image-uuid-1")
    assert task_id == "task-123"
    dnac.software_image_management_swim.trigger_software_image_distribution.assert_called_once_with(
        payload=[{"deviceUuid": "device-uuid-1", "imageUuid": "image-uuid-1"}]
    )


def test_trigger_activation_posts_expected_payload_shape():
    dnac = _fake_dnac()
    swim.trigger_activation(
        dnac, "device-uuid-1", "image-uuid-1",
        activate_lower_image_version=True, distribute_if_needed=True,
        device_upgrade_mode="Distribute", schedule_validate=False,
    )
    args, kwargs = dnac.software_image_management_swim.trigger_software_image_activation.call_args
    assert kwargs["schedule_validate"] is False
    payload = kwargs["payload"][0]
    assert payload["deviceUuid"] == "device-uuid-1"
    assert payload["imageUuidList"] == ["image-uuid-1"]
    assert payload["smuImageUuidList"] == []
    assert payload["activateLowerImageVersion"] is True
    assert payload["distributeIfNeeded"] is True
    assert payload["deviceUpgradeMode"] == "Distribute"


def test_trigger_distribution_raises_on_sdk_error():
    dnac = MagicMock()
    dnac.software_image_management_swim.trigger_software_image_distribution.side_effect = RuntimeError("DNAC unreachable")
    with pytest.raises(RuntimeError):
        swim.trigger_distribution(dnac, "d1", "i1")


# ── poll_device_status() ──────────────────────────────────────────────────────

def _fake_poll_dnac(rows: list[dict]):
    dnac = MagicMock()
    resp = MagicMock()
    resp.response = rows
    dnac.software_image_management_swim.get_network_device_image_updates.return_value = resp
    return dnac


def test_poll_device_status_no_rows_is_pending():
    dnac = _fake_poll_dnac([])
    result = swim.poll_device_status(dnac, "d1", datetime.now(timezone.utc))
    assert result == {"status": "pending", "failure_reason": None}


def test_poll_device_status_success():
    dnac = _fake_poll_dnac([{"status": "SUCCESS"}])
    result = swim.poll_device_status(dnac, "d1", datetime.now(timezone.utc))
    assert result["status"] == "success"


def test_poll_device_status_failure_carries_reason():
    dnac = _fake_poll_dnac([{"status": "FAILURE", "failureReason": "Disk full"}])
    result = swim.poll_device_status(dnac, "d1", datetime.now(timezone.utc))
    assert result == {"status": "failed", "failure_reason": "Disk full"}


def test_poll_device_status_in_progress():
    dnac = _fake_poll_dnac([{"status": "IN_PROGRESS"}])
    result = swim.poll_device_status(dnac, "d1", datetime.now(timezone.utc))
    assert result["status"] == "in_progress"


def test_poll_device_status_failure_wins_over_other_rows():
    # A device can have multiple update rows since submission (e.g. distribute
    # then a retry) — failure must never be masked by a stale in-progress row.
    dnac = _fake_poll_dnac([{"status": "IN_PROGRESS"}, {"status": "FAILURE", "failureReason": "x"}])
    result = swim.poll_device_status(dnac, "d1", datetime.now(timezone.utc))
    assert result["status"] == "failed"


def test_poll_device_status_swallows_sdk_errors_as_pending():
    dnac = MagicMock()
    dnac.software_image_management_swim.get_network_device_image_updates.side_effect = RuntimeError("timeout")
    result = swim.poll_device_status(dnac, "d1", datetime.now(timezone.utc))
    assert result["status"] == "pending"


# ── get_assigned_products() ───────────────────────────────────────────────────
# Response shape below is the real schema from Cisco's own published OpenAPI
# spec (Catalyst Center Intent API 3.1.6,
# retrievesNetworkDeviceProductNamesAssignedToASoftwareImageResponse) — not a
# guess. Confirms the fix for a real bug: an earlier version of this function
# read a singular `productId` field that doesn't exist in the real response
# (the actual field is `productIds`, a list), so it silently found nothing
# for every real image and reported every device as incompatible.

def _fake_products_dnac(rows: list[dict]):
    dnac = MagicMock()
    resp = MagicMock()
    resp.response = rows
    dnac.software_image_management_swim.retrieves_network_device_product_names_assigned_to_a_software_image.return_value = resp
    return dnac


def test_get_assigned_products_reads_productIds_list_not_singular_productId():
    dnac = _fake_products_dnac([
        {"id": "1", "productName": "Cisco Catalyst 9300 Series Switches", "productNameOrdinal": 1,
         "productIds": ["C9300-48U", "C9300-24P"], "recommended": "CISCO"},
    ])
    result = swim.get_assigned_products(dnac, "image-1")
    assert result == {
        "C9300-48U": "Cisco Catalyst 9300 Series Switches",
        "C9300-24P": "Cisco Catalyst 9300 Series Switches",
    }


def test_get_assigned_products_does_not_filter_by_assigned_status():
    """No `assigned=` kwarg should be sent — NOT_ASSIGNED rows still "apply
    to" the image per DNAC's own field description, and most golden-tag
    workflows never touch the separate formal-assignment step."""
    dnac = _fake_products_dnac([
        {"id": "1", "productName": "Cisco Catalyst 9300 Series Switches", "productNameOrdinal": 1,
         "productIds": ["C9300-48U"], "recommended": "USER"},
    ])
    swim.get_assigned_products(dnac, "image-1")
    call_kwargs = dnac.software_image_management_swim.retrieves_network_device_product_names_assigned_to_a_software_image.call_args.kwargs
    assert "assigned" not in call_kwargs


def test_get_assigned_products_empty_response():
    dnac = _fake_products_dnac([])
    assert swim.get_assigned_products(dnac, "image-1") == {}


def test_get_assigned_products_swallows_sdk_errors_as_empty():
    dnac = MagicMock()
    dnac.software_image_management_swim.retrieves_network_device_product_names_assigned_to_a_software_image.side_effect = RuntimeError("timeout")
    assert swim.get_assigned_products(dnac, "image-1") == {}
