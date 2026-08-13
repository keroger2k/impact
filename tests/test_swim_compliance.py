"""tests/test_swim_compliance.py — golden-image compliance classification
and by-platform/family/site aggregation.

Golden-image-to-platform matching reuses the model-number-token technique
utils/device_comparison_report.py::_model_matches validated for the same
class of problem (see utils/swim_compliance.py's module docstring) — these
tests confirm that technique still works once applied to golden image rows.
"""
from __future__ import annotations

from utils.swim_compliance import build_golden_version_index, classify_device, compute_compliance


def _golden_image(platform: str, version: str) -> dict:
    return {"name": f"{platform}-golden.bin", "version": version,
            "productNames": [{"productName": platform}], "family": "Switches and Hubs"}


def _device(id_, hostname, platform, version) -> dict:
    return {"id": id_, "hostname": hostname, "platformId": platform, "softwareVersion": version,
            "family": "Switches and Hubs"}


# ── build_golden_version_index() ────────────────────────────────────────────

def test_index_matches_on_shared_model_number_token():
    images = [_golden_image("C9300-48U", "17.9.3")]
    index = build_golden_version_index(images)
    assert index["9300"]["version"] == "17.9.3"


def test_index_falls_back_to_name_or_family_field():
    image = {"name": "ISR4451-golden.bin", "version": "17.9.5"}  # no productNames
    index = build_golden_version_index([image])
    assert index["4451"]["version"] == "17.9.5"


def test_index_skips_images_with_no_version():
    images = [{"name": "C9300-48U.bin", "productNames": [{"productName": "C9300-48U"}]}]
    index = build_golden_version_index(images)
    assert index == {}


# ── classify_device() ───────────────────────────────────────────────────────

def test_classify_device_compliant():
    index = build_golden_version_index([_golden_image("C9300-48U", "17.9.3")])
    device = _device("d1", "host-1", "C9300-48U", "17.09.03")  # zero-padded, should still match
    result = classify_device(device, index)
    assert result["status"] == "compliant"
    assert result["golden_version"] == "17.9.3"


def test_classify_device_non_compliant():
    index = build_golden_version_index([_golden_image("C9300-48U", "17.9.3")])
    device = _device("d1", "host-1", "C9300-48U", "17.6.5")
    result = classify_device(device, index)
    assert result["status"] == "non_compliant"
    assert result["golden_version"] == "17.9.3"


def test_classify_device_unknown_when_no_golden_image_for_platform():
    index = build_golden_version_index([_golden_image("C9300-48U", "17.9.3")])
    device = _device("d1", "host-1", "ISR4451-X/K9", "17.6.5")  # no golden entry for this platform
    result = classify_device(device, index)
    assert result["status"] == "unknown"
    assert result["golden_version"] is None


# ── compute_compliance() ─────────────────────────────────────────────────────

def test_compute_compliance_overall_and_breakdowns():
    golden_images = [_golden_image("C9300-48U", "17.9.3"), _golden_image("ISR4451-X/K9", "17.9.5")]
    devices = [
        _device("d1", "sw-k001-1", "C9300-48U", "17.9.3"),   # compliant
        _device("d2", "sw-k001-2", "C9300-48U", "17.6.5"),   # non_compliant
        _device("d3", "rt-k002-1", "ISR4451-X/K9", "17.9.5"),  # compliant
        _device("d4", "sw-k002-3", "C9500-40X", "17.12.1"),  # unknown platform
    ]
    device_site_map = {"d1": "Global/K001", "d2": "Global/K001", "d3": "Global/K002", "d4": "Global/K002"}

    result = compute_compliance(devices, device_site_map, golden_images)

    assert result["overall"] == {"compliant": 2, "non_compliant": 1, "unknown": 1, "total": 4}

    by_site = {r["site_code"]: r for r in result["by_site"]}
    assert by_site["K001"]["compliant"] == 1
    assert by_site["K001"]["non_compliant"] == 1
    assert by_site["K002"]["compliant"] == 1
    assert by_site["K002"]["unknown"] == 1

    by_platform = {r["platform"]: r for r in result["by_platform"]}
    assert by_platform["C9300-48U"]["compliant"] == 1
    assert by_platform["C9300-48U"]["non_compliant"] == 1
    assert by_platform["C9300-48U"]["golden_version"] == "17.9.3"


def test_compute_compliance_filters_narrow_before_aggregation():
    golden_images = [_golden_image("C9300-48U", "17.9.3")]
    devices = [
        _device("d1", "sw-k001-1", "C9300-48U", "17.9.3"),
        _device("d2", "sw-k002-1", "C9300-48U", "17.6.5"),
    ]
    device_site_map = {"d1": "Global/K001", "d2": "Global/K002"}

    result = compute_compliance(devices, device_site_map, golden_images, site="K001")
    assert result["overall"]["total"] == 1
    assert result["overall"]["compliant"] == 1


def test_compute_compliance_empty_devices():
    result = compute_compliance([], {}, [])
    assert result["overall"] == {"compliant": 0, "non_compliant": 0, "unknown": 0, "total": 0}
    assert result["by_platform"] == []
