"""tests/test_swim_compliance.py — golden-image compliance classification
and by-product-family/by-device-family/by-site aggregation.

Matching is exact-PID against DNAC's own assigned-products data
(clients.swim.get_assigned_products), not a heuristic — these tests confirm
the index-building and classification logic consume that shape correctly,
including the "many PIDs share one product family name" case (see
utils/swim_compliance.py's module docstring for why this replaced an
earlier model-number-token heuristic).
"""
from __future__ import annotations

from utils.swim_compliance import build_golden_version_index, classify_device, compute_compliance


def _golden_image(version: str, assigned_products: dict[str, str]) -> dict:
    return {"name": f"golden-{version}.bin", "version": version, "assigned_products": assigned_products}


def _device(id_, hostname, platform, version, family="Switches and Hubs") -> dict:
    return {"id": id_, "hostname": hostname, "platformId": platform, "softwareVersion": version, "family": family}


# ── build_golden_version_index() ────────────────────────────────────────────

def test_index_keys_on_exact_pid():
    images = [_golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"})]
    index = build_golden_version_index(images)
    assert index["C9300-48U"]["version"] == "17.9.3"
    assert index["C9300-48U"]["product_family"] == "Cisco Catalyst 9300 Series Switches"


def test_index_one_family_can_cover_multiple_pids():
    # DNAC's real productName data covers many PIDs per family — confirmed
    # via the SDK's own docstring ("network device product names ... and
    # the support PIDs"). Two distinct platformIds sharing one family name.
    images = [_golden_image("17.9.3", {
        "C9300-48U": "Cisco Catalyst 9300 Series Switches",
        "C9300-24P": "Cisco Catalyst 9300 Series Switches",
    })]
    index = build_golden_version_index(images)
    assert index["C9300-48U"]["product_family"] == index["C9300-24P"]["product_family"]


def test_index_skips_images_with_no_version():
    images = [{"name": "no-version.bin", "assigned_products": {"C9300-48U": "Cisco Catalyst 9300 Series Switches"}}]
    index = build_golden_version_index(images)
    assert index == {}


def test_index_ignores_images_with_no_assigned_products():
    images = [_golden_image("17.9.3", {})]
    assert build_golden_version_index(images) == {}


# ── classify_device() ───────────────────────────────────────────────────────

def test_classify_device_compliant():
    index = build_golden_version_index([_golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"})])
    device = _device("d1", "host-1", "C9300-48U", "17.09.03")  # zero-padded, should still match
    result = classify_device(device, index)
    assert result["status"] == "compliant"
    assert result["golden_version"] == "17.9.3"
    assert result["product_family"] == "Cisco Catalyst 9300 Series Switches"


def test_classify_device_non_compliant():
    index = build_golden_version_index([_golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"})])
    device = _device("d1", "host-1", "C9300-48U", "17.6.5")
    result = classify_device(device, index)
    assert result["status"] == "non_compliant"


def test_classify_device_unknown_when_platform_not_assigned_to_any_image():
    index = build_golden_version_index([_golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"})])
    device = _device("d1", "host-1", "ISR4451-X/K9", "17.6.5")  # no golden assignment for this exact PID
    result = classify_device(device, index)
    assert result["status"] == "unknown"
    assert result["golden_version"] is None
    assert result["product_family"] is None


def test_classify_device_does_not_fuzzy_match_similar_pids():
    # A close-but-not-identical PID (e.g. a different SKU in the same line)
    # must NOT be treated as compliant just because it "looks similar" —
    # that was exactly the failure mode of the old digit-token heuristic.
    index = build_golden_version_index([_golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"})])
    device = _device("d1", "host-1", "C9300-48P", "17.9.3")  # different PID, not assigned
    result = classify_device(device, index)
    assert result["status"] == "unknown"


def test_classify_device_stacked_switch_all_members_known():
    # DNAC reports a stack's platformId as a comma-separated list of every
    # member's exact PID — confirmed against a real instance where stacked
    # devices classified as "unknown" even though every member PID
    # individually had a golden image (the whole combined string was being
    # looked up as one key, which never matches).
    index = build_golden_version_index([_golden_image("17.9.3", {"C9300-48UXM": "Cisco Catalyst 9300 Series Switches"})])
    device = _device("d1", "stack-1", "C9300-48UXM,C9300-48UXM,C9300-48UXM", "17.9.3")
    result = classify_device(device, index)
    assert result["status"] == "compliant"
    assert result["product_family"] == "Cisco Catalyst 9300 Series Switches"


def test_classify_device_stacked_switch_partial_coverage_is_unknown():
    # Only one member's PID has a golden assignment — not enough
    # information to confidently call the whole stack compliant or not.
    index = build_golden_version_index([_golden_image("17.9.3", {"C9300-48UXM": "Cisco Catalyst 9300 Series Switches"})])
    device = _device("d1", "stack-1", "C9300-48UXM,C9300-24UXM", "17.9.3")
    result = classify_device(device, index)
    assert result["status"] == "unknown"


# ── compute_compliance() ─────────────────────────────────────────────────────

def test_compute_compliance_overall_and_breakdowns():
    golden_images = [
        _golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"}),
        _golden_image("17.9.5", {"ISR4451-X/K9": "Cisco 4000 Series Integrated Services Routers"}),
    ]
    devices = [
        _device("d1", "sw-k001-1", "C9300-48U", "17.9.3"),                       # compliant
        _device("d2", "sw-k001-2", "C9300-48U", "17.6.5"),                       # non_compliant
        _device("d3", "rt-k002-1", "ISR4451-X/K9", "17.9.5", family="Routers"),  # compliant
        _device("d4", "sw-k002-3", "C9500-40X", "17.12.1"),                      # unknown platform
    ]
    device_site_map = {"d1": "Global/K001", "d2": "Global/K001", "d3": "Global/K002", "d4": "Global/K002"}

    result = compute_compliance(devices, device_site_map, golden_images)

    assert result["overall"] == {"compliant": 2, "non_compliant": 1, "unknown": 1, "total": 4}

    by_site = {r["site_code"]: r for r in result["by_site"]}
    assert by_site["K001"]["compliant"] == 1
    assert by_site["K001"]["non_compliant"] == 1
    assert by_site["K002"]["compliant"] == 1
    assert by_site["K002"]["unknown"] == 1

    by_pf = {r["product_family"]: r for r in result["by_product_family"]}
    assert by_pf["Cisco Catalyst 9300 Series Switches"]["compliant"] == 1
    assert by_pf["Cisco Catalyst 9300 Series Switches"]["non_compliant"] == 1
    assert by_pf["Cisco Catalyst 9300 Series Switches"]["golden_version"] == "17.9.3"
    # Unknown devices fall back to the raw platformId as their grouping key
    # (nothing prettier is available) rather than being dropped.
    assert by_pf["C9500-40X"]["unknown"] == 1

    by_fam = {r["family"]: r for r in result["by_family"]}
    assert by_fam["Routers"]["compliant"] == 1
    assert by_fam["Switches and Hubs"]["total"] == 3


def test_compute_compliance_filters_narrow_before_aggregation():
    golden_images = [_golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"})]
    devices = [
        _device("d1", "sw-k001-1", "C9300-48U", "17.9.3"),
        _device("d2", "sw-k002-1", "C9300-48U", "17.6.5"),
    ]
    device_site_map = {"d1": "Global/K001", "d2": "Global/K002"}

    result = compute_compliance(devices, device_site_map, golden_images, site="K001")
    assert result["overall"]["total"] == 1
    assert result["overall"]["compliant"] == 1


def test_compute_compliance_product_family_filter():
    golden_images = [
        _golden_image("17.9.3", {"C9300-48U": "Cisco Catalyst 9300 Series Switches"}),
        _golden_image("17.9.5", {"ISR4451-X/K9": "Cisco 4000 Series Integrated Services Routers"}),
    ]
    devices = [
        _device("d1", "sw-k001-1", "C9300-48U", "17.9.3"),
        _device("d2", "rt-k002-1", "ISR4451-X/K9", "17.9.5", family="Routers"),
    ]
    device_site_map = {"d1": "Global/K001", "d2": "Global/K002"}

    result = compute_compliance(
        devices, device_site_map, golden_images,
        product_family="Cisco Catalyst 9300 Series Switches",
    )
    assert result["overall"]["total"] == 1
    assert result["overall"]["compliant"] == 1


def test_compute_compliance_empty_devices():
    result = compute_compliance([], {}, [])
    assert result["overall"] == {"compliant": 0, "non_compliant": 0, "unknown": 0, "total": 0}
    assert result["by_product_family"] == []
