"""utils/swim_compliance.py — golden-image compliance breakdown.

Answers "which devices are on the golden image, broken down by product
family, device family, and site" for the Compliance dashboard
(`/software/compliance`). Pure, synchronous, in-memory — no live DNAC calls.
Reads the already-warmed `devices`/`device_site_map` caches plus the
golden-images dataset (`clients.swim.list_golden_images`, cached under
`dnac_golden_images` via the normal `datasets.py` registry — each image row
already carries an `assigned_products` dict, see that function), so a
dashboard view costs nothing beyond a few thousand in-memory comparisons.

**Golden-image-to-device matching is exact, keyed on DNAC's own assigned
product IDs** (`clients.swim.get_assigned_products` — PID, matching a
device's `platformId` exactly), not a heuristic. An earlier version of this
module matched by extracting shared 3+-digit "model number" tokens out of
`platformId` and an image's `productNames` strings — the same class of
device-comparison-report trick, but wrong here for a reason that trick
doesn't have: a heuristic "looks similar" match is a false compatibility
signal an operator could act on when deciding which devices to push an image
to, not just a display nicety. DNAC's own per-image assigned-products list is
the actual source of truth for that, so both this dashboard and the
distribution/activation compatibility gate (`routers/swim.py`) are now built
on the same data.

Two distinct "family" axes exist here, intentionally not conflated:
  * **product family** — DNAC's own per-image assigned product name (e.g.
    "Cisco Catalyst 9300 Series Switches"), driven by the exact-PID index
    below. This is the primary compliance axis (`by_product_family`).
  * **device family** — DNAC's coarse `family`/`deviceFamily` field (e.g.
    "Switches and Hubs", "Routers"), unrelated and unchanged
    (`by_family`) — a broader category than a specific product line.

Three-way classification per device, not two — "unknown" is not silently
folded into "non_compliant":
  * compliant     — exact version match (utils.version_compare.versions_equal)
                     against this device's golden version.
  * non_compliant — a golden version is known for this exact platformId, and
                     it doesn't match.
  * unknown       — no golden image is assigned to this platformId at all;
                     nothing to compare against, which is itself an
                     actionable gap distinct from "out of date".
"""
from __future__ import annotations

from collections import defaultdict

from utils.device_sites import resolve_site_code
from utils.version_compare import versions_equal


def _golden_version(image: dict) -> str:
    return image.get("version") or image.get("imageVersion") or image.get("softwareVersion") or ""


def build_golden_version_index(golden_images: list[dict]) -> dict[str, dict]:
    """{platformId: {"version": str, "image_name": str, "product_family": str}}
    — one entry per exact PID DNAC has assigned to a golden image (see
    clients.swim.get_assigned_products). A device's platformId is looked up
    directly against this index (see classify_device) — no fuzzy matching."""
    index: dict[str, dict] = {}
    for image in golden_images:
        version = _golden_version(image)
        if not version:
            continue
        image_name = image.get("name") or image.get("imageName") or ""
        assigned = image.get("assigned_products") or {}
        for pid, product_name in assigned.items():
            index[pid] = {"version": version, "image_name": image_name, "product_family": product_name or pid}
    return index


def classify_device(device: dict, golden_index: dict[str, dict]) -> dict:
    """Return {"status": "compliant"|"non_compliant"|"unknown",
    "golden_version": str|None, "golden_image_name": str|None,
    "product_family": str|None}. Exact platformId lookup — no partial or
    token-based matching."""
    golden = golden_index.get(device.get("platformId"))

    if golden is None:
        return {"status": "unknown", "golden_version": None, "golden_image_name": None, "product_family": None}

    current = device.get("softwareVersion")
    status = "compliant" if versions_equal(current, golden["version"]) else "non_compliant"
    return {
        "status": status, "golden_version": golden["version"],
        "golden_image_name": golden["image_name"], "product_family": golden["product_family"],
    }


def _empty_bucket() -> dict:
    return {"compliant": 0, "non_compliant": 0, "unknown": 0}


def compute_compliance(
    devices: list[dict],
    device_site_map: dict[str, str],
    golden_images: list[dict],
    *,
    product_family: str | None = None,
    family: str | None = None,
    site: str | None = None,
) -> dict:
    """Full breakdown: overall totals plus by-product-family/by-device-family/
    by-site three-way splits. Optional filters narrow the device set
    considered (applied before aggregation, so percentages reflect the
    filtered view). `product_family` filters on the DNAC-assigned family
    name (or raw platformId for devices with no known assignment);
    `family` filters on DNAC's separate, coarser device-family field."""
    golden_index = build_golden_version_index(golden_images)

    overall = _empty_bucket()
    by_product_family: dict[str, dict] = defaultdict(_empty_bucket)
    by_family: dict[str, dict] = defaultdict(_empty_bucket)
    by_site: dict[str, dict] = defaultdict(_empty_bucket)
    family_golden: dict[str, dict] = {}

    for d in devices:
        fam = d.get("family") or d.get("deviceFamily") or "(unknown family)"
        code, _source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
        code = code or "UNKNOWN"

        result = classify_device(d, golden_index)
        status = result["status"]
        # Fall back to the raw platformId when no golden assignment is known
        # for it — still a usable grouping key, just not a pretty label,
        # since nothing better exists for that platform yet.
        pfam = result["product_family"] or d.get("platformId") or "(unknown platform)"

        if product_family and pfam != product_family:
            continue
        if family and fam != family:
            continue
        if site and code.upper() != site.upper():
            continue

        overall[status] += 1
        by_product_family[pfam][status] += 1
        by_family[fam][status] += 1
        by_site[code][status] += 1
        if pfam not in family_golden and result["golden_version"]:
            family_golden[pfam] = {"version": result["golden_version"]}

    total = sum(overall.values())

    def _rows(buckets: dict[str, dict], key_name: str, with_golden: bool = False) -> list[dict]:
        rows = []
        for key, counts in sorted(buckets.items(), key=lambda kv: -sum(kv[1].values())):
            row = {key_name: key, **counts, "total": sum(counts.values())}
            if with_golden:
                g = family_golden.get(key)
                row["golden_version"] = g["version"] if g else None
            rows.append(row)
        return rows

    return {
        "overall": {**overall, "total": total},
        "by_product_family": _rows(by_product_family, "product_family", with_golden=True),
        "by_family": _rows(by_family, "family"),
        "by_site": _rows(by_site, "site_code"),
    }
