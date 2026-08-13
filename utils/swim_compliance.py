"""utils/swim_compliance.py — golden-image compliance breakdown.

Answers "which devices are on the golden image, broken down by platform,
family, and site" for the Compliance dashboard (`/software/compliance`).
Pure, synchronous, in-memory — no live DNAC calls. Reads the already-warmed
`devices`/`device_site_map` caches plus the golden-images dataset
(`clients.swim.list_golden_images`, cached under `dnac_golden_images` via
the normal `datasets.py` registry), so a dashboard view costs nothing beyond
a few thousand in-memory comparisons.

**Golden-image-to-platform matching is a documented simplification, not a
confirmed contract.** DNAC's `returns_list_of_software_images` response
shape for which fields identify a platform (`productNames`, `family`, plain
`name`) isn't pinned down against a real instance the way, say,
`clients/solarwinds.py`'s field names are — so this reuses the same
model-number-token technique `utils/device_comparison_report.py::
_model_matches` already validated for the exact same class of problem
(DNAC's `platformId` ordering code vs. a prose/product-name string from a
different system): extract 3+-digit runs (`4451`, `9300`, ...) and match on
shared tokens rather than substring/equality, since the two sides format the
same hardware differently. Revisit if compliance numbers look wrong against
a real instance — the same caveat CLAUDE.md already carries for other
heuristic classifications in this codebase (e.g. the SolarWinds/DNAC device
comparison's vendor-model exclusion rules).

Three-way classification per device, not two — "unknown" is not silently
folded into "non_compliant":
  * compliant     — exact version match (utils.version_compare.versions_equal)
                     against this platform's golden version.
  * non_compliant — a golden version is known for this platform, and it
                     doesn't match.
  * unknown       — no golden image is on record for this platform at all;
                     nothing to compare against, which is itself an
                     actionable gap distinct from "out of date".
"""
from __future__ import annotations

import re
from collections import defaultdict

from utils.device_sites import resolve_site_code
from utils.version_compare import versions_equal

_MODEL_TOKEN_RE = re.compile(r"\d{3,}")


def _model_tokens(value: str | None) -> set[str]:
    return set(_MODEL_TOKEN_RE.findall(value or ""))


def _golden_candidates(image: dict) -> list[str]:
    """Best-effort platform-identifying strings out of one golden-image row —
    tries every plausible field name since the real shape isn't pinned down
    (see module docstring)."""
    candidates: list[str] = []
    product_names = image.get("productNames") or image.get("product_names") or []
    if isinstance(product_names, list):
        for p in product_names:
            if isinstance(p, dict):
                candidates.append(p.get("productName") or p.get("product_name") or "")
            elif isinstance(p, str):
                candidates.append(p)
    for key in ("family", "name", "imageName"):
        v = image.get(key)
        if isinstance(v, str):
            candidates.append(v)
    return [c for c in candidates if c]


def _golden_version(image: dict) -> str:
    return image.get("version") or image.get("imageVersion") or image.get("softwareVersion") or ""


def build_golden_version_index(golden_images: list[dict]) -> dict[str, dict]:
    """{model_token: {"version": str, "image_name": str}} — one entry per
    3+-digit model token found across every golden image's candidate
    platform strings. A device's platformId is looked up by its own token(s)
    against this index (see classify_device)."""
    index: dict[str, dict] = {}
    for image in golden_images:
        version = _golden_version(image)
        if not version:
            continue
        image_name = image.get("name") or image.get("imageName") or ""
        for candidate in _golden_candidates(image):
            for token in _model_tokens(candidate):
                index[token] = {"version": version, "image_name": image_name}
    return index


def classify_device(device: dict, golden_index: dict[str, dict]) -> dict:
    """Return {"status": "compliant"|"non_compliant"|"unknown",
    "golden_version": str|None, "golden_image_name": str|None}."""
    tokens = _model_tokens(device.get("platformId"))
    golden = None
    for t in tokens:
        if t in golden_index:
            golden = golden_index[t]
            break

    if golden is None:
        return {"status": "unknown", "golden_version": None, "golden_image_name": None}

    current = device.get("softwareVersion")
    status = "compliant" if versions_equal(current, golden["version"]) else "non_compliant"
    return {"status": status, "golden_version": golden["version"], "golden_image_name": golden["image_name"]}


def _empty_bucket() -> dict:
    return {"compliant": 0, "non_compliant": 0, "unknown": 0}


def compute_compliance(
    devices: list[dict],
    device_site_map: dict[str, str],
    golden_images: list[dict],
    *,
    platform: str | None = None,
    family: str | None = None,
    site: str | None = None,
) -> dict:
    """Full breakdown: overall totals plus by-platform/by-family/by-site
    three-way splits. Optional filters narrow the device set considered
    (applied before aggregation, so percentages reflect the filtered view)."""
    golden_index = build_golden_version_index(golden_images)

    overall = _empty_bucket()
    by_platform: dict[str, dict] = defaultdict(_empty_bucket)
    by_family: dict[str, dict] = defaultdict(_empty_bucket)
    by_site: dict[str, dict] = defaultdict(_empty_bucket)
    platform_golden: dict[str, dict] = {}

    for d in devices:
        plat = d.get("platformId") or "(unknown platform)"
        fam = d.get("family") or d.get("deviceFamily") or "(unknown family)"
        code, _source = resolve_site_code(d.get("id"), d.get("hostname"), device_site_map)
        code = code or "UNKNOWN"

        if platform and plat != platform:
            continue
        if family and fam != family:
            continue
        if site and code.upper() != site.upper():
            continue

        result = classify_device(d, golden_index)
        status = result["status"]

        overall[status] += 1
        by_platform[plat][status] += 1
        by_family[fam][status] += 1
        by_site[code][status] += 1
        if plat not in platform_golden and result["golden_version"]:
            platform_golden[plat] = {"version": result["golden_version"], "image_name": result["golden_image_name"]}

    total = sum(overall.values())

    def _rows(buckets: dict[str, dict], key_name: str, with_golden: bool = False) -> list[dict]:
        rows = []
        for key, counts in sorted(buckets.items(), key=lambda kv: -sum(kv[1].values())):
            row = {key_name: key, **counts, "total": sum(counts.values())}
            if with_golden:
                g = platform_golden.get(key)
                row["golden_version"] = g["version"] if g else None
            rows.append(row)
        return rows

    return {
        "overall": {**overall, "total": total},
        "by_platform": _rows(by_platform, "platform", with_golden=True),
        "by_family": _rows(by_family, "family"),
        "by_site": _rows(by_site, "site_code"),
    }
