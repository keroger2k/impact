import os
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class FabricConfig:
    id: str
    label: str
    url: str
    domain: str | None = None

_fabrics: dict[str, FabricConfig] = {}
_warned = False

def load_fabrics() -> dict[str, FabricConfig]:
    global _fabrics, _warned
    if _fabrics:
        return _fabrics

    fabrics = {}
    aci_fabrics_env = os.getenv("ACI_FABRICS")

    if aci_fabrics_env:
        fabric_ids = [f.strip() for f in aci_fabrics_env.split(",") if f.strip()]
        for fid in fabric_ids:
            fid_upper = fid.upper()
            url = os.getenv(f"ACI_{fid_upper}_URL")
            domain = os.getenv(f"ACI_{fid_upper}_DOMAIN")
            label = os.getenv(f"ACI_{fid_upper}_LABEL", fid)

            if url:
                fabrics[fid] = FabricConfig(id=fid, label=label, url=url, domain=domain)
            else:
                logger.error(f"ACI Fabric {fid} configured in ACI_FABRICS but ACI_{fid_upper}_URL is missing")

    # Backwards compatibility
    legacy_url = os.getenv("ACI_URL")
    if not fabrics and legacy_url:
        if not _warned:
            logger.warning("DEPRECATION: ACI_URL/ACI_DOMAIN is deprecated. Use ACI_FABRICS and ACI_<ID>_URL instead.")
            _warned = True

        fabrics["default"] = FabricConfig(
            id="default",
            label="ACI",
            url=legacy_url,
            domain=os.getenv("ACI_DOMAIN")
        )

    _fabrics = fabrics
    return _fabrics

def list_fabrics() -> list[FabricConfig]:
    return list(load_fabrics().values())

def get_fabric(fabric_id: str) -> FabricConfig:
    fabrics = load_fabrics()
    if fabric_id not in fabrics:
        raise KeyError(f"Unknown fabric: {fabric_id}")
    return fabrics[fabric_id]
