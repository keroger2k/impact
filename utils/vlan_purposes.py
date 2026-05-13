"""Short, human-readable labels for VLAN IDs used in TSA's network.

Edit VLAN_PURPOSES below to add or rename entries. The labels are surfaced
in the IPAM dashboard (as the row label, when known) and in the
SolarWinds CSV's Group Description column.
"""
from typing import Optional

VLAN_PURPOSES: dict[int, str] = {
    100: "Data VLAN",
    500: "STIP VLAN",
    600: "Voice VLAN",
    700: "HSDN VLAN",
    800: "eTAS VLAN",
}


def describe_vlan(vlan_id) -> Optional[str]:
    """Return the short purpose label for ``vlan_id`` or ``None`` if unknown."""
    if vlan_id is None:
        return None
    try:
        vid = int(vlan_id)
    except (TypeError, ValueError):
        return None
    return VLAN_PURPOSES.get(vid)
