from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class InterfaceResult:
    """
    Normalized interface record returned by every collector.
    Adding a new platform means populating these same fields —
    the output layer never needs to change.
    """
    hostname: str
    device_ip: str
    platform: str
    interface_name: str
    ipv4_address: str          # "x.x.x.x/prefix" or "N/A"
    ipv6_addresses: List[str]  # list of "addr/prefix" strings, may be empty
    zone: str = ""        # ← add this
    mac_address: str = "N/A"   # "xx:xx:xx:xx:xx:xx" or "N/A"
    input_bytes: Optional[int] = None   # cumulative RX byte counter, since last clear
    output_bytes: Optional[int] = None  # cumulative TX byte counter, since last clear
    error: Optional[str] = None

    @property
    def ipv6_display(self) -> str:
        return ", ".join(self.ipv6_addresses) if self.ipv6_addresses else "N/A"

    @property
    def total_bytes(self) -> Optional[int]:
        """Combined RX+TX traffic, or None if neither counter was collected."""
        if self.input_bytes is None and self.output_bytes is None:
            return None
        return (self.input_bytes or 0) + (self.output_bytes or 0)

    @property
    def has_error(self) -> bool:
        return self.error is not None