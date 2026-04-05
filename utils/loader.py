"""
Parses the devices.txt file.

Expected format (one device per line, no header):
  <type>,<hostname>,<ip_address>

Example:
  paloalto,fw-atl-01,10.10.1.1
  paloalto,fw-den-02,10.20.1.1
  panorama,panorama-dc1,10.0.0.5

Rules:
  - Lines starting with '#' are treated as comments and skipped.
  - Blank lines are skipped.
  - Type is normalized to lowercase.
  - Duplicate hostname+IP combinations are de-duplicated with a warning.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class DeviceEntry:
    platform_type: str
    hostname: str
    ip_address: str


def load_devices(filepath: str) -> List[DeviceEntry]:
    """
    Read and parse a device list file.
    Returns a list of DeviceEntry objects.
    Raises FileNotFoundError if the file does not exist.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Device list not found: {filepath}")

    devices: List[DeviceEntry] = []
    seen: set = set()

    with open(path, "r") as fh:
        for line_num, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()

            # Skip comments and blank lines
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 3:
                logger.warning(
                    "Line %d: expected 3 comma-separated fields, got %d — skipping: %r",
                    line_num, len(parts), line,
                )
                continue

            platform_type, hostname, ip_address = parts
            platform_type = platform_type.lower()

            key = (hostname, ip_address)
            if key in seen:
                logger.warning("Line %d: duplicate entry %s / %s — skipping", line_num, hostname, ip_address)
                continue
            seen.add(key)

            devices.append(DeviceEntry(
                platform_type=platform_type,
                hostname=hostname,
                ip_address=ip_address,
            ))

    logger.info("Loaded %d device(s) from %s", len(devices), filepath)
    return devices
