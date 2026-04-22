import sys
import os
import xml.etree.ElementTree as ET
import requests
import urllib3
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

import clients.panorama as pc

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) < 2:
        print("Usage: python pan_diag.py <serial> [command]")
        print("Example: python pan_diag.py 0123456789 \"<show><zone></show>\"")
        sys.exit(1)

    serial = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "<show><zone></show>"

    key = pc.get_api_key()
    if not key:
        print("Error: Could not obtain Panorama API key. Check .env")
        sys.exit(1)

    host = os.getenv("PANORAMA_HOST")
    host_clean = host.strip().split('/')[0]

    print(f"--- Querying Panorama ({host_clean}) for Target: {serial} ---")
    print(f"Command: {cmd}")

    try:
        resp = requests.get(
            f"https://{host_clean}/api/",
            params={"type": "op", "cmd": cmd, "key": key, "target": serial},
            verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true",
            timeout=20,
        )

        print("\n--- RAW XML RESPONSE ---")
        print(resp.text)

        root = ET.fromstring(resp.text)
        if root.attrib.get("status") == "success":
            print("\n--- PARSED ZONES ---")
            result = root.find("result")
            if result is not None:
                for entry in result.findall(".//entry"):
                    zone_name = entry.get("name") or entry.findtext("name")
                    print(f"Zone: {zone_name}")
                    ifaces = entry.findall(".//interface/member") + entry.findall("./member")
                    for iface in ifaces:
                        print(f"  - Interface: {iface.text}")
        else:
            print(f"\nError: Panorama returned status '{root.attrib.get('status')}'")
            msg = root.findtext(".//msg")
            if msg: print(f"Message: {msg}")

    except Exception as e:
        print(f"\nException occurred: {e}")

if __name__ == "__main__":
    main()
