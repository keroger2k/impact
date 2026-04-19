from cache import cache
import json

inv = cache.get("nexus_inventory")
ifaces = cache.get("nexus_interfaces")

print(f"Inventory items: {len(inv) if inv else 0}")
print(f"Interfaces: {len(ifaces) if ifaces else 0}")

if inv:
    print("First inventory hostname:", inv[0].get('hostname'))

# Check for a specific config
if inv:
    host = inv[0].get('hostname')
    conf = cache.get(f"config:nexus:{host}")
    print(f"Config for {host} exists: {conf is not None}")
