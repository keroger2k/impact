import asyncio
import os
import json
import sys

# Mocking some dependencies to allow it to run outside the full app context if needed
# but since we are in the repo, we should just try to run it.

from utils.ipam_engine import IPAMEngine

async def debug():
    os.environ["DEV_MODE"] = "true"
    engine = IPAMEngine()

    class MockSession:
        def __init__(self):
            self.id = "mock"

    session = MockSession()
    loop = asyncio.get_event_loop()

    print("Starting discovery...")
    subnets = await engine.discover_all(session, loop)
    print(f"Discovered {len(subnets)} subnets")
    for s in subnets:
        print(f"  - {s.cidr} from {s.source}")

    print("Building tree...")
    engine.build_tree()
    tree = engine.get_tree()

    v4_roots = [node['cidr'] for node in tree['ipv4']]
    v6_roots = [node['cidr'] for node in tree['ipv6']]
    print(f"v4 Roots: {v4_roots}")
    print(f"v6 Roots: {v6_roots}")

if __name__ == "__main__":
    asyncio.run(debug())
