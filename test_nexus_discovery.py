import asyncio
import os
import json
from utils.ipam_engine import IPAMEngine
from dev import seed_cache
from cache import cache

async def test():
    os.environ["DEV_MODE"] = "true"
    seed_cache(cache)

    engine = IPAMEngine()

    class MockSession:
        username = "admin"
        password = "admin"
        _lock = asyncio.Lock()

    session = MockSession()
    loop = asyncio.get_event_loop()

    print("Running Nexus discovery...")
    subnets = await engine._discover_nexus(session, loop)
    print(f"Subnets found: {len(engine.subnets)}")
    for s in engine.subnets:
        print(f"  - {s.cidr} from {s.source} (Device: {s.device}, Site: {s.site})")

if __name__ == "__main__":
    asyncio.run(test())
