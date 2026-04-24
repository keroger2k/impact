import asyncio
import logging
from auth import SessionEntry, get_dnac_for_session, get_ise_for_session, get_panorama_key_for_session, get_aci_for_session
from cache import cache, TTL_STATUS
from logger_config import run_with_context

logger = logging.getLogger(__name__)

async def get_system_status(session: SessionEntry):
    """Aggregated live connectivity check for all systems using user credentials."""
    loop = asyncio.get_event_loop()

    systems = [
        ("dnac", _check_dnac),
        ("ise", _check_ise),
        ("panorama", _check_panorama),
        ("aci", _check_aci),
    ]

    results = {}
    for name, checker in systems:
        try:
            res = await asyncio.wait_for(checker(session, loop), timeout=10)
            if name == "aci" and isinstance(res, dict) and any(k.startswith("aci_") for k in res.keys()):
                results.update(res)
            else:
                results[name] = res
        except asyncio.TimeoutError:
            results[name] = {"ok": False, "detail": "Timeout"}
        except Exception as e:
            results[name] = {"ok": False, "detail": str(e)[:80]}

    return results

async def _check_dnac(session, loop):
    from dev import DEV_MODE
    if DEV_MODE: return {"ok": True, "detail": "25 devices (mock)"}

    key = "status_dnac_live"
    cached = cache.get(key)
    if cached: return cached

    try:
        dnac = get_dnac_for_session(session)
        result = await loop.run_in_executor(
            None,
            run_with_context(lambda: dnac.custom_caller.call_api("GET", "/dna/intent/api/v1/network-device/count"))
        )
        count = getattr(result, "response", 0)
        res = {"ok": True, "detail": f"{count:,} devices"}
        cache.set(key, res, TTL_STATUS)
        return res
    except Exception as e:
        return {"ok": False, "detail": str(e)[:80]}

async def _check_ise(session, loop):
    from dev import DEV_MODE
    if DEV_MODE: return {"ok": True, "detail": "Connected (mock)"}

    key = "status_ise_live"
    cached = cache.get(key)
    if cached: return cached

    try:
        import clients.ise as ic
        ise = get_ise_for_session(session)
        ok = await loop.run_in_executor(None, run_with_context(ic.connectivity_check, ise))
        res = {"ok": ok, "detail": "Connected" if ok else "Unreachable"}
        cache.set(key, res, TTL_STATUS)
        return res
    except Exception as e:
        return {"ok": False, "detail": str(e)[:80]}

async def _check_panorama(session, loop):
    from dev import DEV_MODE
    if DEV_MODE: return {"ok": True, "detail": "Connected (mock)"}

    key = "status_panorama_live"
    cached = cache.get(key)
    if cached: return cached

    try:
        import clients.panorama as pc
        pan_key = get_panorama_key_for_session(session)
        ok, detail = await loop.run_in_executor(None, run_with_context(pc.connectivity_check_with_key, pan_key))
        res = {"ok": ok, "detail": detail}
        cache.set(key, res, TTL_STATUS)
        return res
    except Exception as e:
        return {"ok": False, "detail": str(e)[:80]}

async def _check_aci(session, loop):
    import clients.aci_registry as reg
    from routers.aci import _get_processed_nodes
    from dev import DEV_MODE

    fabrics = reg.list_fabrics()
    results = {}

    async def _check_single(fabric):
        fid = fabric.id
        key = f"status_aci_{fid}_live"
        cached = cache.get(key)
        if cached: return fid, cached

        if DEV_MODE:
            res = {"ok": True, "detail": "Connected (mock)"}
            cache.set(key, res, TTL_STATUS)
            return fid, res

        try:
            aci_client = get_aci_for_session(session, fid)
            processed, _ = await _get_processed_nodes(aci_client, loop, fid)
            if processed:
                up = len([n for n in processed if n.get('status') == 'active'])
                res = {"ok": True, "detail": f"{up}/{len(processed)} Nodes"}
            else:
                res = {"ok": False, "detail": "No nodes found"}
            cache.set(key, res, TTL_STATUS)
            return fid, res
        except Exception as e:
            res = {"ok": False, "detail": str(e)[:80]}
            return fid, res

    if not fabrics:
        return {"ok": False, "detail": "No fabrics configured"}

    tasks = [_check_single(f) for f in fabrics]
    check_results = await asyncio.gather(*tasks)

    for fid, res in check_results:
        results[f"aci_{fid}"] = res

    # Requirement: "report per-fabric connectivity with ids like aci_dc1, aci_dc2, aci_dc3"
    # The caller expects a single dict for 'aci' in the main results, or multiple entries.
    # We also include a legacy 'aci' key for dashboard templates that expect it.
    # RULE: 'aci' is green only if every configured fabric is up.
    if results:
        all_ok = all(res.get("ok", False) for res in results.values())
        total = len([k for k in results if k.startswith("aci_")])
        online = len([k for k in results if k.startswith("aci_") and results[k].get("ok")])

        results["aci"] = {
            "ok": all_ok,
            "detail": f"{online}/{total} Fabrics Up" if not all_ok else f"{total} Fabrics Up"
        }

    return results
