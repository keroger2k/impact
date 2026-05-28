from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse
import logging
import asyncio
from auth import require_auth, SessionEntry
from routers.commands import _run_on_device, guess_device_type
from utils.routing import correlate_next_hops
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/bgp/summary", response_class=HTMLResponse)
async def bgp_summary(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    from templates_module import templates
    from dev import DEV_MODE
    if DEV_MODE:
        mock_output = """BGP router identifier 10.10.1.1, local AS number 65001
BGP table version is 1, main routing table version 1

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.10.1.2       4        65002     100     102        1    0    0 01:22:33       10
10.20.1.1       4        65003      50      55        1    0    0 00:45:12        5
"""
        neighbors = ["10.10.1.2", "10.20.1.1"]
        correlations = correlate_next_hops(neighbors)
        corr_map = {c["ip"]: c for c in correlations}
        return templates.TemplateResponse(request, "partials/bgp_summary.html", {
            "output": mock_output,
            "correlations": corr_map
        })

    loop = asyncio.get_event_loop()
    # Auto-detect device type or default to ios
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    cmd = "show ip bgp summary"
    if dtype == "cisco_nxos":
        cmd = "show bgp ipv4 unicast summary"

    result = await loop.run_in_executor(None, _run_on_device, ip, cmd, session.username, session.password, dtype, 30)

    if result["status"] == "error":
        return HTMLResponse(f"<div class='alert alert-danger'>{result['error']}</div>")

    # Simple parsing for next hop correlation
    lines = result["output"].splitlines()
    neighbors = []
    for line in lines:
        parts = line.split()
        if parts and parts[0].count('.') == 3: # Looks like an IP
            neighbors.append(parts[0])

    correlations = correlate_next_hops(neighbors)
    corr_map = {c["ip"]: c for c in correlations}

    return templates.TemplateResponse(request, "partials/bgp_summary.html", {
        "output": result["output"],
        "correlations": corr_map
    })


@router.post("/eigrp/topology", response_class=HTMLResponse)
async def eigrp_topology(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    from templates_module import templates
    from dev import DEV_MODE
    if DEV_MODE:
        mock_output = """IP-EIGRP Topology Table for AS(1)/ID(10.10.1.1)
Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply,
       r - reply Status, s - sia Status

P 10.10.0.0/16, 1 successors, FD is 2816
        via Connected, GigabitEthernet0/1
P 10.20.0.0/16, 1 successors, FD is 3072
        via 10.10.1.2 (3072/2816), GigabitEthernet0/1
P 10.30.0.0/16, 1 successors, FD is 3328
        via 10.10.1.3 (3328/3072), GigabitEthernet0/2
"""
        next_hops = ["10.10.1.2", "10.10.1.3"]
        correlations = correlate_next_hops(next_hops)
        corr_map = {c["ip"]: c for c in correlations}
        return templates.TemplateResponse(request, "partials/eigrp_topology.html", {
            "output": mock_output,
            "correlations": corr_map
        })

    loop = asyncio.get_event_loop()
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    cmd = "show ip eigrp topology"
    result = await loop.run_in_executor(None, _run_on_device, ip, cmd, session.username, session.password, dtype, 30)

    if result["status"] == "error":
        return HTMLResponse(f"<div class='alert alert-danger'>{result['error']}</div>")

    # Simple parsing for next hop correlation
    lines = result["output"].splitlines()
    next_hops = []
    for line in lines:
        if "via " in line:
            parts = line.split()
            for p in parts:
                if p.count('.') == 3:
                    next_hops.append(p)

    correlations = correlate_next_hops(next_hops)
    corr_map = {c["ip"]: c for c in correlations}

    return templates.TemplateResponse(request, "partials/eigrp_topology.html", {
        "output": result["output"],
        "correlations": corr_map
    })

@router.post("/eigrp/neighbors", response_class=HTMLResponse)
async def eigrp_neighbors(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    """Fetch IPv4 + IPv6 EIGRP neighbors in parallel and render them
    side-by-side. Two SSH sessions per device (the cost is dominated by
    the handshake, so running them concurrently keeps the wait under
    ~5s vs. ~10s sequential)."""
    from templates_module import templates
    from dev import DEV_MODE
    if DEV_MODE:
        mock_v4 = """EIGRP-IPv4 Neighbors for AS(100)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
0   1.2.3.5                 Gi0/1                    11 01:22:33   12   100  0  42
1   1.2.3.6                 Gi0/2                    13 03:14:15   15   100  0  19
"""
        mock_v6 = """EIGRP-IPv6 Neighbors for AS(100)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
0   FE80::1                 Gi0/1                    12 01:22:33   18   100  0  42
"""
        return templates.TemplateResponse(request, "partials/eigrp_neighbors.html", {
            "v4_output": mock_v4, "v6_output": mock_v6, "ip": ip,
        })

    loop = asyncio.get_event_loop()
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    cmd_v4 = "show ip eigrp neighbors"
    cmd_v6 = "show ipv6 eigrp neighbors"

    v4_task = loop.run_in_executor(None, _run_on_device, ip, cmd_v4, session.username, session.password, dtype, 30)
    v6_task = loop.run_in_executor(None, _run_on_device, ip, cmd_v6, session.username, session.password, dtype, 30)
    v4_res, v6_res = await asyncio.gather(v4_task, v6_task)

    return templates.TemplateResponse(request, "partials/eigrp_neighbors.html", {
        "v4_output": v4_res["output"] if v4_res["status"] == "success" else None,
        "v4_error":  v4_res.get("error") if v4_res["status"] != "success" else None,
        "v6_output": v6_res["output"] if v6_res["status"] == "success" else None,
        "v6_error":  v6_res.get("error") if v6_res["status"] != "success" else None,
        "ip": ip,
    })


@router.post("/ospf/neighbors", response_class=HTMLResponse)
async def ospf_neighbors(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    from templates_module import templates
    from dev import DEV_MODE
    if DEV_MODE:
        mock_output = """Neighbor ID      Pri   State           Dead Time   Address         Interface
10.10.1.2         1   FULL/BDR        00:00:34    10.10.1.2       GigabitEthernet0/1
10.30.1.1         1   FULL/DROTHER    00:00:38    10.30.1.1       GigabitEthernet0/2
"""
        neighbors = ["10.10.1.2", "10.30.1.1"]
        correlations = correlate_next_hops(neighbors)
        corr_map = {c["ip"]: c for c in correlations}
        return templates.TemplateResponse(request, "partials/ospf_neighbors.html", {
            "output": mock_output,
            "correlations": corr_map
        })

    loop = asyncio.get_event_loop()
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    cmd = "show ip ospf neighbor"
    result = await loop.run_in_executor(None, _run_on_device, ip, cmd, session.username, session.password, dtype, 30)

    if result["status"] == "error":
        return HTMLResponse(f"<div class='alert alert-danger'>{result['error']}</div>")

    # Simple parsing for next hop correlation
    lines = result["output"].splitlines()
    neighbors = []
    for line in lines:
        parts = line.split()
        if parts and parts[0].count('.') == 3:
            # Address is typically the 5th column in Cisco IOS
            if len(parts) >= 5 and parts[4].count('.') == 3:
                neighbors.append(parts[4])
            else:
                neighbors.append(parts[0])

    correlations = correlate_next_hops(neighbors)
    corr_map = {c["ip"]: c for c in correlations}

    return templates.TemplateResponse(request, "partials/ospf_neighbors.html", {
        "output": result["output"],
        "correlations": corr_map
    })