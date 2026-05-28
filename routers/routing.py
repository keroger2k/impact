from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse
import logging
import asyncio
import re
from auth import require_auth, SessionEntry
from routers.commands import _run_on_device, guess_device_type
from utils.routing import correlate_next_hops
from cache import cache

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Neighbor-count parsers ───────────────────────────────────────────────────
# Each helper extracts a count from the raw `show` output. Returns 0 on
# empty/None/parse-miss — the panel header just renders "0 IPvX" then,
# which is the truthful answer when the box isn't peered on that family.

def _count_bgp_neighbors(output: str | None) -> int:
    """Count neighbor lines in `show ip bgp summary` /
    `show bgp ipv{4,6} unicast summary`. A neighbor line starts with an
    IPv4/IPv6 address followed by the V/AS/MsgRcvd columns."""
    if not output:
        return 0
    count = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        first = parts[0]
        is_v4 = first.count(".") == 3 and first.replace(".", "").isdigit()
        is_v6 = ":" in first and not first.endswith(":")  # exclude "Neighbor:" etc.
        if not (is_v4 or is_v6):
            continue
        # 2nd column must be the BGP version (digit). Filters out the table
        # header and any informational lines that happen to start with an IP.
        if parts[1].isdigit():
            count += 1
    return count


def _count_ospf_neighbors(output: str | None) -> int:
    """Count neighbor lines in `show ip ospf neighbor` /
    `show ipv6 ospf neighbor`. OSPFv3 still uses an IPv4 router-id as the
    Neighbor ID so the same matcher works for both families."""
    if not output:
        return 0
    count = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        first = parts[0]
        if not (first.count(".") == 3 and first.replace(".", "").isdigit()):
            continue
        # 2nd column is the priority (numeric). Filters the header row.
        if parts[1].isdigit():
            count += 1
    return count


_RE_EIGRP_NBR = re.compile(r"^\s*\d+\s+\S")


def _count_eigrp_neighbors(output: str | None) -> int:
    """Count neighbor lines in `show ip|ipv6 eigrp neighbors`. Each
    neighbor row starts with the H-index (small integer) followed by
    the address."""
    if not output:
        return 0
    return sum(1 for line in output.splitlines() if _RE_EIGRP_NBR.match(line))

@router.post("/bgp/summary", response_class=HTMLResponse)
async def bgp_summary(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    """BGP summary for both IPv4 and IPv6 unicast families.

    Both `show` commands run in parallel SSH sessions (latency is
    dominated by the handshake, so this keeps the wait under ~5s vs.
    ~10s sequential). The partial renders next-hop correlations against
    the v4 table only — DNAC IP lookup is IPv4-keyed."""
    from templates_module import templates
    from dev import DEV_MODE
    if DEV_MODE:
        mock_v4 = """BGP router identifier 10.10.1.1, local AS number 65001
BGP table version is 1, main routing table version 1

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.10.1.2       4        65002     100     102        1    0    0 01:22:33       10
10.20.1.1       4        65003      50      55        1    0    0 00:45:12        5
"""
        mock_v6 = """BGP router identifier 10.10.1.1, local AS number 65001

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
2001:db8::2     4        65002      80      82        1    0    0 01:22:33        3
"""
        neighbors = ["10.10.1.2", "10.20.1.1"]
        correlations = correlate_next_hops(neighbors)
        corr_map = {c["ip"]: c for c in correlations}
        return templates.TemplateResponse(request, "partials/bgp_summary.html", {
            "output":      mock_v4,
            "v6_output":   mock_v6,
            "v4_count":    _count_bgp_neighbors(mock_v4),
            "v6_count":    _count_bgp_neighbors(mock_v6),
            "correlations": corr_map,
            "ip": ip,
        })

    loop = asyncio.get_event_loop()
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    cmd_v4 = "show bgp ipv4 unicast summary" if dtype == "cisco_nxos" else "show ip bgp summary"
    cmd_v6 = "show bgp ipv6 unicast summary"

    v4_task = loop.run_in_executor(None, _run_on_device, ip, cmd_v4, session.username, session.password, dtype, 30)
    v6_task = loop.run_in_executor(None, _run_on_device, ip, cmd_v6, session.username, session.password, dtype, 30)
    v4_res, v6_res = await asyncio.gather(v4_task, v6_task)

    if v4_res["status"] == "error":
        return HTMLResponse(f"<div class='alert alert-danger'>{v4_res['error']}</div>")

    v4_output = v4_res["output"]
    v6_output = v6_res["output"] if v6_res["status"] == "success" else None

    # Next-hop correlation: IPv4 only (DNAC IP lookup is v4-keyed).
    neighbors = []
    for line in v4_output.splitlines():
        parts = line.split()
        if parts and parts[0].count('.') == 3:
            neighbors.append(parts[0])
    correlations = correlate_next_hops(neighbors)
    corr_map = {c["ip"]: c for c in correlations}

    return templates.TemplateResponse(request, "partials/bgp_summary.html", {
        "output":       v4_output,
        "v6_output":    v6_output,
        "v4_count":     _count_bgp_neighbors(v4_output),
        "v6_count":     _count_bgp_neighbors(v6_output),
        "correlations": corr_map,
        "ip":           ip,
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
            "v4_count":  _count_eigrp_neighbors(mock_v4),
            "v6_count":  _count_eigrp_neighbors(mock_v6),
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

    v4_output = v4_res["output"] if v4_res["status"] == "success" else None
    v6_output = v6_res["output"] if v6_res["status"] == "success" else None

    return templates.TemplateResponse(request, "partials/eigrp_neighbors.html", {
        "v4_output": v4_output,
        "v4_error":  v4_res.get("error") if v4_res["status"] != "success" else None,
        "v6_output": v6_output,
        "v6_error":  v6_res.get("error") if v6_res["status"] != "success" else None,
        "v4_count":  _count_eigrp_neighbors(v4_output),
        "v6_count":  _count_eigrp_neighbors(v6_output),
        "ip": ip,
    })


@router.post("/ospf/neighbors", response_class=HTMLResponse)
async def ospf_neighbors(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    """OSPF neighbors for both IPv4 (OSPFv2) and IPv6 (OSPFv3).

    Both `show` commands run in parallel SSH sessions. Next-hop
    correlation uses the v4 (OSPFv2) Address column."""
    from templates_module import templates
    from dev import DEV_MODE
    if DEV_MODE:
        mock_v4 = """Neighbor ID      Pri   State           Dead Time   Address         Interface
10.10.1.2         1   FULL/BDR        00:00:34    10.10.1.2       GigabitEthernet0/1
10.30.1.1         1   FULL/DROTHER    00:00:38    10.30.1.1       GigabitEthernet0/2
"""
        mock_v6 = """Neighbor ID     Pri   State           Dead Time   Interface ID    Interface
10.10.1.2         1   FULL/BDR        00:00:34    7               GigabitEthernet0/1
"""
        neighbors = ["10.10.1.2", "10.30.1.1"]
        correlations = correlate_next_hops(neighbors)
        corr_map = {c["ip"]: c for c in correlations}
        return templates.TemplateResponse(request, "partials/ospf_neighbors.html", {
            "output":      mock_v4,
            "v6_output":   mock_v6,
            "v4_count":    _count_ospf_neighbors(mock_v4),
            "v6_count":    _count_ospf_neighbors(mock_v6),
            "correlations": corr_map,
            "ip":          ip,
        })

    loop = asyncio.get_event_loop()
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    cmd_v4 = "show ip ospf neighbor"
    cmd_v6 = "show ipv6 ospf neighbor"

    v4_task = loop.run_in_executor(None, _run_on_device, ip, cmd_v4, session.username, session.password, dtype, 30)
    v6_task = loop.run_in_executor(None, _run_on_device, ip, cmd_v6, session.username, session.password, dtype, 30)
    v4_res, v6_res = await asyncio.gather(v4_task, v6_task)

    if v4_res["status"] == "error":
        return HTMLResponse(f"<div class='alert alert-danger'>{v4_res['error']}</div>")

    v4_output = v4_res["output"]
    v6_output = v6_res["output"] if v6_res["status"] == "success" else None

    # Next-hop correlation: IPv4 only.
    neighbors = []
    for line in v4_output.splitlines():
        parts = line.split()
        if parts and parts[0].count('.') == 3:
            if len(parts) >= 5 and parts[4].count('.') == 3:
                neighbors.append(parts[4])
            else:
                neighbors.append(parts[0])
    correlations = correlate_next_hops(neighbors)
    corr_map = {c["ip"]: c for c in correlations}

    return templates.TemplateResponse(request, "partials/ospf_neighbors.html", {
        "output":       v4_output,
        "v6_output":    v6_output,
        "v4_count":     _count_ospf_neighbors(v4_output),
        "v6_count":     _count_ospf_neighbors(v6_output),
        "correlations": corr_map,
        "ip":           ip,
    })