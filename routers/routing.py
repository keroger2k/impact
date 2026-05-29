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

# BGP neighbors are collected with `show ip bgp all neighbors` (IOS) /
# `show bgp all neighbors` (NXOS), which enumerate every neighbor across ALL
# address families AND all VRFs. The per-AF summary commands used previously
# only covered the global table, so VRF peers were invisible. The output is
# per-neighbor detail blocks headed by
#   "BGP neighbor is <addr>[,  vrf <name>],  remote AS <asn>, ..."
_RE_BGP_HDR   = re.compile(r"BGP neighbor is\s+([0-9A-Fa-f:.]+)")
_RE_BGP_VRF   = re.compile(r",\s*vrf\s+(\S+?)\s*,")
_RE_BGP_AS    = re.compile(r"remote AS\s+(\d+)")
_RE_BGP_STATE = re.compile(r"BGP state\s*=\s*(\w+)")


def _parse_bgp_neighbors(output: str | None) -> list[dict]:
    """Parse `show ip bgp all neighbors` detail into structured neighbors.

    Returns one dict per neighbor — ``{ip, family, vrf, remote_as, state,
    established}`` — across every address family and VRF. Works for both IOS
    and NXOS (both head each block with "BGP neighbor is")."""
    if not output:
        return []
    out: list[dict] = []
    # Split on the per-neighbor header so each block carries its own state line.
    for block in re.split(r"(?=BGP neighbor is\s)", output):
        m = _RE_BGP_HDR.search(block)
        if not m:
            continue
        ip = m.group(1).rstrip(",")
        is_v4 = ip.count(".") == 3 and ip.replace(".", "").isdigit()
        is_v6 = ":" in ip
        if not (is_v4 or is_v6):
            continue
        header = block.splitlines()[0]
        vrf_m = _RE_BGP_VRF.search(header)
        as_m = _RE_BGP_AS.search(header) or _RE_BGP_AS.search(block)
        st_m = _RE_BGP_STATE.search(block)
        state = st_m.group(1) if st_m else "—"
        out.append({
            "ip": ip,
            "family": 4 if is_v4 else 6,
            "vrf": vrf_m.group(1) if vrf_m else "default",
            "remote_as": as_m.group(1) if as_m else "",
            "state": state,
            "established": state.lower() == "established",
        })
    return out


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


# ── Neighbor row parsers (raw `show` → structured rows for clean tables) ──────
# The count helpers above stay as the authoritative header badge; these add
# per-row structure so the panels render as tables instead of raw CLI dumps.
# Token-based (column whitespace varies by platform/terminal width). A parse
# miss just yields [] and the template falls back to showing the raw output, so
# nothing is ever hidden.

def _is_ipv4(tok: str) -> bool:
    parts = tok.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts)


_RE_LINKLOCAL = re.compile(r"fe80::\S+", re.I)
_EIGRP_COLS = ("h", "address", "interface", "hold", "uptime", "srtt", "rto", "q", "seq")


def _parse_eigrp_v4(output: str | None) -> list[dict]:
    """`show ip eigrp neighbors`: H Address Iface Hold Uptime SRTT RTO Q Seq."""
    rows = []
    for line in (output or "").splitlines():
        t = line.split()
        if len(t) >= 9 and t[0].isdigit() and _is_ipv4(t[1]):
            rows.append(dict(zip(_EIGRP_COLS, t[:9])))
    return rows


def _parse_eigrp_v6(output: str | None) -> list[dict]:
    """`show ipv6 eigrp neighbors`: the neighbor prints as 'Link-local
    address:' on the row with the FE80:: address on the *next* line; also
    tolerates an inline IPv6 address."""
    lines = (output or "").splitlines()
    rows = []
    for i, line in enumerate(lines):
        t = line.split()
        if len(t) >= 10 and t[0].isdigit() and t[1].lower() == "link-local":
            addr = ""
            if i + 1 < len(lines):
                m = _RE_LINKLOCAL.search(lines[i + 1])
                if m:
                    addr = m.group(0)
            rows.append({"h": t[0], "address": addr or "link-local",
                         "interface": t[3], "hold": t[4], "uptime": t[5],
                         "srtt": t[6], "rto": t[7], "q": t[8], "seq": t[9]})
        elif len(t) >= 9 and t[0].isdigit() and ":" in t[1]:
            rows.append(dict(zip(_EIGRP_COLS, t[:9])))
    return rows


def _ospf_state_class(state: str) -> str:
    """Bootstrap color token for an OSPF adjacency state."""
    s = (state or "").upper()
    if s.startswith("FULL"):
        return "success"
    if any(x in s for x in ("DOWN", "INIT", "ATTEMPT", "EXSTART", "EXCHANGE", "LOADING")):
        return "warning"
    return "secondary"  # 2-WAY / DROTHER-DROTHER and the like — normal, not "up"


def _parse_ospf_neighbors(output: str | None) -> list[dict]:
    """`show ip|ipv6 ospf neighbor`: Neighbor-ID Pri State Dead-Time
    Address|Iface-ID Interface. OSPFv3 keeps an IPv4 router-id, so the same
    matcher works for both families."""
    rows = []
    for line in (output or "").splitlines():
        t = line.split()
        if len(t) >= 6 and _is_ipv4(t[0]) and t[1].isdigit():
            rows.append({"neighbor_id": t[0], "pri": t[1], "state": t[2],
                         "state_class": _ospf_state_class(t[2]),
                         "dead_time": t[3], "address": t[4], "interface": t[5]})
    return rows

@router.post("/bgp/summary", response_class=HTMLResponse)
async def bgp_summary(
    request: Request,
    ip: str = Form(...),
    session: SessionEntry = Depends(require_auth)
):
    """BGP health for a device across ALL address families and VRFs.

    Uses a single `show ip bgp all neighbors` (IOS) / `show bgp all neighbors`
    (NXOS) — the older per-AF summary commands only saw the global table, so
    IPv4/IPv6 neighbors living in a VRF were missed entirely. Next-hop
    correlation runs on the IPv4 neighbors (DNAC IP lookup is v4-keyed)."""
    from templates_module import templates
    from dev import DEV_MODE

    def _render(raw_output: str):
        neighbors = _parse_bgp_neighbors(raw_output)
        v4 = [n["ip"] for n in neighbors if n["family"] == 4]
        corr_map = {c["ip"]: c for c in correlate_next_hops(v4)}
        return templates.TemplateResponse(request, "partials/bgp_summary.html", {
            "neighbors":    neighbors,
            "raw_output":   raw_output,
            "v4_count":     sum(1 for n in neighbors if n["family"] == 4),
            "v6_count":     sum(1 for n in neighbors if n["family"] == 6),
            "up_count":     sum(1 for n in neighbors if n["established"]),
            "correlations": corr_map,
            "ip":           ip,
        })

    if DEV_MODE:
        return _render(
            "BGP neighbor is 10.10.1.2,  remote AS 65002, external link\n"
            "  BGP version 4, remote router ID 10.10.1.2\n"
            "  BGP state = Established, up for 01:22:33\n"
            "BGP neighbor is 10.20.1.1,  vrf MGMT,  remote AS 65003, external link\n"
            "  BGP version 4, remote router ID 10.20.1.1\n"
            "  BGP state = Established, up for 00:45:12\n"
            "BGP neighbor is 1000:2000:3000::2,  remote AS 65002, external link\n"
            "  BGP version 4, remote router ID 10.10.1.2\n"
            "  BGP state = Idle\n"
        )

    loop = asyncio.get_event_loop()
    devices = cache.get("devices") or []
    device = next((d for d in devices if d.get("managementIpAddress") == ip), {})
    dtype = guess_device_type(device.get("platformId", ""))

    # All-AF, all-VRF neighbor detail in one command.
    cmd = "show bgp all neighbors" if dtype == "cisco_nxos" else "show ip bgp all neighbors"
    res = await loop.run_in_executor(None, _run_on_device, ip, cmd, session.username, session.password, dtype, 60)

    if res["status"] == "error":
        return HTMLResponse(f"<div class='alert alert-danger'>{res['error']}</div>")

    return _render(res["output"])


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
            "v4_rows":   _parse_eigrp_v4(mock_v4),
            "v6_rows":   _parse_eigrp_v6(mock_v6),
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
        "v4_rows":   _parse_eigrp_v4(v4_output),
        "v6_rows":   _parse_eigrp_v6(v6_output),
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
            "v4_rows":     _parse_ospf_neighbors(mock_v4),
            "v6_rows":     _parse_ospf_neighbors(mock_v6),
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
        "v4_rows":      _parse_ospf_neighbors(v4_output),
        "v6_rows":      _parse_ospf_neighbors(v6_output),
        "v4_count":     _count_ospf_neighbors(v4_output),
        "v6_count":     _count_ospf_neighbors(v6_output),
        "correlations": corr_map,
        "ip":           ip,
    })