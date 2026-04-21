"""
clients/aci.py — Cisco ACI REST API client.
"""

import logging
import os
import re
import time
import urllib.parse
import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

def _quote_dn(dn: str) -> str:
    """
    Escapes special characters in an ACI Distinguished Name (DN) while preserving
    the hierarchy separators (slashes) and bracketed structure. Internal slashes
    within brackets (e.g., BGP prefixes) are correctly escaped to prevent 400
    Bad Request errors.
    """
    if not dn:
        return ""
    # Matches sequences of (non-slash non-bracket) OR (bracketed content which may contain slashes)
    segments = re.findall(r'(?:[^/\[]+|\[[^\]]*\])+', dn)
    # Re-assemble with / separator, quoting each segment but keeping brackets and colons safe
    return "/".join(urllib.parse.quote(s, safe=':[]') for s in segments)

class ACIClient:
    def __init__(self, url, username, password, domain=None):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.domain = domain
        self.session = requests.Session()
        self.token = None

    def login(self):
        """Authenticate with the APIC and store the session token."""
        from dev import DEV_MODE
        if DEV_MODE:
            self.token = "mock-token"
            return True

        login_url = f"{self.url}/api/aaaLogin.json"

        # Format username if domain is provided
        if self.domain:
            formatted_user = f"apic#{self.domain}\\{self.username}"
        else:
            formatted_user = self.username

        payload = {
            "aaaUser": {
                "attributes": {
                    "name": formatted_user,
                    "pwd": self.password
                }
            }
        }

        start_time = time.time()
        try:
            response = self.session.post(login_url, json=payload, verify=False, timeout=10)
            duration = int((time.time() - start_time) * 1000)
            logger.info(f"ACI Login: {formatted_user}", extra={
                "target": "ACI",
                "action": "LOGIN",
                "status": response.status_code,
                "duration_ms": duration
            })
            logger.debug(f"ACI Login payload: {payload}", extra={"payload": payload})

            response.raise_for_status()
            data = response.json()
            self.token = data['imdata'][0]['aaaLogin']['attributes']['token']

            logger.debug(f"ACI Login response: {data}", extra={"payload": data})
            return True
        except Exception as e:
            duration = int((time.time() - start_time) * 1000)
            status = getattr(e.response, 'status_code', 500) if hasattr(e, 'response') else 500
            logger.error(f"ACI Login failed for {self.url}: {e}", extra={
                "target": "ACI",
                "action": "LOGIN",
                "status": status,
                "duration_ms": duration
            })
            return False

    def get(self, path, action="GET_DATA"):
        """Generic GET request to the APIC."""
        from dev import DEV_MODE
        if DEV_MODE:
            from dev import (
                MOCK_ACI_NODES, MOCK_ACI_L3OUTS, MOCK_ACI_BGP_PEERS,
                MOCK_ACI_SUBNETS, MOCK_ACI_EPGS, MOCK_ACI_FAULT_INST,
                MOCK_ACI_BGP_DOMS, MOCK_ACI_BGP_RIB_IN, MOCK_ACI_BGP_RIB_OUT,
                MOCK_ACI_BGP_DOMS_ALL, MOCK_ACI_BGP_PEER_CFG,
                MOCK_ACI_BGP_ADJ_RIB_IN, MOCK_ACI_BGP_ADJ_RIB_OUT
            )
            if "fabricNode" in path: return {"imdata": MOCK_ACI_NODES}
            if "l3extOut" in path: return {"imdata": MOCK_ACI_L3OUTS}
            if "bgpPeerEntry" in path: return {"imdata": MOCK_ACI_BGP_PEERS}
            if "l3extSubnet" in path: return {"imdata": MOCK_ACI_SUBNETS}
            if "fvSubnet" in path:
                return {
                    "imdata": [
                        {"fvSubnet": {"attributes": {"ip": "10.10.10.1/24", "dn": "uni/tn-TSA-HQ/BD-Users/subnet-[10.10.10.1/24]", "descr": "User Access"}}},
                        {"fvSubnet": {"attributes": {"ip": "fc00:10::1/64", "dn": "uni/tn-TSA-HQ/BD-Users/subnet-[fc00:10::1/64]", "descr": "User Access IPv6"}}}
                    ]
                }
            if "fvAEPg" in path: return {"imdata": MOCK_ACI_EPGS}
            if "faultInst" in path: return {"imdata": MOCK_ACI_FAULT_INST}
            if "bgpDomAf.json" in path: return {"imdata": MOCK_ACI_BGP_DOMS_ALL}
            if "target-subtree-class=bgpRoute" in path: return {"imdata": MOCK_ACI_BGP_DOMS}
            if "bgpPeerP" in path: return {"imdata": MOCK_ACI_BGP_PEER_CFG}
            if "class/bgpAdjRibIn" in path: return {"imdata": MOCK_ACI_BGP_ADJ_RIB_IN}
            if "class/bgpAdjRibOut" in path: return {"imdata": MOCK_ACI_BGP_ADJ_RIB_OUT}
            if "bgpAdjRibIn" in path: return {"imdata": MOCK_ACI_BGP_RIB_IN}
            if "bgpAdjRibOut" in path: return {"imdata": MOCK_ACI_BGP_RIB_OUT}
            return {"imdata": []}

        if not self.token:
            if not self.login():
                return None

        url = f"{self.url}/{path.lstrip('/')}"
        start_time = time.time()
        try:
            response = self.session.get(url, verify=False, timeout=15)
            duration = int((time.time() - start_time) * 1000)
            logger.info(f"ACI GET {path}", extra={
                "target": "ACI",
                "action": action,
                "status": response.status_code,
                "duration_ms": duration
            })

            response.raise_for_status()
            data = response.json()
            logger.debug(f"ACI response body: {data}", extra={"payload": data})
            return data
        except Exception as e:
            duration = int((time.time() - start_time) * 1000)
            status = getattr(e.response, 'status_code', 500) if hasattr(e, 'response') else 500
            logger.error(f"ACI GET {path} failed: {e}", extra={
                "target": "ACI",
                "action": action,
                "status": status,
                "duration_ms": duration
            })
            return None

    def get_fabric_nodes(self):
        """List all fabricNode objects."""
        return self.get("api/node/class/fabricNode.json", action="FETCH_ACI_NODES")

    def get_l3outs(self, tenant=None):
        """Fetch L3Out configurations."""
        if tenant:
            path = f"api/node/mo/uni/tn-{tenant}.json?query-target=subtree&target-subtree-class=l3extOut"
        else:
            path = "api/node/class/l3extOut.json"
        return self.get(path, action="FETCH_ACI_L3OUTS")

    def get_l3out_details(self, dn):
        """Fetch details for a specific L3Out including children like node profiles and interface profiles."""
        # Query with rsp-subtree=full to get children
        path = f"api/node/mo/{_quote_dn(dn)}.json?rsp-subtree=full"
        return self.get(path, action="FETCH_ACI_L3OUT_DETAIL")

    def get_bgp_peers(self):
        """Query bgpPeerEntry for BGP neighbor states."""
        return self.get("api/node/class/bgpPeerEntry.json", action="FETCH_ACI_BGP_PEERS")

    def get_ospf_peers(self):
        """Query ospfAdjEp for OSPF neighbor states."""
        return self.get("api/node/class/ospfAdjEp.json", action="FETCH_ACI_OSPF_PEERS")

    def get_l3_subnets(self):
        """Query l3extSubnet for external subnet policies."""
        return self.get("api/node/class/l3extSubnet.json", action="FETCH_ACI_SUBNETS")

    def get_bgp_routes(self, dn):
        """Query all BGP route types on a specific node."""
        if "topology/" not in dn:
            dn = f"topology/pod-1/node-{dn}"
        # Query route classes directly to get a clean list
        path = f"api/node/mo/{_quote_dn(dn)}.json?query-target=subtree&target-subtree-class=bgpRoute,bgpBdpRoute,bgpEvpnRoute"
        return self.get(path, action="FETCH_ACI_BGP_ROUTES")

    def get_all_bgp_doms(self):
        """Query all bgpDomAf objects across the fabric to get route counts."""
        # We query bgpDomAf and count its route children.
        # This is more accurate than counting all children of bgpDom.
        # We remove redundant query parameters that can cause 400 errors on some versions
        path = "api/node/class/bgpDomAf.json?rsp-subtree-include=count&page-size=1000"
        return self.get(path, action="FETCH_ACI_BGP_DOMS")

    def get_epgs(self, tenant=None):
        """Fetch Endpoint Groups (fvAEPg) with health score."""
        if tenant:
            path = f"api/node/mo/uni/tn-{_quote_dn(tenant)}.json?query-target=subtree&target-subtree-class=fvAEPg&rsp-subtree-include=health"
        else:
            path = "api/node/class/fvAEPg.json?rsp-subtree-include=health"
        return self.get(path, action="FETCH_ACI_EPGS")

    def get_bgp_adj_rib(self, peer_dn, direction="in"):
        """Fetch BGP Received or Advertised routes for a specific peer."""
        # direction can be "in" (bgpAdjRibIn) or "out" (bgpAdjRibOut)
        cls = "bgpAdjRibIn" if direction == "in" else "bgpAdjRibOut"
        path = f"api/node/mo/{_quote_dn(peer_dn)}.json?query-target=subtree&target-subtree-class={cls}"
        return self.get(path, action=f"FETCH_ACI_BGP_RIB_{direction.upper()}")

    def get_bgp_peer_configs(self):
        """Query bgpPeerP (policy-space) to map peer IPs to their L3Outs."""
        return self.get("api/node/class/bgpPeerP.json", action="FETCH_ACI_BGP_PEER_CFG")

    def get_bgp_advertised_routes(self):
        """Fabric-wide query for all bgpAdjRibOut (TX) routes."""
        return self.get("api/node/class/bgpAdjRibOut.json?page-size=1000", action="FETCH_ACI_BGP_ADJ_RIB_OUT")

    def get_bgp_received_routes(self):
        """Fabric-wide query for all bgpAdjRibIn (RX) routes."""
        return self.get("api/node/class/bgpAdjRibIn.json?page-size=1000", action="FETCH_ACI_BGP_ADJ_RIB_IN")

    def get_epg_stats(self, dn):
        """Fetch health and stats for a specific EPG."""
        # healthInst and dbgrStats
        path = f"api/node/mo/{_quote_dn(dn)}.json?rsp-subtree-include=health,stats"
        return self.get(path, action="FETCH_ACI_EPG_STATS")

    def get_faults(self, severity=None):
        """Fetch faults."""
        if severity:
            path = f"api/node/class/faultInst.json?query-target-filter=eq(faultInst.severity,\"{severity}\")"
        else:
            path = "api/node/class/faultInst.json"
        return self.get(path, action="FETCH_ACI_FAULTS")

    def get_health_score(self, dn="topology/health"):
        """Fetch health score for a specific DN."""
        path = f"api/node/mo/{_quote_dn(dn)}.json?rsp-subtree-include=health"
        return self.get(path, action="FETCH_ACI_HEALTH")

    def get_overall_health(self):
        """Fetch overall system health score."""
        return self.get_health_score("topology/health")

    def get_tenant_health(self):
        """Fetch health scores for all tenants."""
        path = "api/node/class/fvTenant.json?rsp-subtree-include=health"
        return self.get(path)

    def get_pod_health(self):
        """Fetch health scores for pods."""
        # Some ACI versions prefer fabricPod objects directly
        # If health subtree fails (400), we fallback to the class itself
        path = "api/node/class/fabricPod.json?rsp-subtree-include=health"
        resp = self.get(path)
        if resp is None:
            return self.get("api/node/class/fabricPod.json")
        return resp

def connectivity_check(client: ACIClient) -> bool:
    """Verify APIC is reachable using the existing session token."""
    try:
        resp = client.get("api/node/class/fabricPod.json?rsp-subtree-include=count")
        return resp is not None
    except Exception:
        return False
