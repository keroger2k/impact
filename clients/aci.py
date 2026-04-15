"""
clients/aci.py — Cisco ACI REST API client.
"""

import logging
import os
import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

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

        try:
            response = self.session.post(login_url, json=payload, verify=False, timeout=10)
            response.raise_for_status()
            data = response.json()
            self.token = data['imdata'][0]['aaaLogin']['attributes']['token']
            # APIC session usually uses a cookie named 'APIC-cookie'
            # requests.Session() handles cookies automatically if they are sent in Set-Cookie header.
            logger.info(f"Successfully logged into ACI: {self.url} as {formatted_user}")
            return True
        except Exception as e:
            logger.error(f"ACI Login failed for {self.url}: {e}")
            return False

    def get(self, path):
        """Generic GET request to the APIC."""
        from dev import DEV_MODE
        if DEV_MODE:
            from dev import MOCK_ACI_NODES, MOCK_ACI_L3OUTS, MOCK_ACI_BGP_PEERS, MOCK_ACI_SUBNETS, MOCK_ACI_EPGS, MOCK_ACI_FAULT_INST
            if "fabricNode" in path: return {"imdata": MOCK_ACI_NODES}
            if "l3extOut" in path: return {"imdata": MOCK_ACI_L3OUTS}
            if "bgpPeerEntry" in path: return {"imdata": MOCK_ACI_BGP_PEERS}
            if "l3extSubnet" in path: return {"imdata": MOCK_ACI_SUBNETS}
            if "fvAEPg" in path: return {"imdata": MOCK_ACI_EPGS}
            if "faultInst" in path: return {"imdata": MOCK_ACI_FAULT_INST}
            return {"imdata": []}

        if not self.token:
            if not self.login():
                return None

        url = f"{self.url}/{path.lstrip('/')}"
        try:
            response = self.session.get(url, verify=False, timeout=15)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"ACI GET {url} failed: {e}")
            return None

    def get_fabric_nodes(self):
        """List all fabricNode objects."""
        data = self.get("api/node/class/fabricNode.json")
        return data.get('imdata', []) if data else []

    def get_l3outs(self, tenant=None):
        """Fetch L3Out configurations."""
        if tenant:
            path = f"api/node/mo/uni/tn-{tenant}.json?query-target=subtree&target-subtree-class=l3extOut"
        else:
            path = "api/node/class/l3extOut.json"
        data = self.get(path)
        return data.get('imdata', []) if data else []

    def get_l3out_details(self, dn):
        """Fetch details for a specific L3Out including children like node profiles and interface profiles."""
        # Query with rsp-subtree=full to get children
        path = f"api/node/mo/{dn}.json?rsp-subtree=full"
        data = self.get(path)
        return data.get('imdata', []) if data else []

    def get_bgp_peers(self):
        """Query bgpPeerEntry for BGP neighbor states."""
        data = self.get("api/node/class/bgpPeerEntry.json")
        return data.get('imdata', []) if data else []

    def get_ospf_peers(self):
        """Query ospfAdjEp for OSPF neighbor states."""
        data = self.get("api/node/class/ospfAdjEp.json")
        return data.get('imdata', []) if data else []

    def get_l3_subnets(self):
        """Query l3extSubnet for external subnet policies."""
        data = self.get("api/node/class/l3extSubnet.json")
        return data.get('imdata', []) if data else []

    def get_bgp_routes(self, node_id):
        """Query bgpDom for routing tables on a specific node."""
        # This is a bit more complex, usually requires targeting the node
        # Example: api/node/mo/topology/pod-1/node-101/sys/bgp/inst/dom-default.json?query-target=subtree&target-subtree-class=bgpRoute
        path = f"api/node/mo/topology/pod-1/node-{node_id}/sys/bgp/inst.json?query-target=subtree&target-subtree-class=bgpDom"
        data = self.get(path)
        return data.get('imdata', []) if data else []

    def get_epgs(self, tenant=None):
        """Fetch Endpoint Groups (fvAEPg)."""
        if tenant:
            path = f"api/node/mo/uni/tn-{tenant}.json?query-target=subtree&target-subtree-class=fvAEPg"
        else:
            path = "api/node/class/fvAEPg.json"
        data = self.get(path)
        return data.get('imdata', []) if data else []

    def get_epg_stats(self, dn):
        """Fetch health and stats for a specific EPG."""
        # healthInst and dbgrStats
        path = f"api/node/mo/{dn}.json?rsp-subtree-include=health,stats"
        data = self.get(path)
        return data.get('imdata', []) if data else []

    def get_faults(self, severity=None):
        """Fetch faults."""
        if severity:
            path = f"api/node/class/faultInst.json?query-target-filter=eq(faultInst.severity,\"{severity}\")"
        else:
            path = "api/node/class/faultInst.json"
        data = self.get(path)
        return data.get('imdata', []) if data else []

def connectivity_check(client: ACIClient) -> bool:
    """Lightweight call to verify APIC is reachable."""
    try:
        return client.login()
    except Exception:
        return False
