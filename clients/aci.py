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
    def __init__(self, url, username, password, domain=None, fabric_id="default"):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.domain = domain
        self.fabric_id = fabric_id
        self.session = requests.Session()
        self.token = None
        self.domains = []

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
            response = self.session.post(login_url, json=payload, verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true", timeout=10)
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

            # Deliverable 3d — Record session domains
            try:
                domains_resp = self.session.get(f"{self.url}/api/aaaListDomains.json", verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true", timeout=5)
                if domains_resp.ok:
                    d_data = domains_resp.json()
                    self.domains = [d.get("aaaDomain", {}).get("attributes", {}).get("name") for d in d_data.get("imdata", [])]
                    if self.domains == ["common"] or not self.domains:
                         logger.warning(
                            "ACI [%s] login succeeded but user '%s' has restricted read access to domains %s. L3Out and BGP data may be empty.",
                            self.fabric_id, self.username, self.domains
                         )
            except Exception as e:
                logger.warning(f"ACI [{self.fabric_id}] failed to fetch domain list: {e}")

            logger.debug(f"ACI Login response: {data}", extra={"payload": data, "fabric": self.fabric_id})
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

    def get(self, path, action="GET_DATA", quiet=False):
        """Generic GET request to the APIC.

        When `quiet=True`, upstream failures (e.g. 400s on capability probes) are
        logged at INFO instead of ERROR so they don't appear as alerts.
        """
        from dev import DEV_MODE
        if DEV_MODE:
            from dev import (
                MOCK_ACI_NODES, MOCK_ACI_L3OUTS, MOCK_ACI_BGP_PEERS,
                MOCK_ACI_SUBNETS, MOCK_ACI_EPGS, MOCK_ACI_FAULT_INST,
                MOCK_ACI_BGP_RIB_IN, MOCK_ACI_BGP_RIB_OUT,
                MOCK_ACI_BGP_DOMS_ALL, MOCK_ACI_BGP_PEER_CFG,
                MOCK_ACI_BGP_ADJ_RIB_IN, MOCK_ACI_BGP_ADJ_RIB_OUT,
                MOCK_ACI_NODE_INTERFACES, MOCK_ACI_NODE_208_INTERFACES,
                MOCK_ACI_URIBV4_ROUTES, MOCK_ACI_URIBV6_ROUTES,
                MOCK_ACI_OSPF_ADJ_EP, MOCK_ACI_L3EXT_RS_ECTX,
                MOCK_ACI_TENANTS, MOCK_ACI_VRFS, MOCK_ACI_BDS,
                MOCK_ACI_APP_PROFILES, MOCK_ACI_CONTRACTS, MOCK_ACI_FILTERS,
                MOCK_ACI_FV_RSPROV, MOCK_ACI_FV_RSCONS, MOCK_ACI_ACCESS_PG,
                MOCK_ACI_BUNDLE_PG, MOCK_ACI_AAEPS, MOCK_ACI_PHYS_DOMAINS,
                MOCK_ACI_L3_DOMAINS, MOCK_ACI_VMM_DOMAINS, MOCK_ACI_VLAN_POOLS,
                MOCK_ACI_CDP_POLS, MOCK_ACI_LLDP_POLS, MOCK_ACI_LACP_POLS,
                MOCK_ACI_LINK_POLS, MOCK_ACI_MCP_POLS, MOCK_ACI_STP_POLS,
                MOCK_ACI_L2_POLS, MOCK_ACI_STORMCTRL_POLS, MOCK_ACI_ACCESS_TOPOLOGY
            )
            if "fabricNode" in path: return {"imdata": MOCK_ACI_NODES}
            if "fvTenant" in path and "fvCtx" not in path and "fvAEPg" not in path: return {"imdata": MOCK_ACI_TENANTS}
            if "fvCtx" in path: return {"imdata": MOCK_ACI_VRFS}
            if "fvBD" in path: return {"imdata": MOCK_ACI_BDS}
            if "fvAp" in path: return {"imdata": MOCK_ACI_APP_PROFILES}
            if "vzBrCP" in path:
                if "api/node/mo/" in path:
                    # Single contract lookup
                    dn_part = path.split(".json")[0].split("api/node/mo/")[1]
                    from urllib.parse import unquote
                    target_dn = unquote(dn_part)
                    match = [c for c in MOCK_ACI_CONTRACTS if c["vzBrCP"]["attributes"]["dn"] == target_dn]
                    return {"imdata": match}
                return {"imdata": MOCK_ACI_CONTRACTS}
            if "vzFilter" in path: return {"imdata": MOCK_ACI_FILTERS}
            if "fvRsProv" in path: return {"imdata": MOCK_ACI_FV_RSPROV}
            if "fvRsCons" in path: return {"imdata": MOCK_ACI_FV_RSCONS}
            if "infraAccPortGrp" in path:
                if "api/node/mo/" in path:
                    dn_part = path.split(".json")[0].split("api/node/mo/")[1]
                    from urllib.parse import unquote
                    target_dn = unquote(dn_part)
                    match = [p for p in MOCK_ACI_ACCESS_PG if p["infraAccPortGrp"]["attributes"]["dn"] == target_dn]
                    return {"imdata": match}
                return {"imdata": MOCK_ACI_ACCESS_PG}
            if "infraAccBndlGrp" in path:
                if "api/node/mo/" in path:
                    dn_part = path.split(".json")[0].split("api/node/mo/")[1]
                    from urllib.parse import unquote
                    target_dn = unquote(dn_part)
                    match = [p for p in MOCK_ACI_BUNDLE_PG if p["infraAccBndlGrp"]["attributes"]["dn"] == target_dn]
                    return {"imdata": match}
                return {"imdata": MOCK_ACI_BUNDLE_PG}
            if "infraAttEntityP" in path: return {"imdata": MOCK_ACI_AAEPS}
            if "physDomP" in path: return {"imdata": MOCK_ACI_PHYS_DOMAINS}
            if "l3extDomP" in path: return {"imdata": MOCK_ACI_L3_DOMAINS}
            if "vmmDomP" in path: return {"imdata": MOCK_ACI_VMM_DOMAINS}
            if "fvnsVlanInstP" in path: return {"imdata": MOCK_ACI_VLAN_POOLS}
            if "cdpIfPol" in path: return {"imdata": MOCK_ACI_CDP_POLS}
            if "lldpIfPol" in path: return {"imdata": MOCK_ACI_LLDP_POLS}
            if "lacpLagPol" in path: return {"imdata": MOCK_ACI_LACP_POLS}
            if "fabricHIfPol" in path: return {"imdata": MOCK_ACI_LINK_POLS}
            if "mcpIfPol" in path: return {"imdata": MOCK_ACI_MCP_POLS}
            if "stpIfPol" in path: return {"imdata": MOCK_ACI_STP_POLS}
            if "l2IfPol" in path: return {"imdata": MOCK_ACI_L2_POLS}
            if "stormctrlIfPol" in path: return {"imdata": MOCK_ACI_STORMCTRL_POLS}
            if "uni/infra.json" in path and "infraNodeP" in path: return {"imdata": MOCK_ACI_ACCESS_TOPOLOGY}

            if "l3extOut" in path:
                if "rsp-subtree=full" in path:
                    return {
                        "imdata": [{
                            "l3extOut": {
                                "attributes": {"name": "L3OUT-CORE", "dn": "uni/tn-COMMON/out-L3OUT-CORE"},
                                "children": [
                                    {
                                        "l3extLNodeP": {
                                            "attributes": {"name": "BorderLeafs", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs"},
                                            "children": [
                                                {"l3extRsNodeL3OutAtt": {"attributes": {"tDn": "topology/pod-1/node-101"}}},
                                                {"l3extRsNodeL3OutAtt": {"attributes": {"tDn": "topology/pod-1/node-102"}}},
                                                {
                                                    "l3extLIfP": {
                                                        "attributes": {"name": "IF1", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/lifp-IF1"},
                                                        "children": [
                                                            {"l3extRsPathL3OutAtt": {"attributes": {
                                                                "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/lifp-IF1/rspathL3OutAtt-[topology/pod-1/paths-101/pathep-[eth1/49]]",
                                                                "tDn": "topology/pod-1/paths-101/pathep-[eth1/49]",
                                                                "addr": "10.255.0.254/30"
                                                            }}}
                                                        ]
                                                    }
                                                }
                                            ]
                                        }
                                    },
                                    {"bgpPeerP": {"attributes": {"addr": "10.255.0.1", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.1]"}}},
                                    {"bgpPeerP": {"attributes": {"addr": "10.255.0.2", "dn": "uni/tn-COMMON/out-L3OUT-CORE/lnodep-BorderLeafs/rspeerToProfile/bgpPeerP-[10.255.0.2]"}}},
                                ]
                            }
                        }]
                    }
                return {"imdata": MOCK_ACI_L3OUTS}
            if "bgpPeerEntry" in path: return {"imdata": MOCK_ACI_BGP_PEERS}
            if "l3extSubnet" in path: return {"imdata": MOCK_ACI_SUBNETS}
            if "uribv4Route" in path or "uribv4/dom-" in path: return {"imdata": MOCK_ACI_URIBV4_ROUTES}
            if "uribv6Route" in path or "uribv6/dom-" in path: return {"imdata": MOCK_ACI_URIBV6_ROUTES}
            if "ospfAdjEp" in path: return {"imdata": MOCK_ACI_OSPF_ADJ_EP}
            if "l3extRsEctx" in path: return {"imdata": MOCK_ACI_L3EXT_RS_ECTX}
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
            if "bgpPeerP" in path: return {"imdata": MOCK_ACI_BGP_PEER_CFG}
            if "class/bgpAdjRibIn" in path: return {"imdata": MOCK_ACI_BGP_ADJ_RIB_IN}
            if "class/bgpAdjRibOut" in path: return {"imdata": MOCK_ACI_BGP_ADJ_RIB_OUT}
            if "bgpAdjRibIn" in path: return {"imdata": MOCK_ACI_BGP_RIB_IN}
            if "bgpAdjRibOut" in path: return {"imdata": MOCK_ACI_BGP_RIB_OUT}
            if "l1PhysIf" in path:
                if "node-208" in path:
                    return {"imdata": MOCK_ACI_NODE_208_INTERFACES}
                return {"imdata": MOCK_ACI_NODE_INTERFACES}
            if "fvTenant" in path: return {"imdata": [{"fvTenant": {"attributes": {"name": "common"}}}]}
            if "firmwareCtrlrRunning" in path: return {"imdata": [{"firmwareCtrlrRunning": {"attributes": {"version": "5.2(4d)"}}}]}
            return {"imdata": []}

        if not self.token:
            if not self.login():
                return None

        url = f"{self.url}/{path.lstrip('/')}"

        def _do_get():
            start_time = time.time()
            try:
                response = self.session.get(url, verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true", timeout=15)
                duration = int((time.time() - start_time) * 1000)
                logger.info(f"ACI GET {path}", extra={
                    "target": "ACI",
                    "action": action,
                    "status": response.status_code,
                    "duration_ms": duration,
                    "fabric": self.fabric_id
                })

                if response.status_code in (401, 403):
                    return response, None

                response.raise_for_status()
                data = response.json()
                logger.debug(f"ACI response body: {data}", extra={"payload": data})
                return response, data
            except Exception as e:
                duration = int((time.time() - start_time) * 1000)
                status = getattr(e.response, 'status_code', 500) if hasattr(e, 'response') else 500
                log_fn = logger.info if quiet else logger.error
                log_fn(f"ACI GET {path} failed: {e}", extra={
                    "target": "ACI",
                    "action": action,
                    "status": status,
                    "duration_ms": duration,
                    "fabric": self.fabric_id
                })
                return getattr(e, 'response', None), None

        resp, data = _do_get()
        if resp is not None and resp.status_code in (401, 403):
            logger.info("ACI token expired, retrying after login...")
            if self.login():
                resp, data = _do_get()
            else:
                logger.error("ACI login failed during token refresh retry")

        return data

    def get_with_meta(self, path, action="GET_DATA", quiet=False):
        """Like `get()`, but returns a dict with the underlying status/error so
        callers can surface diagnostic info instead of seeing only `None`.
        """
        from dev import DEV_MODE
        if DEV_MODE:
            return {"data": self.get(path, action=action, quiet=quiet), "status": 200, "error": None}

        if not self.token and not self.login():
            return {"data": None, "status": None, "error": "login_failed"}

        url = f"{self.url}/{path.lstrip('/')}"

        def _do():
            try:
                response = self.session.get(url, verify=os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true", timeout=15)
                if response.status_code in (401, 403):
                    return response, None, f"status_{response.status_code}"
                response.raise_for_status()
                return response, response.json(), None
            except Exception as e:
                status = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                log_fn = logger.info if quiet else logger.error
                log_fn(f"ACI GET {path} failed: {e}", extra={
                    "target": "ACI", "action": action, "status": status or 500, "fabric": self.fabric_id
                })
                return getattr(e, 'response', None), None, str(e)

        resp, data, err = _do()
        if resp is not None and resp.status_code in (401, 403):
            if self.login():
                resp, data, err = _do()
        body_text = None
        if resp is not None and data is None:
            try:
                body_text = resp.text[:500]
            except Exception:
                pass
        return {
            "data": data,
            "status": resp.status_code if resp is not None else None,
            "error": err,
            "body": body_text,
            "url": url,
        }

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

    def get_l3out_vrf_bindings(self):
        """Query l3extRsEctx to map L3Outs to their VRF contexts (used by OSPF Map)."""
        return self.get("api/node/class/l3extRsEctx.json", action="FETCH_ACI_L3OUT_VRF_BINDINGS")

    def get_l3_subnets(self):
        """Query l3extSubnet for external subnet policies."""
        return self.get("api/node/class/l3extSubnet.json", action="FETCH_ACI_SUBNETS")

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

    def get_bgp_peer_configs(self):
        """Query bgpPeerP (policy-space) to map peer IPs to their L3Outs."""
        return self.get("api/node/class/bgpPeerP.json", action="FETCH_ACI_BGP_PEER_CFG")

    def get_node_interfaces(self, node_dn):
        """Single tree fetch of every interface-related MO on a node."""
        classes = "l1PhysIf,ethpmPhysIf,pcAggrIf,pcAggrMbrIf,pcRsMbrIfs,vpcIf,vpcRsVpcConf,vpcDom"
        path = f"api/node/mo/{_quote_dn(node_dn)}.json?query-target=subtree&target-subtree-class={classes}"
        return self.get(path, action="FETCH_ACI_NODE_INTERFACES")

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

    def get_all_subnets(self):
        """Fetch both Bridge Domain subnets (fvSubnet) and L3Out subnets (l3extSubnet)."""
        fv_subnets = self.get("api/node/class/fvSubnet.json")
        l3_subnets = self.get("api/node/class/l3extSubnet.json")

        all_subnets = []
        if fv_subnets and 'imdata' in fv_subnets:
            for item in fv_subnets['imdata']:
                if 'fvSubnet' in item:
                    all_subnets.append(item['fvSubnet']['attributes'])

        if l3_subnets and 'imdata' in l3_subnets:
            for item in l3_subnets['imdata']:
                if 'l3extSubnet' in item:
                    all_subnets.append(item['l3extSubnet']['attributes'])

        return all_subnets

    def get_overall_health(self):
        """Fetch overall system health score."""
        return self.get_health_score("topology/health")

    def get_tenant_health(self):
        """Fetch health scores for all tenants."""
        path = "api/node/class/fvTenant.json?rsp-subtree-include=health"
        return self.get(path)

    def get_pod_health(self):
        """Fetch pod list. The ?rsp-subtree-include=health modifier 400s on this
        APIC version, so we skip it; per-pod health is unavailable."""
        return self.get("api/node/class/fabricPod.json")

    # ── Tenant Model ──────────────────────────────────────────────────────────

    def get_tenants(self):
        """List all fvTenant objects."""
        return self.get("api/node/class/fvTenant.json", action="FETCH_ACI_TENANTS")

    def get_vrfs(self, tenant=None):
        """List VRFs (fvCtx). Optionally scoped to a tenant."""
        if tenant:
            path = f"api/node/mo/uni/tn-{_quote_dn(tenant)}.json?query-target=subtree&target-subtree-class=fvCtx"
        else:
            path = "api/node/class/fvCtx.json"
        return self.get(path, action="FETCH_ACI_VRFS")

    def get_bridge_domains(self):
        """List Bridge Domains with subnets, VRF binding, and L3Out bindings."""
        path = ("api/node/class/fvBD.json"
                "?rsp-subtree=children&rsp-subtree-class=fvSubnet,fvRsCtx,fvRsBDToOut")
        return self.get(path, action="FETCH_ACI_BDS")

    def get_app_profiles(self):
        """List Application Profiles with their EPG count via subtree count."""
        path = "api/node/class/fvAp.json?rsp-subtree-include=count"
        return self.get(path, action="FETCH_ACI_APP_PROFILES")

    def get_contracts(self):
        """List Contracts with full subject+filter tree.

        rsp-subtree=full pulls vzSubj children, including vzRsSubjFiltAtt
        (filter binding). We separately resolve filter contents via
        get_filters() — APIC won't follow the relation cross-MO.
        """
        path = "api/node/class/vzBrCP.json?rsp-subtree=full"
        return self.get(path, action="FETCH_ACI_CONTRACTS")

    def get_filters(self):
        """List all Filters with their entries (vzEntry) inline."""
        path = "api/node/class/vzFilter.json?rsp-subtree=children&rsp-subtree-class=vzEntry"
        return self.get(path, action="FETCH_ACI_FILTERS")

    def get_epg_relations(self):
        """Fetch every fvRsProv + fvRsCons in the fabric so we can build a
        contract-to-EPG (provider/consumer) map without per-EPG fan-out.

        Each fvRsProv/fvRsCons attribute has:
          dn: .../tn-X/ap-Y/epg-Z/rsprov-W   (or rscons-W)
          tDn: uni/tn-X/brc-W                (the contract being prov'd/cons'd)
          tnVzBrCPName: W
        """
        prov = self.get("api/node/class/fvRsProv.json", action="FETCH_ACI_EPG_PROV")
        cons = self.get("api/node/class/fvRsCons.json", action="FETCH_ACI_EPG_CONS")
        return {"prov": prov, "cons": cons}

    def get_epg_detail(self, dn):
        """Drill-down for a single EPG: provided/consumed contracts,
        static path bindings, domain associations."""
        classes = "fvRsProv,fvRsCons,fvRsPathAtt,fvRsDomAtt,fvSubnet"
        path = f"api/node/mo/{_quote_dn(dn)}.json?query-target=subtree&target-subtree-class={classes}"
        return self.get(path, action="FETCH_ACI_EPG_DETAIL")

    # ── Access Model ──────────────────────────────────────────────────────────

    def get_access_policy_groups(self):
        """List both Access (single-port) and Bundle (PC/vPC) policy groups,
        plus their child relation MOs in one call so the response can be
        flattened by the router without further fan-out."""
        children = ("infraRsAttEntP,infraRsCdpIfPol,infraRsLldpIfPol,"
                    "infraRsLacpPol,infraRsHIfPol,infraRsMcpIfPol,"
                    "infraRsStpIfPol,infraRsL2IfPol,infraRsStormctrlIfPol")
        access = self.get(
            f"api/node/class/infraAccPortGrp.json?rsp-subtree=children&rsp-subtree-class={children}",
            action="FETCH_ACI_ACCESS_PG")
        bundle = self.get(
            f"api/node/class/infraAccBndlGrp.json?rsp-subtree=children&rsp-subtree-class={children}",
            action="FETCH_ACI_BUNDLE_PG")
        return {"access": access, "bundle": bundle}

    def get_aaeps(self):
        """List AAEPs (infraAttEntityP) with domain links and per-EPG
        static-bind generic config."""
        path = ("api/node/class/infraAttEntityP.json"
                "?rsp-subtree=children&rsp-subtree-class=infraRsDomP,infraGeneric")
        return self.get(path, action="FETCH_ACI_AAEPS")

    def get_physical_domains(self):
        return self.get(
            "api/node/class/physDomP.json?rsp-subtree=children&rsp-subtree-class=infraRsVlanNs",
            action="FETCH_ACI_PHYS_DOMAINS")

    def get_l3_domains(self):
        return self.get(
            "api/node/class/l3extDomP.json?rsp-subtree=children&rsp-subtree-class=infraRsVlanNs",
            action="FETCH_ACI_L3_DOMAINS")

    def get_vmm_domains(self):
        return self.get(
            "api/node/class/vmmDomP.json?rsp-subtree=children&rsp-subtree-class=infraRsVlanNs",
            action="FETCH_ACI_VMM_DOMAINS")

    def get_vlan_pools(self):
        """fvnsVlanInstP with their fvnsEncapBlk children (the actual ranges)."""
        path = ("api/node/class/fvnsVlanInstP.json"
                "?rsp-subtree=children&rsp-subtree-class=fvnsEncapBlk")
        return self.get(path, action="FETCH_ACI_VLAN_POOLS")

    def get_interface_policy_class(self, cls):
        """Generic fetch for one interface-policy class. cls in:
        cdpIfPol, lldpIfPol, lacpLagPol, fabricHIfPol, mcpIfPol,
        stpIfPol, l2IfPol, stormctrlIfPol.
        """
        return self.get(f"api/node/class/{cls}.json", action=f"FETCH_ACI_{cls.upper()}")

    def get_access_topology(self):
        """Pull every MO needed to build the policy-group → (node, port) map
        in one fan-out call. The router joins these.

        - infraNodeP        (Switch Profile)
        - infraLeafS        (leaf selector, with fromCard/fromPort)
        - infraNodeBlk      (range of node IDs)
        - infraRsAccPortP   (Switch Profile → Interface Profile)
        - infraAccPortP     (Interface Profile)
        - infraHPortS       (port selector)
        - infraPortBlk      (range of port IDs)
        - infraRsAccBaseGrp (Port selector → Policy Group)
        """
        classes = ("infraNodeP,infraLeafS,infraNodeBlk,infraRsAccPortP,"
                   "infraAccPortP,infraHPortS,infraPortBlk,infraRsAccBaseGrp")
        path = f"api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class={classes}"
        return self.get(path, action="FETCH_ACI_ACCESS_TOPOLOGY")

def connectivity_check(client: ACIClient) -> bool:
    """Verify APIC is reachable using the existing session token."""
    try:
        resp = client.get("api/node/class/fabricPod.json?rsp-subtree-include=count")
        return resp is not None
    except Exception:
        return False
