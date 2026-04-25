import os
import pytest
from unittest.mock import patch
from clients.aci_registry import load_fabrics, list_fabrics, get_fabric

def test_legacy_fallback():
    with patch.dict(os.environ, {"ACI_URL": "https://legacy", "ACI_DOMAIN": "dom"}, clear=True):
        # We need to ensure the singleton is cleared or we use a fresh import
        import clients.aci_registry
        clients.aci_registry._fabrics = {}
        fabrics = load_fabrics()
        assert "default" in fabrics
        assert fabrics["default"].url == "https://legacy"
        assert fabrics["default"].domain == "dom"
        assert fabrics["default"].label == "ACI"

def test_multi_fabric_parsing():
    env = {
        "ACI_FABRICS": "dc1,dc2",
        "ACI_DC1_URL": "https://dc1",
        "ACI_DC1_LABEL": "Dallas",
        "ACI_DC2_URL": "https://dc2",
        "ACI_DC2_DOMAIN": "dom2"
    }
    with patch.dict(os.environ, env, clear=True):
        import clients.aci_registry
        clients.aci_registry._fabrics = {}
        fabrics = load_fabrics()
        assert len(fabrics) == 2
        assert fabrics["dc1"].url == "https://dc1"
        assert fabrics["dc1"].label == "Dallas"
        assert fabrics["dc2"].url == "https://dc2"
        assert fabrics["dc2"].domain == "dom2"
        assert fabrics["dc2"].label == "dc2"

def test_list_fabrics_order():
    env = {
        "ACI_FABRICS": "dc2,dc1",
        "ACI_DC1_URL": "https://dc1",
        "ACI_DC2_URL": "https://dc2"
    }
    with patch.dict(os.environ, env, clear=True):
        import clients.aci_registry
        clients.aci_registry._fabrics = {}
        fabrics = list_fabrics()
        assert fabrics[0].id == "dc2"
        assert fabrics[1].id == "dc1"

def test_get_fabric_success():
    env = {
        "ACI_FABRICS": "dc1",
        "ACI_DC1_URL": "https://dc1"
    }
    with patch.dict(os.environ, env, clear=True):
        import clients.aci_registry
        clients.aci_registry._fabrics = {}
        f = get_fabric("dc1")
        assert f.id == "dc1"

def test_get_fabric_error():
    env = {"ACI_FABRICS": "dc1", "ACI_DC1_URL": "https://dc1"}
    with patch.dict(os.environ, env, clear=True):
        import clients.aci_registry
        clients.aci_registry._fabrics = {}
        with pytest.raises(KeyError):
            get_fabric("unknown")

def test_quote_dn_ipv6():
    from clients.aci import _quote_dn
    # Test IPv6 address in brackets with colons
    dn = "topology/pod-1/node-101/sys/bgp/inst/dom-default/peer-[fc00:10::1]/ent-[fc00:10::1]"
    quoted = _quote_dn(dn)
    # Colons in peer-[...] segments should be preserved
    assert "peer-[fc00:10::1]" in quoted
    assert "ent-[fc00:10::1]" in quoted
    assert "/" in quoted
