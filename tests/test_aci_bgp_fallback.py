import pytest
import asyncio
from routers.aci import _fetch_bgp_rib_aggregated
from unittest.mock import MagicMock, patch, AsyncMock

@pytest.mark.asyncio
async def test_bgp_rib_fallback_logic():
    aci = MagicMock()
    loop = MagicMock()

    def mock_run(executor, fn, *args):
        f = asyncio.Future()
        f.set_result(fn(*args))
        return f

    loop.run_in_executor.side_effect = mock_run

    # Mock _get_processed_nodes to return one leaf
    with patch("routers.aci._get_processed_nodes", AsyncMock(return_value=([{"id": "101", "role": "leaf", "dn": "topo/node-101"}], {}))):
        # 1. Test successful per-leaf fetch
        aci.get_bgp_rib_for_node.return_value = {
            "imdata": [{"bgpAdjRibIn": {"attributes": {"dn": "topo/node-101/sys/bgp/inst/dom-V/peer-[1.1.1.1]/ent-[1.1.1.1]", "prefix": "10.0.0.0/24"}}}]
        }

        async def mock_gather_cfg(*args, **kwargs):
            return [{}, {}, {"imdata": []}]

        async def mock_gather_results(*args, **kwargs):
            # For leaves
            return [{"imdata": [{"bgpAdjRibIn": {"attributes": {"dn": "topo/node-101/sys/bgp/inst/dom-V/peer-[1.1.1.1]/ent-[1.1.1.1]", "prefix": "10.0.0.0/24"}}}]}]

        with patch("asyncio.gather", side_effect=[mock_gather_cfg(), mock_gather_results()]), \
             patch("routers.aci._cached", side_effect=lambda k, l, t=300: l()), \
             patch("routers.aci.run_with_context", lambda x: x):

            rows, raw = await _fetch_bgp_rib_aggregated(aci, loop, "dc1", "in")
            assert len(rows) == 1
            assert rows[0]["node"] == "101"
            assert rows[0]["prefix"] == "10.0.0.0/24"

        # 2. Test fallback when per-leaf is empty
        aci.get_bgp_rib_for_node.return_value = {"imdata": []}
        aci.get.return_value = {
            "imdata": [{"bgpAdjRibIn": {"attributes": {"dn": "topo/node-102/sys/bgp/inst/dom-V/peer-[2.2.2.2]/ent-[2.2.2.2]", "prefix": "20.0.0.0/24"}}}]
        }

        async def mock_gather_empty_results(*args, **kwargs):
            return [{"imdata": []}]

        with patch("asyncio.gather", side_effect=[mock_gather_cfg(), mock_gather_empty_results()]), \
             patch("routers.aci._cached", side_effect=lambda k, l, t=300: l()), \
             patch("routers.aci.run_with_context", lambda x: x):

            rows, raw = await _fetch_bgp_rib_aggregated(aci, loop, "dc1", "in")
            assert len(rows) == 1
            assert rows[0]["node"] == "102"
            assert rows[0]["prefix"] == "20.0.0.0/24"
            aci.get.assert_called_with("api/node/class/bgpAdjRibIn.json?page-size=1000")
