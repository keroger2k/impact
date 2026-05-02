import pytest
import re
import json
import hashlib
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import Request, HTTPException
from routers.dnac import (
    evaluate_groups, SearchGroup, SearchRuleV2, ConfigSearchRequestV2,
    config_search, config_search_ui, config_search_download, _search_cache_key
)
from pydantic import ValidationError

# ── evaluate_groups tests ──────────────────────────────────────────────────────

def test_1_contains_case_insensitive():
    groups = [SearchGroup(rules=[SearchRuleV2(op="contains", value="SNMP-server", case_sensitive=False)])]
    lines = ["snmp-server community TSA-RO"]
    matched, indices, groups_hit, first = evaluate_groups(lines, groups, {})
    assert matched is True
    assert 0 in indices
    assert groups_hit == [1]

def test_2_contains_case_sensitive():
    groups = [SearchGroup(rules=[SearchRuleV2(op="contains", value="SNMP-server", case_sensitive=True)])]
    lines = ["snmp-server community TSA-RO"]
    matched, indices, groups_hit, first = evaluate_groups(lines, groups, {})
    assert matched is False

    lines = ["SNMP-server community TSA-RO"]
    matched, indices, groups_hit, first = evaluate_groups(lines, groups, {})
    assert matched is True

def test_3_regex_compilation_validation():
    # This is actually tested via ConfigSearchRequestV2 validation
    with pytest.raises(ValueError) as exc:
        ConfigSearchRequestV2(groups=[SearchGroup(rules=[SearchRuleV2(op="regex", value="[")])])
    assert "Group 1, Rule 1: Invalid regex" in str(exc.value)

def test_4_regex_word_boundary():
    groups = [SearchGroup(rules=[SearchRuleV2(op="regex", value=r"\binterface\b")])]
    compiled = {(0, 0): re.compile(r"\binterface\b", re.IGNORECASE)}

    assert evaluate_groups(["interface Ethernet1/1"], groups, compiled)[0] is True
    assert evaluate_groups(["interfaces Ethernet1/1"], groups, compiled)[0] is False

def test_5_exact_line():
    groups = [SearchGroup(rules=[SearchRuleV2(op="exact_line", value="interface Ethernet1/1")])]

    assert evaluate_groups(["interface Ethernet1/1"], groups, {})[0] is True
    assert evaluate_groups([" interface Ethernet1/1 "], groups, {})[0] is True # strips
    assert evaluate_groups(["interface Ethernet1/10"], groups, {})[0] is False

def test_6_single_group_any():
    groups = [SearchGroup(combinator="any", rules=[
        SearchRuleV2(value="AAAA"), SearchRuleV2(value="BBBB")
    ])]
    assert evaluate_groups(["AAAA"], groups, {})[0] is True
    assert evaluate_groups(["BBBB"], groups, {})[0] is True
    assert evaluate_groups(["CCCC"], groups, {})[0] is False

def test_7_single_group_all():
    groups = [SearchGroup(combinator="all", rules=[
        SearchRuleV2(value="AAAA"), SearchRuleV2(value="BBBB")
    ])]
    assert evaluate_groups(["AAAA", "BBBB"], groups, {})[0] is True
    assert evaluate_groups(["AAAA"], groups, {})[0] is False

def test_8_two_groups_and():
    groups = [
        SearchGroup(rules=[SearchRuleV2(value="AAAA")]),
        SearchGroup(rules=[SearchRuleV2(value="BBBB")])
    ]
    assert evaluate_groups(["AAAA", "BBBB"], groups, {})[0] is True
    assert evaluate_groups(["AAAA"], groups, {})[0] is False

def test_9_group_negation():
    groups = [SearchGroup(negate=True, rules=[SearchRuleV2(value="AAAA")])]
    assert evaluate_groups(["BBBB"], groups, {})[0] is True
    assert evaluate_groups(["AAAA"], groups, {})[0] is False

def test_10_logic_matrix():
    # (A any B) AND NOT C
    groups = [
        SearchGroup(combinator="any", rules=[SearchRuleV2(value="AAAA"), SearchRuleV2(value="BBBB")]),
        SearchGroup(negate=True, rules=[SearchRuleV2(value="CCCC")])
    ]
    assert evaluate_groups(["AAAA"], groups, {})[0] is True
    assert evaluate_groups(["BBBB"], groups, {})[0] is True
    assert evaluate_groups(["AAAA", "BBBB"], groups, {})[0] is True
    assert evaluate_groups(["AAAA", "CCCC"], groups, {})[0] is False
    assert evaluate_groups(["DDDD"], groups, {})[0] is False

def test_11_empty_rules():
    with pytest.raises(ValueError) as exc:
        ConfigSearchRequestV2(groups=[SearchGroup(rules=[])])
    assert "Group 1 must have between 1 and 10 rules" in str(exc.value)

def test_12_empty_groups():
    with pytest.raises(ValueError) as exc:
        ConfigSearchRequestV2(groups=[])
    assert "Search must have between 1 and 10 groups" in str(exc.value)

def test_13_bounds():
    # > 10 groups
    with pytest.raises(ValueError) as exc:
        ConfigSearchRequestV2(groups=[SearchGroup(rules=[SearchRuleV2(value="AAAA")])] * 11)
    assert "Search must have between 1 and 10 groups" in str(exc.value)

    # > 10 rules
    with pytest.raises(ValueError) as exc:
        ConfigSearchRequestV2(groups=[SearchGroup(rules=[SearchRuleV2(value="AAAA")] * 11)])
    assert "Group 1 must have between 1 and 10 rules" in str(exc.value)

# ── Endpoint tests ─────────────────────────────────────────────────────────────

@pytest.fixture
def mock_session():
    s = MagicMock()
    s.username = "dev"
    return s

@pytest.fixture
def mock_request():
    r = MagicMock(spec=Request)
    r.headers = {}
    r.url = MagicMock()
    r.url.path = "/api/dnac/config-search/ui"
    return r

@pytest.mark.asyncio
async def test_14_json_api_v2(mock_session):
    req = ConfigSearchRequestV2(groups=[SearchGroup(rules=[SearchRuleV2(value="snmp")])])

    # Mocking dependencies
    with patch("routers.dnac._get_dnac"), \
         patch("routers.dnac.cache.get_or_set", return_value=[]), \
         patch("routers.nexus.get_cached_nexus_inventory", return_value=[]):

        resp = await config_search(req, mock_session)
        assert "groups" in resp
        assert resp["total_matches"] == 0

@pytest.mark.asyncio
async def test_15_ui_endpoint(mock_request, mock_session):
    groups = [SearchGroup(rules=[SearchRuleV2(value="snmp")])]
    groups_json = json.dumps([g.model_dump() for g in groups])

    mock_form = MagicMock()
    mock_form.get = lambda k: groups_json if k == "groups_json" else None
    mock_request.form = AsyncMock(return_value=mock_form)

    with patch("routers.dnac._get_dnac"), \
         patch("routers.dnac.config_search", return_value={"results": [], "total_matches": 0}), \
         patch("routers.dnac.cache"), \
         patch("templates_module.templates.TemplateResponse") as mock_render:

        await config_search_ui(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            context_lines=5, session=mock_session
        )
        assert mock_render.called

@pytest.mark.asyncio
async def test_16_download_endpoint(mock_request, mock_session):
    groups = [SearchGroup(rules=[SearchRuleV2(value="snmp")])]
    groups_json = json.dumps([g.model_dump() for g in groups])

    mock_form = MagicMock()
    mock_form.get = lambda k: groups_json if k == "groups_json" else None
    mock_request.form = AsyncMock(return_value=mock_form)

    results = {
        "results": [{"hostname": "H1", "ip": "1.1.1.1", "platform": "P", "match_count": 5, "matched_groups": "1", "first_match_line": "L1"}]
    }

    with patch("routers.dnac._get_dnac"), \
         patch("routers.dnac.cache.get", return_value=results):

        resp = await config_search_download(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            session=mock_session
        )
        assert resp.media_type == "text/csv"
        content = "".join([chunk async for chunk in resp.body_iterator])
        assert "H1,1.1.1.1,P,5,1,L1" in content

@pytest.mark.asyncio
async def test_18_malformed_json(mock_request, mock_session):
    mock_form = MagicMock()
    mock_form.get = lambda k: "invalid json" if k == "groups_json" else None
    mock_request.form = AsyncMock(return_value=mock_form)

    with patch("templates_module.templates.TemplateResponse") as mock_render:
        await config_search_ui(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            context_lines=5, session=mock_session
        )
        args, kwargs = mock_render.call_args
        # context is the 3rd positional argument if not passed as kwarg
        context = args[2] if len(args) > 2 else kwargs.get("context", {})
        assert "Invalid groups payload" in context["error"]

@pytest.mark.asyncio
async def test_19_cache_hit_verification(mock_request, mock_session):
    groups = [SearchGroup(rules=[SearchRuleV2(value="snmp")])]
    groups_json = json.dumps([g.model_dump() for g in groups])

    mock_form = MagicMock()
    mock_form.get = lambda k: groups_json if k == "groups_json" else None
    mock_request.form = AsyncMock(return_value=mock_form)

    results = {"results": [], "total_matches": 0}

    with patch("routers.dnac._get_dnac"), \
         patch("routers.dnac.config_search", return_value=results) as mock_search, \
         patch("routers.dnac.cache") as mock_cache:

        # 1. UI call
        await config_search_ui(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            context_lines=5, session=mock_session
        )
        assert mock_search.call_count == 1
        assert mock_cache.set.called

        # 2. Download call with cache HIT
        mock_cache.get.return_value = results
        await config_search_download(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            session=mock_session
        )
        assert mock_search.call_count == 1 # Still 1, didn't re-run

        # 3. Download call with cache MISS
        mock_cache.get.return_value = None
        await config_search_download(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            session=mock_session
        )
        assert mock_search.call_count == 2 # Incremented, re-ran


def test_20_search_cache_key_ignores_context_lines_and_max_devices():
    """
    Regression test: the UI request uses context_lines=5 and max_devices=None,
    while the download request forces context_lines=0 and max_devices=None.
    Both should derive the same cache key so the download path can find the
    UI's stored result. Previously the key included these transient fields,
    causing the download cache lookup to always miss.
    """
    base_groups = [SearchGroup(rules=[SearchRuleV2(value="snmp")])]

    ui_req = ConfigSearchRequestV2(groups=base_groups, context_lines=5, max_devices=None)
    dl_req = ConfigSearchRequestV2(groups=base_groups, context_lines=0, max_devices=None)
    assert _search_cache_key(ui_req) == _search_cache_key(dl_req)

    # Sanity: a different filter still produces a different key.
    other = ConfigSearchRequestV2(groups=base_groups, hostname="switch-01")
    assert _search_cache_key(ui_req) != _search_cache_key(other)


@pytest.mark.asyncio
async def test_21_download_reuses_ui_cached_result(mock_request, mock_session):
    """
    End-to-end version of the cache-hit path that uses a real dict-backed
    cache so the actual key derivation in _search_cache_key gets exercised.
    """
    groups = [SearchGroup(rules=[SearchRuleV2(value="snmp")])]
    groups_json = json.dumps([g.model_dump() for g in groups])

    mock_form = MagicMock()
    mock_form.get = lambda k: groups_json if k == "groups_json" else None
    mock_request.form = AsyncMock(return_value=mock_form)

    store = {}
    fake_cache = MagicMock()
    fake_cache.get.side_effect = lambda k: store.get(k)
    fake_cache.set.side_effect = lambda k, v, ttl=None: store.__setitem__(k, v)

    results = {"results": [], "total_matches": 0}

    with patch("routers.dnac._get_dnac"), \
         patch("routers.dnac.config_search", return_value=results) as mock_search, \
         patch("routers.dnac.cache", fake_cache):

        await config_search_ui(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            context_lines=5, session=mock_session
        )
        assert mock_search.call_count == 1
        assert len(store) == 1  # UI populated cache

        await config_search_download(
            mock_request,
            hostname=None, ip=None, platform=None, role=None,
            device_family=None, reachability="Reachable", tag=None,
            session=mock_session
        )
        # Same logical query → same key → no second search.
        assert mock_search.call_count == 1
