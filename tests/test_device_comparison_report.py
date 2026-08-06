"""tests/test_device_comparison_report.py — DNAC vs SolarWinds reconciliation.

compare_inventories is a pure function, so the matching and classification
rules are exercised here without either system. The exclusion rules are
heuristic (they read vendor model strings), so they're pinned in both
directions: the classes that must be dropped, and — just as important — the
switches/routers that must survive, since an over-eager filter silently
shrinks the very inventory this report exists to reconcile.
"""
from unittest.mock import patch

import pytest
from utils.device_comparison_report import (
    classify_exclusion,
    compare_inventories,
    generate_device_comparison_report,
    site_code_for,
    to_csv,
)


def _dnac(hostname, ip="1.2.3.4", model="ISR4451-X/K9", version="17.6.5",
          family="Routers", serial="FCW1234A1B"):
    return {
        "hostname": hostname, "managementIpAddress": ip, "platformId": model,
        "softwareVersion": version, "family": family, "serialNumber": serial,
        "role": "BORDER ROUTER", "reachabilityStatus": "Reachable",
    }


def _sw(name, ip="1.2.3.4", machine_type="Cisco ISR 4451", version="17.6.5",
        description="Cisco IOS XE Software"):
    return {
        "NodeID": 1, "NodeName": name, "NodeIpAddress": ip,
        "MachineType": machine_type, "IOSVersion": version,
        "NodeDescription": description, "Status": 1,
    }


# ── Exclusion classification ─────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("Cisco Nexus 9000 C9336C-FX2", "Nexus"),
    ("N9K-C93180YC-EX", "Nexus"),
    ("Cisco NX-OS Software", "Nexus"),
    ("Cisco APIC-SERVER-M3", "ACI"),
    ("Cisco ACI Leaf", "ACI"),
    ("AIR-CT5520-K9", "Wireless"),
    ("Cisco Aironet 2802I", "Wireless"),
    ("Unified AP", "Wireless"),
    ("Cisco Catalyst 9800-40 Wireless Controller", "Wireless"),
    ("C9120AXI-B", "Wireless"),
    ("AP3802I-B-K9", "Wireless"),
])
def test_excluded_classes(text, expected):
    assert classify_exclusion(text) == expected


@pytest.mark.parametrize("text", [
    "ISR4451-X/K9",
    "Cisco ISR 4331",
    "C9300-48P",                       # Catalyst 9300 switch — 92xx-96xx stay
    "Cisco Catalyst 9500-16X",
    "WS-C3850-48P",
    "Cisco IOS Software, ISR Software",
    "ASR1001-X",
])
def test_kept_classes(text):
    """Switches and routers must survive — an over-eager wireless/Nexus rule
    would quietly shrink the inventory being reconciled."""
    assert classify_exclusion(text) is None


def test_classify_checks_every_field():
    # DNAC carries the useful signal in `family`, not the model.
    assert classify_exclusion("AIR-AP1815I-B-K9", "Unified AP") == "Wireless"
    assert classify_exclusion("C9300-48P", "Switches and Hubs") is None


def test_classify_empty_input():
    assert classify_exclusion(None, "", None) is None


# ── Matching ─────────────────────────────────────────────────────────────────

def test_matched_on_both_hostname_and_ip():
    report = compare_inventories([_dnac("R-SITE-01")], [_sw("R-SITE-01")])

    assert report["summary"]["matched"] == 1
    assert report["summary"]["dnac_only"] == 0
    assert report["summary"]["solarwinds_only"] == 0
    assert report["matched"][0]["matched_by"] == "hostname+ip"
    assert report["matched"][0]["differences"] == []


def test_hostname_match_ignores_fqdn_and_case():
    report = compare_inventories(
        [_dnac("R-SITE-01.network.ad.tsa.gov")], [_sw("r-site-01")],
    )
    assert report["summary"]["matched"] == 1


def test_certain_pairs_are_settled_before_weaker_evidence():
    """The mis-pairing a single greedy hostname pass produces: DEV-A matches
    node-2 on hostname alone, but node-2 agrees with DEV-B on *both* keys.
    Letting the hostname match win first would consume node-2 and strand
    DEV-B, reporting two false gaps for one real difference."""
    dnac = [
        _dnac("SHARED-NAME", ip="1.1.1.1"),   # hostname-only match against node-2
        _dnac("SHARED-NAME", ip="2.2.2.2"),   # exact hostname+ip match on node-2
    ]
    sw = [_sw("SHARED-NAME", ip="2.2.2.2")]

    report = compare_inventories(dnac, sw)

    assert report["summary"]["matched"] == 1
    assert report["matched"][0]["matched_by"] == "hostname+ip"
    assert report["matched"][0]["dnac"]["ip"] == "2.2.2.2"
    # The other device is a genuine gap, not a mangled partial match.
    assert [d["ip"] for d in report["dnac_only"]] == ["1.1.1.1"]


def test_hostname_only_match_when_ip_differs():
    report = compare_inventories(
        [_dnac("R-SITE-01", ip="1.2.3.4")], [_sw("R-SITE-01", ip="5.6.7.8")],
    )
    assert report["matched"][0]["matched_by"] == "hostname"


def test_device_missing_an_ip_still_matches_on_hostname():
    report = compare_inventories(
        [_dnac("R-SITE-01", ip=None)], [_sw("R-SITE-01", ip="1.2.3.4")],
    )
    assert report["summary"]["matched"] == 1
    assert report["matched"][0]["matched_by"] == "hostname"


def test_devices_missing_an_ip_do_not_all_collapse_together():
    """An empty IP must never act as a join key, or every device lacking one
    would match the first node lacking one."""
    report = compare_inventories(
        [_dnac("AAA-01", ip=""), _dnac("BBB-01", ip="")],
        [_sw("ZZZ-01", ip=""), _sw("YYY-01", ip="")],
    )
    assert report["summary"]["matched"] == 0
    assert report["summary"]["dnac_only"] == 2
    assert report["summary"]["solarwinds_only"] == 2


def test_matched_by_ip_flags_the_hostname_difference():
    """Same address, different names — a real finding, and the reason the
    hostname match missed."""
    report = compare_inventories(
        [_dnac("R-SITE-01", ip="1.2.3.4")], [_sw("OLD-NAME-01", ip="1.2.3.4")],
    )

    assert report["summary"]["matched"] == 1
    match = report["matched"][0]
    assert match["matched_by"] == "ip"
    assert {"field": "Hostname", "dnac": "R-SITE-01", "solarwinds": "OLD-NAME-01"} in match["differences"]


def test_dnac_only_and_solarwinds_only():
    report = compare_inventories(
        [_dnac("R-SITE-01", ip="1.2.3.4")],
        [_sw("R-SITE-02", ip="5.6.7.8")],
    )

    assert report["summary"]["matched"] == 0
    assert [d["hostname"] for d in report["dnac_only"]] == ["R-SITE-01"]
    assert [s["hostname"] for s in report["solarwinds_only"]] == ["R-SITE-02"]


def test_one_solarwinds_node_cannot_satisfy_two_dnac_devices():
    """Duplicate hostnames across sites: the second device is an unmonitored
    gap, not a second match."""
    report = compare_inventories(
        [_dnac("R-SITE-01", ip="1.1.1.1"), _dnac("R-SITE-01", ip="2.2.2.2")],
        [_sw("R-SITE-01", ip="1.1.1.1")],
    )

    assert report["summary"]["matched"] == 1
    assert report["summary"]["dnac_only"] == 1


# ── Difference detection ─────────────────────────────────────────────────────

def test_ip_mismatch_is_flagged():
    report = compare_inventories(
        [_dnac("R-SITE-01", ip="1.2.3.4")], [_sw("R-SITE-01", ip="5.6.7.8")],
    )
    fields = [d["field"] for d in report["matched"][0]["differences"]]
    assert "IP Address" in fields
    assert report["summary"]["with_differences"] == 1


@pytest.mark.parametrize("dnac_model,sw_model", [
    # DNAC ships the ordering code, SolarWinds a prose name — same hardware.
    ("ISR4451-X/K9", "Cisco ISR 4451"),
    ("C9300-48P", "Cisco Catalyst 9300-48P"),
    ("WS-C3850-48P", "Cisco Catalyst 3850 Series"),
    ("ASR1001-X", "Cisco ASR 1001-X"),
])
def test_model_formatting_differences_are_not_flagged(dnac_model, sw_model):
    """Flagging cosmetic formatting would mark every device as differing and
    train the reader to ignore the column."""
    report = compare_inventories(
        [_dnac("R-SITE-01", model=dnac_model)], [_sw("R-SITE-01", machine_type=sw_model)],
    )
    assert report["matched"][0]["differences"] == []


@pytest.mark.parametrize("dnac_version,sw_version", [
    ("17.6.5", "17.6.5"),
    ("17.6.5", "17.06.05"),      # SolarWinds zero-pads
    ("17.6.5", "17.6.5a"),
])
def test_equivalent_versions_are_not_flagged(dnac_version, sw_version):
    report = compare_inventories(
        [_dnac("R-SITE-01", version=dnac_version)], [_sw("R-SITE-01", version=sw_version)],
    )
    assert report["matched"][0]["differences"] == []


def test_genuinely_different_model_is_flagged():
    report = compare_inventories(
        [_dnac("R-SITE-01", model="ISR4451-X/K9")], [_sw("R-SITE-01", machine_type="ASR1001-X")],
    )
    fields = [d["field"] for d in report["matched"][0]["differences"]]
    assert "Model" in fields


def test_version_mismatch_is_flagged():
    report = compare_inventories(
        [_dnac("R-SITE-01", version="17.6.5")], [_sw("R-SITE-01", version="16.9.4")],
    )
    fields = [d["field"] for d in report["matched"][0]["differences"]]
    assert "Software Version" in fields


def test_missing_field_on_one_side_is_not_a_mismatch():
    report = compare_inventories(
        [_dnac("R-SITE-01", version="17.6.5")], [_sw("R-SITE-01", version=None)],
    )
    fields = [d["field"] for d in report["matched"][0]["differences"]]
    assert "Software Version" not in fields


# ── Exclusions are reported, not silent ──────────────────────────────────────

def test_excluded_devices_are_reported_with_reasons():
    report = compare_inventories(
        [_dnac("R-SITE-01"), _dnac("AP-SITE-01", model="AIR-AP1815I-B-K9", family="Unified AP")],
        [_sw("R-SITE-01"), _sw("N9K-SITE-01", machine_type="Cisco Nexus 9000 C9336C-FX2")],
    )

    assert report["summary"]["matched"] == 1
    assert report["summary"]["dnac_only"] == 0
    assert report["summary"]["solarwinds_only"] == 0

    dnac_reasons = {e["reason"]: e for e in report["excluded"]["dnac"]}
    sw_reasons = {e["reason"]: e for e in report["excluded"]["solarwinds"]}
    assert dnac_reasons["Wireless"]["count"] == 1
    assert "AP-SITE-01" in dnac_reasons["Wireless"]["examples"]
    assert sw_reasons["Nexus"]["count"] == 1


@pytest.mark.parametrize("text,expected", [
    ("Cisco Nexus 9000 C9336C-FX2", "Nexus"),
    ("Cisco APIC-SERVER-M3", "ACI"),
])
def test_nexus_and_aci_are_a_solarwinds_only_concern(text, expected):
    """Catalyst Center doesn't manage Nexus or ACI, so those devices only ever
    appear on the SolarWinds side. Running the patterns against DNAC couldn't
    remove a real Nexus — there aren't any — it could only misfire on a
    switch whose model string happened to match, silently dropping it."""
    assert classify_exclusion(text, system="solarwinds") == expected
    assert classify_exclusion(text, system="dnac") is None


def test_wireless_is_excluded_from_both_sides():
    """Unlike Nexus/ACI, Catalyst Center *does* manage WLCs and APs, so
    wireless genuinely exists in both inventories and must be filtered from
    both — otherwise dropping it from SolarWinds alone would resurface every
    AP as a bogus 'in DNAC but unmonitored' row."""
    assert classify_exclusion("AIR-AP1815I-B-K9", system="solarwinds") == "Wireless"
    assert classify_exclusion("AIR-AP1815I-B-K9", system="dnac") == "Wireless"

    report = compare_inventories(
        [_dnac("AP-SITE-01", model="AIR-AP1815I-B-K9", family="Unified AP")],
        [_sw("AP-SITE-01", machine_type="Cisco Aironet 1815")],
    )
    assert report["summary"]["dnac_only"] == 0
    assert report["summary"]["solarwinds_only"] == 0
    assert report["summary"]["matched"] == 0


def test_nexus_in_solarwinds_does_not_become_a_false_dnac_gap():
    """A Nexus monitored by SolarWinds but absent from DNAC is correct and
    expected — it must not surface as 'SolarWinds only', which would read as
    a Catalyst Center onboarding gap."""
    report = compare_inventories(
        [_dnac("R-SITE-01")],
        [_sw("R-SITE-01"), _sw("N9K-SITE-01", machine_type="Cisco Nexus 9000 C9336C-FX2")],
    )

    assert report["summary"]["matched"] == 1
    assert report["summary"]["solarwinds_only"] == 0
    assert report["excluded"]["solarwinds"][0]["reason"] == "Nexus"


def test_devices_without_a_hostname_are_skipped():
    report = compare_inventories([_dnac(None), _dnac("")], [_sw(None)])
    assert report["summary"]["dnac_total"] == 0
    assert report["summary"]["solarwinds_total"] == 0


# ── CSV ──────────────────────────────────────────────────────────────────────

def test_csv_covers_all_three_categories():
    report = compare_inventories(
        [_dnac("R-SITE-01", ip="1.2.3.4"), _dnac("R-SITE-03", ip="9.9.9.9")],
        [_sw("R-SITE-01", ip="5.6.7.8"), _sw("R-SITE-02", ip="8.8.8.8")],
    )
    csv_text = to_csv(report)

    assert "Differs" in csv_text          # matched with an IP mismatch
    assert "DNAC only" in csv_text
    assert "SolarWinds only" in csv_text
    assert csv_text.startswith("Status,Hostname")


# ── Site code (feeds the "Add to DNAC" action) ───────────────────────────────

def test_site_code_prefers_the_solarwinds_custom_property():
    assert site_code_for("RTFAK086AA001", "S689") == ("S689", "solarwinds")


@pytest.mark.parametrize("site", [None, "", "   "])
def test_site_code_falls_back_to_first_four_hostname_chars(site):
    assert site_code_for("RTFAK086AA001", site) == ("RTFA", "hostname")


def test_site_code_fallback_is_uppercased():
    """Matches routers/f5.py::_site_of, the convention already used elsewhere
    for deriving a site from a hostname."""
    assert site_code_for("rtfak086aa001", None) == ("RTFA", "hostname")


def test_site_code_fallback_ignores_the_domain():
    assert site_code_for("RTFAK086AA001.network.ad.tsa.gov", None) == ("RTFA", "hostname")


def test_site_code_short_hostname_is_not_padded():
    assert site_code_for("AB", None) == ("AB", "hostname")


def test_solarwinds_only_rows_carry_site_code_and_its_source():
    """The Add-to-DNAC button needs both: the code to assign, and whether it
    was recorded or guessed, so the operator can see which they're confirming."""
    report = compare_inventories([], [
        _sw("R-SITE-01", ip="1.2.3.4"),
        {"NodeID": 2, "NodeName": "RTFAK086AA001", "NodeIpAddress": "5.6.7.8",
         "MachineType": "Cisco ISR 4331", "IOSVersion": "17.6.5",
         "NodeDescription": "Cisco IOS XE", "Status": 1, "Site": "S689"},
    ])

    rows = {r["hostname"]: r for r in report["solarwinds_only"]}
    assert rows["RTFAK086AA001"]["site_code"] == "S689"
    assert rows["RTFAK086AA001"]["site_code_source"] == "solarwinds"
    # No Site custom property on this one — derived from the hostname.
    assert rows["R-SITE-01"]["site_code"] == "R-SI"
    assert rows["R-SITE-01"]["site_code_source"] == "hostname"


def test_csv_includes_site_code_for_solarwinds_only_rows():
    report = compare_inventories([], [
        {"NodeID": 1, "NodeName": "RTFAK086AA001", "NodeIpAddress": "5.6.7.8",
         "MachineType": "Cisco ISR 4331", "Site": "S689"},
    ])
    csv_text = to_csv(report)
    assert "Site Code,Site Code Source" in csv_text
    assert "S689,solarwinds" in csv_text


# ── Live DNAC fetch ──────────────────────────────────────────────────────────

def test_dnac_side_is_fetched_live_not_from_cache():
    """The cache carries a 7-day TTL. A device onboarded since the last
    refresh would still read as 'in SolarWinds but not DNAC' — and this
    report offers a button to onboard exactly those rows, so acting on stale
    data would push an already-managed device back through discovery."""
    live = [{"hostname": "R-SITE-01", "managementIpAddress": "1.2.3.4",
             "platformId": "ISR4451-X/K9", "family": "Routers"}]

    with patch("clients.dnac.get_all_devices", return_value=live) as mock_fetch, \
         patch("utils.device_comparison_report.cache.get_stale") as mock_cache, \
         patch("utils.device_comparison_report.fetch_solarwinds_devices", return_value=[]):
        report = generate_device_comparison_report(object(), "dev", "dev")

    mock_fetch.assert_called_once()
    mock_cache.assert_not_called()
    assert report["summary"]["dnac_total"] == 1


def test_dnac_fetch_is_strict():
    """A partial page fetch would fabricate the same false gaps a stale cache
    would, so the report must ask for all-or-nothing."""
    with patch("clients.dnac.get_all_devices", return_value=[]) as mock_fetch, \
         patch("utils.device_comparison_report.fetch_solarwinds_devices", return_value=[]):
        generate_device_comparison_report(object(), "dev", "dev")

    assert mock_fetch.call_args.kwargs.get("strict") is True


def test_dnac_failure_propagates_rather_than_reporting_everything_as_a_gap():
    with patch("clients.dnac.get_all_devices", side_effect=RuntimeError("DNAC unreachable")), \
         patch("utils.device_comparison_report.fetch_solarwinds_devices", return_value=[]):
        with pytest.raises(RuntimeError, match="DNAC unreachable"):
            generate_device_comparison_report(object(), "dev", "dev")


def test_solarwinds_failure_propagates():
    with patch("clients.dnac.get_all_devices", return_value=[]), \
         patch("utils.device_comparison_report.fetch_solarwinds_devices",
               side_effect=RuntimeError("SolarWinds query failed")):
        with pytest.raises(RuntimeError, match="SolarWinds"):
            generate_device_comparison_report(object(), "dev", "dev")


def test_no_dnac_client_falls_back_to_cache_for_dev_mode():
    with patch("utils.device_comparison_report.cache.get_stale", return_value=[]) as mock_cache, \
         patch("clients.dnac.get_all_devices") as mock_fetch, \
         patch("utils.device_comparison_report.fetch_solarwinds_devices", return_value=[]):
        generate_device_comparison_report(None, "dev", "dev")

    mock_cache.assert_called_once_with("devices")
    mock_fetch.assert_not_called()
