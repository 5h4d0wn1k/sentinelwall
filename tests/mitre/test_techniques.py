"""Tests for the MITRE ATT&CK technique database."""

import re

import pytest

from sentinelwall.core.events import Severity
from sentinelwall.mitre.techniques import (
    MITRE_TECHNIQUES,
    TACTIC_ORDER,
    get_all_technique_ids,
    get_technique,
    get_techniques_for_tactic,
)


class TestTechniqueRegistry:
    def test_has_20_plus_techniques(self):
        assert len(MITRE_TECHNIQUES) >= 20

    def test_all_ids_are_valid(self):
        for tid in MITRE_TECHNIQUES:
            assert re.fullmatch(r"T\d{4}", tid), f"invalid id {tid}"

    def test_all_have_names(self):
        for info in MITRE_TECHNIQUES.values():
            assert info.name, f"{info.technique_id} has no name"

    def test_all_have_tactics(self):
        for info in MITRE_TECHNIQUES.values():
            assert info.tactic, f"{info.technique_id} has no tactic"
            assert info.tactic in TACTIC_ORDER

    def test_all_have_descriptions(self):
        for info in MITRE_TECHNIQUES.values():
            assert len(info.description) > 20

    def test_all_have_detection_patterns(self):
        for info in MITRE_TECHNIQUES.values():
            assert info.detection_patterns, f"{info.technique_id} missing patterns"

    def test_all_severities_valid(self):
        for info in MITRE_TECHNIQUES.values():
            assert isinstance(info.severity, Severity)

    def test_to_dict_shape(self):
        info = get_technique("T1046")
        d = info.to_dict()
        assert d["technique_id"] == "T1046"
        assert d["severity"] == "MEDIUM"
        assert isinstance(d["detection_patterns"], list)

    def test_get_unknown_technique(self):
        assert get_technique("T9999") is None

    def test_get_techniques_for_tactic(self):
        techniques = get_techniques_for_tactic("discovery")
        assert techniques
        assert all(t.tactic == "discovery" for t in techniques)

    def test_get_all_ids_sorted(self):
        ids = get_all_technique_ids()
        assert ids == sorted(ids)


class TestSpecificTechniques:
    @pytest.mark.parametrize("tid", [
        "T1046", "T1071", "T1048", "T1572", "T1021",
        "T1110", "T1078", "T1041", "T1095", "T1018",
    ])
    def test_core_techniques_present(self, tid):
        assert get_technique(tid) is not None

    def test_kill_chain_coverage(self):
        tactics = {t.tactic for t in MITRE_TECHNIQUES.values()}
        assert "initial-access" in tactics
        assert "execution" in tactics
        assert "persistence" in tactics
        assert "defense-evasion" in tactics
        assert "credential-access" in tactics
        assert "discovery" in tactics
        assert "lateral-movement" in tactics
        assert "collection" in tactics
        assert "command-and-control" in tactics
        assert "exfiltration" in tactics
        assert "impact" in tactics

    def test_c2_has_sub_techniques(self):
        info = get_technique("T1071")
        assert "T1071.001" in info.sub_techniques
        assert "T1071.004" in info.sub_techniques


class TestTacticOrder:
    def test_tactic_order_starts_at_recon(self):
        assert TACTIC_ORDER[0] == "reconnaissance"
        assert TACTIC_ORDER[-1] == "impact"

    def test_tactic_order_all_unique(self):
        assert len(TACTIC_ORDER) == len(set(TACTIC_ORDER))

    def test_tactic_order_has_no_partial_matches(self):
        for tactic in TACTIC_ORDER:
            assert re.fullmatch(r"[a-z-]+", tactic)