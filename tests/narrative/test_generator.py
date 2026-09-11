"""Tests for the threat narrative generator."""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import Severity
from sentinelwall.narrative.generator import (
    NarrativeGenerator,
    NarrativeSegment,
    ThreatNarrative,
)
from sentinelwall.ml.synthetic import generate_attack_scenario
from tests.conftest import make_event


def make_cluster(events, labels, techniques, severity=Severity.HIGH):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return CorrelatedCluster(
        cluster_id="c1",
        events=events,
        first_seen=now,
        last_seen=now + timedelta(seconds=5),
        involved_hosts={e.source_ip for e in events} | {e.destination_ip for e in events},
        severity=severity,
        techniques=techniques,
        labels=labels,
        confidence=0.85,
    )


@pytest.fixture
def generator():
    return NarrativeGenerator()


@pytest.fixture
def multi_stage_clusters():
    events, _ = generate_attack_scenario("multi-stage")
    labels = ["port-scan", "brute-force", "c2-beacon", "exfiltration"]
    techniques = ["T1046", "T1110", "T1071", "T1048"]
    return [make_cluster(events, labels, techniques, Severity.CRITICAL)]


class TestNarrativeDataClasses:
    def test_segment_to_dict(self):
        seg = NarrativeSegment(
            phase="discovery",
            title="Recon detected",
            body="body",
            events=["e1"],
            techniques=["T1046"],
            severity=Severity.MEDIUM,
        )
        d = seg.to_dict()
        assert d["phase"] == "discovery"
        assert d["severity"] == "MEDIUM"

    def test_narrative_to_dict(self):
        n = ThreatNarrative(
            title="T", summary="S", severity=Severity.HIGH, confidence=0.9,
            attacker_ip="1.2.3.4", target_ip="10.0.0.1",
        )
        d = n.to_dict()
        assert d["title"] == "T"
        assert d["confidence"] == 0.9
        assert d["segments"] == []

    def test_narrative_to_text_markdown(self):
        n = ThreatNarrative(
            title="CRITICAL: attack",
            summary="summary line",
            severity=Severity.CRITICAL,
            confidence=0.95,
            attacker_ip="1.2.3.4",
            target_ip="10.0.0.1",
            segments=[
                NarrativeSegment(
                    phase="discovery", title="Scan", body="port scan",
                    techniques=["T1046"], severity=Severity.MEDIUM,
                )
            ],
            recommended_actions=["Isolate"],
            mitre_kill_chain=[{"tactic": "discovery", "techniques": ["T1046"]}],
        )
        text = n.to_text()
        assert "# CRITICAL: attack" in text
        assert "## Attack Chain" in text
        assert "T1046" in text
        assert "## Recommended Actions" in text
        assert "## MITRE ATT&CK Kill Chain" in text


class TestGenerate:
    def test_empty_generates_no_threat(self, generator):
        text = generator.generate([], [], [])
        assert "No Threats Detected" in text

    def test_empty_json(self, generator):
        data = generator.generate_json([], [], [])
        assert data["severity"] == "INFORMATIONAL"

    def test_multi_stage_narrative(self, generator, multi_stage_clusters):
        events = multi_stage_clusters[0].events
        text = generator.generate(events, multi_stage_clusters, [])
        assert "CRITICAL" in text

    def test_narratives_tracked(self, generator, multi_stage_clusters):
        generator.generate(multi_stage_clusters[0].events, multi_stage_clusters, [])
        assert len(generator.get_narratives()) == 1

    def test_json_structured(self, generator, multi_stage_clusters):
        events = multi_stage_clusters[0].events
        data = generator.generate_json(events, multi_stage_clusters, [])
        assert data["total_events"] == len(events)
        assert data["attacker_ip"]
        assert data["techniques_used"]
        assert data["segments"]
        assert data["recommended_actions"]

    def test_attacker_identified(self, generator, multi_stage_clusters):
        events = multi_stage_clusters[0].events
        data = generator.generate_json(events, multi_stage_clusters, [])
        assert "185.220" in data["attacker_ip"]

    def test_target_identified(self, generator, multi_stage_clusters):
        events = multi_stage_clusters[0].events
        data = generator.generate_json(events, multi_stage_clusters, [])
        assert "10.0.1.5" == data["target_ip"]


class TestSeverityResponses:
    @pytest.mark.parametrize("sev,count", [
        (Severity.CRITICAL, 6),
        (Severity.HIGH, 5),
        (Severity.MEDIUM, 4),
        (Severity.LOW, 3),
    ])
    def test_actions_present(self, generator, sev, count):
        cluster = make_cluster(
            [make_event()], ["test"], ["T1046"], severity=sev
        )
        data = generator.generate_json(cluster.events, [cluster], [])
        assert len(data["recommended_actions"]) >= count


class TestPhaseMapping:
    def test_has_attack_chain_section(self, generator, multi_stage_clusters):
        events = multi_stage_clusters[0].events
        text = generator.generate(events, multi_stage_clusters, [])
        assert "Attack Chain" in text

    def test_techniques_in_text(self, generator, multi_stage_clusters):
        events = multi_stage_clusters[0].events
        text = generator.generate(events, multi_stage_clusters, [])
        for tech in ["T1046", "T1110", "T1071", "T1048"]:
            assert tech in text


class TestEdgeCases:
    def test_single_low_severity_cluster(self, generator):
        cluster = make_cluster(
            [make_event()], ["informational"], [], Severity.LOW
        )
        text = generator.generate(cluster.events, [cluster], [])
        assert "LOW" in text

    def test_medium_severity(self, generator):
        cluster = make_cluster([make_event()], ["x"], [], Severity.MEDIUM)
        data = generator.generate_json(cluster.events, [cluster], [])
        assert data["severity"] == "MEDIUM"

    def test_many_events_capped(self, generator):
        events = [make_event() for _ in range(5100)]
        cluster = make_cluster(events, ["bulk"], ["T1046"], Severity.HIGH)
        data = generator.generate_json(events, [cluster], [])
        assert data["total_events"] == 5100
        assert data["segments"]