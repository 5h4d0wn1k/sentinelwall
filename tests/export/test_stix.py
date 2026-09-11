"""Tests for the STIX 2.1 exporter."""

from datetime import datetime, timedelta, timezone

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import Severity
from sentinelwall.export.stix import StixExporter
from sentinelwall.ml.synthetic import generate_attack_scenario
from tests.conftest import make_event


def build_clusters(events):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        CorrelatedCluster(
            cluster_id="c1",
            events=events,
            first_seen=now,
            last_seen=now + timedelta(minutes=5),
            involved_hosts={e.source_ip for e in events} | {e.destination_ip for e in events},
            severity=Severity.HIGH,
            techniques=["T1046", "T1110", "T1071", "T1048"],
            labels=["port-scan", "brute-force", "c2-beacon", "exfiltration"],
            confidence=0.9,
        )
    ]


def build_bundle():
    events, _ = generate_attack_scenario("multi-stage")
    clusters = build_clusters(events)
    return StixExporter().export(events, clusters, []), events, clusters


class TestBundleShape:
    def test_is_bundle(self):
        bundle, _, _ = build_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert bundle["id"].startswith("bundle--")

    def test_objects_present(self):
        bundle, _, _ = build_bundle()
        assert bundle["objects"]

    def test_object_types(self):
        bundle, _, _ = build_bundle()
        types = {o["type"] for o in bundle["objects"]}
        assert "identity" in types
        assert "observed-data" in types
        assert "attack-pattern" in types
        assert "indicator" in types
        assert "incident" in types

    def test_observed_data_count(self):
        bundle, events, _ = build_bundle()
        observed = [o for o in bundle["objects"] if o["type"] == "observed-data"]
        assert len(observed) == len(events)


class TestAttackPatterns:
    def test_attack_patterns_match_techniques(self):
        bundle, _, clusters = build_bundle()
        patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        ids = {p["x_mitre_technique_id"] for p in patterns}
        detected = {t for c in clusters for t in c.techniques}
        assert detected <= ids

    def test_attack_pattern_phases(self):
        bundle, _, _ = build_bundle()
        phases = bundle["objects"]
        for o in phases:
            if o["type"] == "attack-pattern":
                assert o["kill_chain_phases"][0]["kill_chain_name"] == "mitre-attack"


class TestIndicators:
    def test_indicator_pattern(self):
        bundle, _, _ = build_bundle()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        for ind in indicators:
            assert ind["pattern"].startswith("[ipv4-addr:value = '")
            assert 0 <= ind["confidence"] <= 100
            assert ind["valid_from"]

    def test_indicator_relationships(self):
        bundle, _, _ = build_bundle()
        all_rels = []
        for o in bundle["objects"]:
            all_rels.extend(o.get("x_sentinelwall_relationships", []))
        assert all_rels
        rel_types = {r["relationship_type"] for r in all_rels}
        assert rel_types == {"indicates"}


class TestIncident:
    def test_incident_links_indicators(self):
        bundle, _, _ = build_bundle()
        incidents = [o for o in bundle["objects"] if o["type"] == "incident"]
        assert incidents
        assert incidents[0]["object_refs"]

    def test_severity_critical_for_multi_stage(self):
        bundle, _, _ = build_bundle()
        incidents = [o for o in bundle["objects"] if o["type"] == "incident"]
        assert incidents[0]["severity"] == "High"


class TestEmptyInputs:
    def test_empty_events(self):
        bundle = StixExporter().export([], [], [])
        assert bundle["objects"]
        types = {o["type"] for o in bundle["objects"]}
        assert "observed-data" not in types
        assert "incident" not in types

    def test_no_clusters_no_incident(self):
        bundle = StixExporter().export([make_event()], [], [])
        types = {o["type"] for o in bundle["objects"]}
        assert "incident" not in types