"""Tests for the SentinelEngine end-to-end."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinelwall.core.engine import EngineConfig, ProcessingStats, SentinelEngine
from sentinelwall.core.events import EventType, Protocol, Severity
from sentinelwall.ml.synthetic import generate_attack_scenario, generate_benign_traffic
from tests.conftest import make_event


class TestEngineSetup:
    def test_default_engine(self):
        engine = SentinelEngine()
        assert engine.get_events() == []
        assert engine.get_stats().events_processed == 0

    def test_config_applied(self):
        config = EngineConfig(min_severity=Severity.HIGH, enable_ml=False)
        engine = SentinelEngine(config)
        assert engine.config.min_severity == Severity.HIGH

    def test_disable_mitre(self):
        engine = SentinelEngine(EngineConfig(enable_mitre=False))
        assert engine._mitre_mapper is None

    def test_disable_narrative(self):
        engine = SentinelEngine(EngineConfig(enable_narrative=False))
        assert engine._narrative_generator is None

    def test_disable_ml(self):
        engine = SentinelEngine(EngineConfig(enable_ml=False))
        assert engine._ml_detector is None

    def test_reset(self):
        engine = SentinelEngine()
        engine.ingest_event(make_event())
        assert len(engine.get_events()) == 1
        engine.reset()
        assert engine.get_events() == []
        assert engine.get_stats().events_processed == 0


class TestEngineIngestion:
    def test_ingest_single_event(self):
        engine = SentinelEngine()
        alerts = engine.ingest_event(make_event())
        assert alerts == []
        assert len(engine.get_events()) == 1

    def test_ingest_batch(self):
        engine = SentinelEngine()
        events = [make_event() for _ in range(25)]
        engine.ingest_batch(events)
        assert len(engine.get_events()) == 25

    def test_process_counts_events(self):
        engine = SentinelEngine()
        engine.ingest_batch([make_event() for _ in range(50)])
        stats = engine.process()
        assert stats.events_processed == 50

    def test_alerts_callback(self):
        received = []
        config = EngineConfig(alert_callback=received.append)
        engine = SentinelEngine(config)
        events, _ = generate_attack_scenario("c2-beacon")
        engine.ingest_batch(events)
        engine.process()
        assert received, "expected alert callbacks"


class TestEngineFullScenario:
    def setup_engine(self):
        engine = SentinelEngine()
        benign = generate_benign_traffic(duration_minutes=10, samples_per_minute=3)
        attack, _ = generate_attack_scenario("multi-stage")
        engine.ingest_batch(benign + attack)
        return engine, attack

    def test_multi_stage_detects_clusters(self):
        engine, _ = self.setup_engine()
        stats = engine.process()
        assert stats.clusters_detected >= 4

    def test_multi_stage_techniques(self, ):
        engine, _ = self.setup_engine()
        engine.process()
        techs = set(engine.get_stats().technique_counts.keys())
        assert "T1046" in techs
        assert "T1110" in techs
        assert "T1071" in techs
        assert "T1048" in techs
        assert "T1021" in techs

    def test_critical_severity_detected(self):
        engine, _ = self.setup_engine()
        engine.process()
        sev = engine.get_stats().severity_distribution
        assert sev.get("CRITICAL", 0) >= 1

    def test_timeline_built(self):
        engine, _ = self.setup_engine()
        engine.process()
        assert len(engine.get_timelines()) == 1
        assert engine.get_timelines()[0].event_count > 0

    def test_narrative_generated(self):
        engine, _ = self.setup_engine()
        engine.process()
        narrative = engine.generate_narrative()
        assert narrative
        assert "Attack Chain" in narrative or "Suspicious" in narrative

    def test_scenario_recall(self):
        """Ground-truth techniques should be substantially recovered."""
        engine = SentinelEngine()
        attack, ground_truth = generate_attack_scenario("multi-stage")
        engine.ingest_batch(attack)
        engine.process()
        detected = set(engine.get_stats().technique_counts.keys())
        recall = len(detected & set(ground_truth)) / len(set(ground_truth))
        assert recall >= 0.5


class TestEngineExports:
    def setup_engine(self):
        engine = SentinelEngine()
        attack, _ = generate_attack_scenario("multi-stage")
        engine.ingest_batch(attack)
        engine.process()
        return engine

    def test_stix_export(self):
        engine = self.setup_engine()
        bundle = engine.export_stix()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert bundle["objects"]
        types = {o["type"] for o in bundle["objects"]}
        assert "observed-data" in types
        assert "attack-pattern" in types

    def test_navigator_export(self):
        engine = self.setup_engine()
        layer = engine.export_mitre_navigator()
        assert layer["domain"] == "enterprise-attack"
        assert layer["techniques"]
        for t in layer["techniques"]:
            assert t["techniqueID"].startswith("T")
            assert 0 <= t["score"] <= 100

    def test_html_export_returns_html(self):
        engine = self.setup_engine()
        html = engine.export_html_report()
        assert html.startswith("<!DOCTYPE html>")
        assert "SENTINEL" in html.upper()

    def test_html_export_writes_file(self, tmp_path):
        engine = self.setup_engine()
        out = tmp_path / "report.html"
        engine.export_html_report(out)
        assert out.exists()
        assert out.stat().st_size > 1000


class TestEnginePerformance:
    def test_throughput_benchmark(self):
        """Engine must process >10K events/sec on synthetic data."""
        from sentinelwall.ml.synthetic import generate_benign_traffic
        engine = SentinelEngine()
        events = generate_benign_traffic(
            duration_minutes=200, samples_per_minute=60, seed=99
        )
        assert len(events) >= 10000, f"benchmark needs >=10k, got {len(events)}"
        import time
        start = time.monotonic()
        engine.ingest_batch(events)
        engine.process()
        elapsed = time.monotonic() - start
        throughput = len(events) / elapsed
        assert throughput > 10000, f"throughput {throughput:.0f} below 10k/s"

    def test_large_batch_no_crash(self):
        engine = SentinelEngine()
        engine.ingest_batch([make_event() for _ in range(2000)])
        engine.process()
        assert engine.get_stats().events_processed == 2000


class TestEngineRuleIntegration:
    def test_custom_rules_loaded(self, tmp_path):
        rule_text = """
rule test_ssh_high:
    meta:
        description = "SSH port check"
        severity = HIGH
        techniques = ["T1021"]
    condition:
        protocol == ssh
        AND destination_port == 22
"""
        rules_file = tmp_path / "rules.swl"
        rules_file.write_text(rule_text)
        engine = SentinelEngine(EngineConfig(custom_rules_path=str(rules_file)))
        assert engine._rule_engine is not None
        assert len(engine._rule_engine.get_custom_rules()) == 1

    def test_rule_fires(self):
        engine = SentinelEngine()
        from sentinelwall.rules.parser import Rule, RuleCondition
        from sentinelwall.rules.engine import RuleEngine
        engine._rule_engine = RuleEngine()
        # built-in ssh_non_standard_port fires on SSH to non-22 port
        alerts = engine.ingest_event(make_event(
            protocol=Protocol.SSH, event_type=EventType.SSH_HANDSHAKE,
            destination_port=2222,
        ))
        assert any(a.get("type") == "rule_match" for a in alerts)


class TestEngineStats:
    def test_stats_dict(self):
        engine = SentinelEngine()
        attack, _ = generate_attack_scenario("brute-force")
        engine.ingest_batch(attack)
        stats = engine.process()
        d = stats.to_dict()
        assert d["events_processed"] == len(attack)
        assert "processing_time_seconds" in d
        assert isinstance(d["events_per_second"], float)

    def test_severity_distribution(self):
        engine = SentinelEngine()
        attack, _ = generate_attack_scenario("c2-beacon")
        engine.ingest_batch(attack)
        stats = engine.process()
        assert stats.severity_distribution.get("CRITICAL", 0) >= 1

    def test_protocol_distribution(self):
        engine = SentinelEngine()
        attack, _ = generate_attack_scenario("multi-stage")
        engine.ingest_batch(attack)
        stats = engine.process()
        assert stats.protocol_counts.get("ssh", 0) >= 1
        assert stats.protocol_counts.get("https", 0) >= 1