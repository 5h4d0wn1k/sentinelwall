"""SentinelEngine — the main detection pipeline orchestrator."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sentinelwall.core.correlator import EventCorrelator, CorrelatedCluster
from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity
from sentinelwall.core.timeline import AttackTimeline, TimelineAnalyzer


@dataclass
class EngineConfig:
    """Configuration for the SentinelEngine."""
    correlation_window: int = 300
    enable_ml: bool = True
    enable_mitre: bool = True
    enable_narrative: bool = True
    min_severity: Severity = Severity.INFORMATIONAL
    max_events_per_second: int = 50000
    alert_callback: Callable[[dict[str, Any]], None] | None = None
    custom_rules_path: str | None = None
    mitre_mapping_enabled: bool = True


@dataclass
class ProcessingStats:
    """Statistics from an engine processing run."""
    events_processed: int = 0
    clusters_detected: int = 0
    timelines_built: int = 0
    alerts_generated: int = 0
    processing_time_seconds: float = 0.0
    events_per_second: float = 0.0
    severity_distribution: dict[str, int] = field(default_factory=dict)
    technique_counts: dict[str, int] = field(default_factory=dict)
    protocol_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_processed": self.events_processed,
            "clusters_detected": self.clusters_detected,
            "timelines_built": self.timelines_built,
            "alerts_generated": self.alerts_generated,
            "processing_time_seconds": round(self.processing_time_seconds, 4),
            "events_per_second": round(self.events_per_second, 2),
            "severity_distribution": self.severity_distribution,
            "technique_counts": self.technique_counts,
            "protocol_counts": self.protocol_counts,
        }


class SentinelEngine:
    """The main detection engine that orchestrates the full analysis pipeline.

    Pipeline:
    1. Ingest events (from pcap, logs, or programmatic API)
    2. Enrich events (DNS resolution, GeoIP placeholder, protocol parsing)
    3. Correlate events (temporal, spatial, behavioral)
    4. Detect threats (ML + rule-based + MITRE mapping)
    5. Build timelines (attack chain reconstruction)
    6. Generate narratives (human-readable threat stories)
    7. Export results (STIX, Navigator JSON, HTML, JSON)
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()
        self._correlator = EventCorrelator(time_window=self.config.correlation_window)
        self._timeline_analyzer = TimelineAnalyzer()
        self._events: list[NetworkEvent] = []
        self._all_clusters: list[CorrelatedCluster] = []
        self._stats = ProcessingStats()
        self._mitre_mapper = None
        self._narrative_generator = None
        self._rule_engine = None
        self._ml_detector = None
        self._setup_components()

    def _setup_components(self) -> None:
        if self.config.enable_mitre:
            try:
                from sentinelwall.mitre.mapper import MitreMapper
                self._mitre_mapper = MitreMapper()
            except ImportError:
                pass
        if self.config.enable_narrative:
            try:
                from sentinelwall.narrative.generator import NarrativeGenerator
                self._narrative_generator = NarrativeGenerator()
            except ImportError:
                pass
        if self.config.custom_rules_path:
            try:
                from sentinelwall.rules.engine import RuleEngine
                self._rule_engine = RuleEngine()
                if self.config.custom_rules_path:
                    self._rule_engine.load_rules_from_file(self.config.custom_rules_path)
            except ImportError:
                pass
        if self.config.enable_ml:
            try:
                from sentinelwall.ml.detector import AnomalyDetector
                self._ml_detector = AnomalyDetector()
            except ImportError:
                pass

    def ingest_event(self, event: NetworkEvent) -> list[dict[str, Any]]:
        """Ingest a single event and return any alerts generated."""
        self._events.append(event)
        alerts = []
        clusters = self._correlator.ingest(event)
        for cluster in clusters:
            alert = self._process_cluster(cluster, event)
            if alert:
                alerts.append(alert)
        if self._rule_engine:
            rule_matches = self._rule_engine.evaluate(event)
            for match in rule_matches:
                alerts.append({
                    "type": "rule_match",
                    "rule_name": match.get("rule_name", "unknown"),
                    "severity": match.get("severity", "MEDIUM"),
                    "event_id": event.event_id,
                    "description": match.get("description", ""),
                    "mitre_techniques": match.get("techniques", []),
                })
        if self._ml_detector and self._ml_detector.is_trained:
            anomaly = self._ml_detector.detect(event)
            if anomaly and anomaly.get("is_anomaly"):
                alerts.append({
                    "type": "ml_anomaly",
                    "anomaly_score": anomaly.get("score", 0),
                    "event_id": event.event_id,
                    "severity": "HIGH",
                    "description": f"ML anomaly detected: score={anomaly.get('score', 0):.3f}",
                })
        return alerts

    def ingest_batch(self, events: list[NetworkEvent]) -> list[dict[str, Any]]:
        """Ingest a batch of events efficiently."""
        all_alerts = []
        for event in events:
            alerts = self.ingest_event(event)
            all_alerts.extend(alerts)
        return all_alerts

    def process(self) -> ProcessingStats:
        """Process all ingested events and generate final statistics."""
        start = time.monotonic()
        self._stats.events_processed = len(self._events)
        if self._ml_detector and not self._ml_detector.is_trained:
            result = self._train_anomaly_model(self._events)
            if result.get("status") != "trained":
                from sentinelwall.ml.synthetic import generate_benign_traffic
                baseline = generate_benign_traffic(
                    duration_minutes=60, samples_per_minute=6, seed=42
                )
                self._ml_detector.train(baseline)
        self._correlator.flush()
        self._all_clusters = self._correlator.get_clusters()
        for cluster in self._all_clusters:
            self._stats.clusters_detected += 1
            self._update_stats_from_cluster(cluster)
        if self._all_clusters:
            all_cluster_events = []
            for c in self._all_clusters:
                all_cluster_events.extend(c.events)
            timeline = self._timeline_analyzer.build_timeline(all_cluster_events)
            self._stats.timelines_built = 1
        elapsed = time.monotonic() - start
        self._stats.processing_time_seconds = elapsed
        self._stats.events_per_second = (
            self._stats.events_processed / elapsed if elapsed > 0 else 0
        )
        return self._stats

    def get_clusters(self) -> list[CorrelatedCluster]:
        return list(self._all_clusters)

    def get_timelines(self) -> list[AttackTimeline]:
        return self._timeline_analyzer.get_timelines()

    def get_stats(self) -> ProcessingStats:
        return self._stats

    def get_events(self) -> list[NetworkEvent]:
        return list(self._events)

    def generate_narrative(self) -> str | None:
        """Generate a human-readable threat narrative."""
        if not self._narrative_generator:
            return None
        return self._narrative_generator.generate(
            events=self._events,
            clusters=self._all_clusters,
            timelines=self._timeline_analyzer.get_timelines(),
        )

    def export_stix(self) -> dict[str, Any]:
        """Export findings in STIX 2.1 format."""
        from sentinelwall.export.stix import StixExporter
        exporter = StixExporter()
        return exporter.export(
            events=self._events,
            clusters=self._all_clusters,
            timelines=self._timeline_analyzer.get_timelines(),
        )

    def export_mitre_navigator(self) -> dict[str, Any]:
        """Export MITRE ATT&CK Navigator layer."""
        from sentinelwall.export.navigator import NavigatorExporter
        exporter = NavigatorExporter()
        return exporter.export(clusters=self._all_clusters)

    def export_html_report(self, output_path: str | Path | None = None) -> str:
        """Generate HTML dashboard report."""
        from sentinelwall.export.html_report import HtmlReportExporter
        exporter = HtmlReportExporter()
        return exporter.export(
            events=self._events,
            clusters=self._all_clusters,
            timelines=self._timeline_analyzer.get_timelines(),
            stats=self._stats,
            output_path=output_path,
        )

    def load_pcap(self, path: str | Path) -> int:
        """Load events from a pcap file. Returns number of events loaded."""
        from sentinelwall.integrations.pcap_reader import PcapReader
        reader = PcapReader()
        events = reader.read(path)
        self._events.extend(events)
        return len(events)

    def load_zeek_log(self, path: str | Path) -> int:
        """Load events from a Zeek log file."""
        from sentinelwall.integrations.zeek import ZeekImporter
        importer = ZeekImporter()
        events = importer.read(path)
        self._events.extend(events)
        return len(events)

    def load_suricata_eve(self, path: str | Path) -> int:
        """Load events from Suricata eve.json."""
        from sentinelwall.integrations.suricata import SuricataImporter
        importer = SuricataImporter()
        events = importer.read(path)
        self._events.extend(events)
        return len(events)

    def train_anomaly_model(self, events: list[NetworkEvent] | None = None) -> dict[str, Any]:
        """Train the ML anomaly detector. Falls back to synthetic baselines."""
        return self._train_anomaly_model(events)

    def _train_anomaly_model(self, events: list[NetworkEvent] | None = None) -> dict[str, Any]:
        if not self._ml_detector:
            return {"status": "disabled"}
        if events:
            result = self._ml_detector.train(events)
            if result.get("status") == "trained":
                return result
        from sentinelwall.ml.synthetic import generate_benign_traffic
        baseline = generate_benign_traffic(
            duration_minutes=60, samples_per_minute=6, seed=42
        )
        return self._ml_detector.train(baseline)

    def get_anomaly_detector(self) -> Any:
        return self._ml_detector

    def _process_cluster(
        self, cluster: CorrelatedCluster, triggering_event: NetworkEvent
    ) -> dict[str, Any] | None:
        if cluster.severity < self.config.min_severity:
            return None
        self._stats.alerts_generated += 1
        alert = {
            "type": "correlation_alert",
            "cluster_id": cluster.cluster_id,
            "severity": cluster.severity.name,
            "techniques": cluster.techniques,
            "labels": cluster.labels,
            "description": cluster.chain_description,
            "confidence": cluster.confidence,
            "event_count": cluster.event_count,
            "involved_hosts": list(cluster.involved_hosts),
            "triggering_event": triggering_event.event_id,
        }
        if self._mitre_mapper and self.config.mitre_mapping_enabled:
            mitre_info = self._mitre_mapper.map_techniques(cluster)
            alert["mitre_mapping"] = mitre_info
        if self.config.alert_callback:
            self.config.alert_callback(alert)
        return alert

    def _update_stats_from_cluster(self, cluster: CorrelatedCluster) -> None:
        sev = cluster.severity.name
        self._stats.severity_distribution[sev] = self._stats.severity_distribution.get(sev, 0) + 1
        for tech in cluster.techniques:
            self._stats.technique_counts[tech] = self._stats.technique_counts.get(tech, 0) + 1
        for event in cluster.events:
            proto = event.protocol.value
            self._stats.protocol_counts[proto] = self._stats.protocol_counts.get(proto, 0) + 1

    def reset(self) -> None:
        """Reset engine state for fresh analysis."""
        self._correlator = EventCorrelator(time_window=self.config.correlation_window)
        self._timeline_analyzer = TimelineAnalyzer()
        self._events.clear()
        self._all_clusters.clear()
        self._stats = ProcessingStats()
