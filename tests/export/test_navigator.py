"""Tests for the MITRE ATT&CK Navigator layer exporter."""

from datetime import datetime, timedelta, timezone

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import Severity
from sentinelwall.export.navigator import NavigatorExporter
from sentinelwall.mitre.techniques import TACTIC_ORDER
from tests.conftest import make_event


def make_layer(clusters):
    return NavigatorExporter().export(clusters)


def make_cluster(techniques, labels, confidence=0.9):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return CorrelatedCluster(
        cluster_id="c1",
        events=[make_event()],
        first_seen=now,
        last_seen=now + timedelta(seconds=1),
        involved_hosts={"10.0.0.5", "8.8.8.8"},
        severity=Severity.HIGH,
        techniques=techniques,
        labels=labels,
        confidence=confidence,
    )


class TestLayerShape:
    def test_domain(self):
        layer = make_layer([make_cluster(["T1046"], ["port-scan"])])
        assert layer["domain"] == "enterprise-attack"

    def test_techniques_list(self):
        layer = make_layer([make_cluster(["T1046"], ["port-scan"])])
        assert len(layer["techniques"]) == 1
        t = layer["techniques"][0]
        assert t["techniqueID"] == "T1046"
        assert 0 <= t["score"] <= 100
        assert t["enabled"] is True

    def test_tactic_order(self):
        layer = make_layer([])
        assert layer["tacticOrder"] == TACTIC_ORDER

    def test_metadata(self):
        layer = make_layer([make_cluster(["T1046"], ["port-scan"])])
        assert layer["metadata"]["generated_by"] == "SentinelWall v1.0.0"

    def test_gradient_colors(self):
        layer = make_layer([])
        assert len(layer["gradient"]["colors"]) == 5
        assert layer["gradient"]["minValue"] == 0
        assert layer["gradient"]["maxValue"] == 100

    def test_filters(self):
        layer = make_layer([])
        assert "Linux" in layer["filters"]["platforms"]


class TestScoring:
    def test_max_aggregation(self):
        clusters = [
            make_cluster(["T1046"], ["x"], confidence=0.4),
            make_cluster(["T1046"], ["y"], confidence=0.8),
        ]
        layer = make_layer(clusters)
        t = layer["techniques"][0]
        assert t["score"] == 80.0

    def test_comment_mentions_labels(self):
        layer = make_layer([make_cluster(["T1110"], ["brute-force"])])
        assert "brute-force" in layer["techniques"][0]["comment"]

    def test_multiple_techniques(self):
        layer = make_layer([make_cluster(["T1071", "T1572"], ["c2-beacon"])])
        ids = {t["techniqueID"] for t in layer["techniques"]}
        assert ids == {"T1071", "T1572"}

    def test_unknown_technique_skipped(self):
        layer = make_layer([make_cluster(["T0000"], ["x"])])
        assert layer["techniques"] == []


class TestExportJson:
    def test_writes_file(self, tmp_path):
        out = tmp_path / "layer.json"
        NavigatorExporter().export_json(str(out), [make_cluster(["T1046"], ["a"])])
        assert out.exists()
        import json
        layer = json.loads(out.read_text())
        assert layer["domain"] == "enterprise-attack"