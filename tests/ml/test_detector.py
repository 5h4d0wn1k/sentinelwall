"""Tests for the ML anomaly detector."""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelwall.core.events import EventType, NetworkEvent, Protocol
from sentinelwall.ml.detector import AnomalyDetector, BaselineStats
from sentinelwall.ml.synthetic import generate_benign_traffic
from tests.conftest import make_event


def dns_events(n, host="10.0.0.5", port=53, size=60):
    events = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(n):
        events.append(
            NetworkEvent(
                timestamp=base + timedelta(seconds=i),
                source_ip=host,
                destination_ip="8.8.8.8",
                source_port=40000,
                destination_port=port,
                protocol=Protocol.DNS,
                event_type=EventType.DNS_QUERY,
                payload_size=size,
            )
        )
    return events


class TestDetectorLifecycle:
    def test_untrained(self):
        detector = AnomalyDetector()
        assert detector.is_trained is False
        assert detector.detect(make_event()) is None

    def test_train_insufficient_data(self):
        detector = AnomalyDetector()
        result = detector.train(dns_events(10))
        assert result["status"] == "insufficient_data"
        assert detector.is_trained is False

    def test_train_empty(self):
        detector = AnomalyDetector()
        result = detector.train([])
        assert result["status"] == "no_data"

    def test_train_sufficient(self):
        detector = AnomalyDetector()
        result = detector.train(dns_events(30))
        assert result["status"] == "trained"
        assert detector.is_trained is True
        assert result["hosts"] >= 1

    def test_train_benign_traffic(self):
        detector = AnomalyDetector()
        events = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=7)
        result = detector.train(events)
        assert result["status"] == "trained"
        assert result["samples"] == len(events)

    def test_train_sample_cap(self):
        detector = AnomalyDetector()
        result = detector.train(dns_events(20000))
        assert result["samples"] <= detector.TRAIN_SAMPLE_CAP

    def test_detect_returns_structure(self):
        detector = AnomalyDetector()
        detector.train(dns_events(30))
        result = detector.detect(make_event(protocol=Protocol.DNS, destination_port=53))
        assert set(result.keys()) >= {"is_anomaly", "score", "sub_scores", "threshold"}
        assert result["threshold"] == AnomalyDetector.Z_SCORE_THRESHOLD

    def test_get_baselines(self):
        detector = AnomalyDetector()
        detector.train(dns_events(30))
        b = detector.get_baselines()
        assert b["trained"] is True
        assert b["hosts"] >= 1
        assert b["samples"] == 30


class TestAnomalyScores:
    def test_catches_out_of_distribution(self):
        detector = AnomalyDetector()
        detector.train(dns_events(30, host="10.0.0.5", port=53))
        benign = detector.detect(dns_events(1, host="10.0.0.5", port=53)[0])
        assert not benign["is_anomaly"]
        evil = make_event(
            source_ip="10.0.0.9",
            destination_ip="203.0.113.1",
            destination_port=23,
            protocol=Protocol.TCP,
        )
        out = detector.detect(evil)
        assert out["is_anomaly"] is True, out

    def test_isolation_score_bounded(self):
        detector = AnomalyDetector()
        detector.train(dns_events(30))
        features = detector._extract_features(make_event())
        score = detector._compute_isolation_score(features)
        assert 0.0 <= score <= 1.0

    def test_isolation_empty_reference(self):
        detector = AnomalyDetector()
        assert detector._compute_isolation_score([1.0, 2.0]) == 0.0

    def test_feature_vector(self):
        detector = AnomalyDetector()
        event = make_event()
        features = detector._extract_features(event)
        assert len(features) == 7
        assert isinstance(features[1], float)


class TestBaselineStats:
    def test_zscore(self):
        stats = BaselineStats(mean=10, std=2, count=100)
        assert stats.z_score(14) == 2.0

    def test_zscore_zero_std(self):
        stats = BaselineStats(mean=10, std=0, count=10)
        assert stats.z_score(99) == 0.0

    def test_percentiles(self):
        values = [float(v) for v in range(100)]
        detector = AnomalyDetector()
        stats = detector._compute_stats_list(values)
        assert stats.count == 100
        assert stats.min_val == 0.0
        assert stats.max_val == 99.0
        assert 49 <= stats.percentiles[50] <= 50
        assert stats.percentiles[95] >= 90

    def test_empty_stats(self):
        detector = AnomalyDetector()
        stats = detector._compute_stats_list([])
        assert stats.count == 0


class TestTrainingInternals:
    def test_host_baselines_built(self):
        detector = AnomalyDetector()
        detector.train(dns_events(30, host="10.0.0.5"))
        assert "10.0.0.5" in detector._host_baselines

    def test_port_frequency(self):
        detector = AnomalyDetector()
        detector.train(dns_events(5) + dns_events(5, port=443))
        freq = detector._port_frequency["_global"]
        assert freq[53] == 5
        assert freq[443] == 5

    def test_protocol_distribution(self):
        detector = AnomalyDetector()
        detector.train(dns_events(5))
        assert detector._protocol_distribution["_global"]["dns"] == 5

    def test_timing_baseline(self):
        detector = AnomalyDetector()
        detector.train(dns_events(20))
        tb = detector._timing_baselines["_global"]
        assert tb.count > 0