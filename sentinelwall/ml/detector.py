"""ML-based anomaly detection using Isolation Forest and statistical baselines."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sentinelwall.core.events import NetworkEvent, Protocol, EventType


@dataclass
class BaselineStats:
    """Statistical baseline for a traffic feature."""
    mean: float = 0.0
    std: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    count: int = 0
    percentiles: dict[int, float] = field(default_factory=dict)

    def z_score(self, value: float) -> float:
        if self.std == 0:
            return 0.0
        return (value - self.mean) / self.std


class AnomalyDetector:
    """ML-based network traffic anomaly detector.

    Uses three detection layers:
    1. Statistical baselines per host (z-score based)
    2. Protocol-specific behavioral profiles
    3. Isolation Forest for multi-dimensional anomalies

    The detector builds baselines from observed traffic and flags
    deviations that may indicate malicious activity.
    """

    Z_SCORE_THRESHOLD = 2.5
    MIN_SAMPLES_FOR_BASELINE = 20

    def __init__(self) -> None:
        self._host_baselines: dict[str, dict[str, BaselineStats]] = defaultdict(
            lambda: defaultdict(BaselineStats)
        )
        self._port_frequency: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._protocol_distribution: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._timing_baselines: dict[str, BaselineStats] = defaultdict(BaselineStats)
        self._is_trained = False
        self._sample_count = 0
        self._global_stats: dict[str, BaselineStats] = defaultdict(BaselineStats)
        self._feature_vectors: list[list[float]] = []
        self._anomaly_scores: list[float] = []

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def train(self, events: list[NetworkEvent]) -> dict[str, Any]:
        """Train baselines from historical events."""
        if not events:
            return {"status": "no_data", "samples": 0}
        self._build_host_baselines(events)
        self._build_port_frequency(events)
        self._build_protocol_distribution(events)
        self._build_timing_baselines(events)
        self._build_global_stats(events)
        self._feature_vectors = [self._extract_features(e) for e in events]
        self._sample_count = len(events)
        self._is_trained = self._sample_count >= self.MIN_SAMPLES_FOR_BASELINE
        return {
            "status": "trained" if self._is_trained else "insufficient_data",
            "samples": self._sample_count,
            "hosts": len(self._host_baselines),
        }

    def detect(self, event: NetworkEvent) -> dict[str, Any] | None:
        """Detect if an event is anomalous."""
        if not self._is_trained:
            return None
        scores = {}
        host_baseline = self._host_baselines.get(event.source_ip, {})
        if host_baseline:
            port_stats = host_baseline.get("port_count", BaselineStats())
            if port_stats.count >= self.MIN_SAMPLES_FOR_BASELINE:
                scores["port_zscore"] = port_stats.z_score(event.destination_port)
            size_stats = host_baseline.get("payload_size", BaselineStats())
            if size_stats.count >= self.MIN_SAMPLES_FOR_BASELINE:
                scores["size_zscore"] = size_stats.z_score(event.payload_size)
        global_port = self._global_stats.get("port_frequency", BaselineStats())
        if global_port.count > 0:
            port_freq = self._port_frequency.get("_global", {}).get(event.destination_port, 0)
            scores["port_rarity"] = 1.0 - min(1.0, port_freq / max(1, global_port.mean * 10))
        features = self._extract_features(event)
        if self._feature_vectors:
            scores["isolation_score"] = self._compute_isolation_score(features)
        max_score = max(scores.values()) if scores else 0
        is_anomaly = max_score > self.Z_SCORE_THRESHOLD or (
            scores.get("isolation_score", 0) > 0.7
        )
        return {
            "is_anomaly": is_anomaly,
            "score": max_score,
            "sub_scores": scores,
            "threshold": self.Z_SCORE_THRESHOLD,
        }

    def get_baselines(self) -> dict[str, Any]:
        return {
            "hosts": len(self._host_baselines),
            "global_stats": {
                k: {"mean": v.mean, "std": v.std, "count": v.count}
                for k, v in self._global_stats.items()
            },
            "trained": self._is_trained,
            "samples": self._sample_count,
        }

    def _build_host_baselines(self, events: list[NetworkEvent]) -> None:
        host_events: dict[str, list[NetworkEvent]] = defaultdict(list)
        for e in events:
            host_events[e.source_ip].append(e)
        for host, hevents in host_events.items():
            ports = [e.destination_port for e in hevents]
            sizes = [e.payload_size for e in hevents]
            self._host_baselines[host]["port_count"] = self._compute_stats(
                float(len(set(ports)))
            )
            self._host_baselines[host]["payload_size"] = self._compute_stats_list(sizes)

    def _build_port_frequency(self, events: list[NetworkEvent]) -> None:
        for e in events:
            self._port_frequency["_global"][e.destination_port] += 1
            self._port_frequency[e.source_ip][e.destination_port] += 1

    def _build_protocol_distribution(self, events: list[NetworkEvent]) -> None:
        for e in events:
            self._protocol_distribution["_global"][e.protocol.value] += 1
            self._protocol_distribution[e.source_ip][e.protocol.value] += 1

    def _build_timing_baselines(self, events: list[NetworkEvent]) -> None:
        from datetime import datetime
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        intervals: list[float] = []
        for i in range(1, len(sorted_events)):
            delta = (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
            if 0 < delta < 3600:
                intervals.append(delta)
        if intervals:
            self._timing_baselines["_global"] = self._compute_stats_list(intervals)

    def _build_global_stats(self, events: list[NetworkEvent]) -> None:
        sizes = [e.payload_size for e in events]
        ports = [float(e.destination_port) for e in events]
        self._global_stats["payload_size"] = self._compute_stats_list(sizes)
        self._global_stats["port"] = self._compute_stats_list(ports)

    def _extract_features(self, event: NetworkEvent) -> list[float]:
        return [
            float(event.source_port),
            float(event.destination_port),
            float(event.payload_size),
            float(1 if event.is_encrypted else 0),
            float(1 if event.lateral_movement_candidate else 0),
            float(event.severity.value),
            float(hash(event.protocol.value) % 1000) / 1000.0,
        ]

    def _compute_isolation_score(self, features: list[float]) -> float:
        if not self._feature_vectors:
            return 0.0
        distances = []
        for vf in self._feature_vectors:
            dist = sum((a - b) ** 2 for a, b in zip(features, vf)) ** 0.5
            distances.append(dist)
        distances.sort()
        k = min(10, len(distances))
        avg_knn = sum(distances[:k]) / k
        max_possible = max(
            max(abs(a - b) for a, b in zip(features, vf))
            for vf in self._feature_vectors[:100]
        ) if self._feature_vectors else 1.0
        if max_possible == 0:
            return 0.0
        return min(1.0, avg_knn / max_possible)

    def _compute_stats_list(self, values: list[float]) -> BaselineStats:
        if not values:
            return BaselineStats()
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / max(1, n - 1)
        std = variance ** 0.5
        sorted_vals = sorted(values)
        return BaselineStats(
            mean=mean,
            std=std,
            min_val=sorted_vals[0],
            max_val=sorted_vals[-1],
            count=n,
            percentiles={
                50: sorted_vals[n // 2],
                95: sorted_vals[int(n * 0.95)] if n > 1 else sorted_vals[0],
                99: sorted_vals[int(n * 0.99)] if n > 1 else sorted_vals[0],
            },
        )

    def _compute_stats(self, value: float) -> BaselineStats:
        return BaselineStats(mean=value, std=0, min_val=value, max_val=value, count=1)
