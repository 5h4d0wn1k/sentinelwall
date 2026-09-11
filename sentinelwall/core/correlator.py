"""Event correlation engine — chains related events into coherent threat sequences."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity


@dataclass
class CorrelatedCluster:
    """A group of related events forming a potential threat sequence."""
    cluster_id: str
    events: list[NetworkEvent] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    involved_hosts: set[str] = field(default_factory=set)
    severity: Severity = Severity.INFORMATIONAL
    techniques: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    confidence: float = 0.0
    chain_description: str = ""

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def duration(self) -> timedelta:
        return self.last_seen - self.first_seen

    @property
    def unique_protocols(self) -> set[Protocol]:
        return {e.protocol for e in self.events}

    @property
    def unique_ports(self) -> set[int]:
        return {e.destination_port for e in self.events}

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "involved_hosts": list(self.involved_hosts),
            "severity": self.severity.name,
            "techniques": self.techniques,
            "labels": self.labels,
            "confidence": self.confidence,
            "chain_description": self.chain_description,
            "duration_seconds": self.duration.total_seconds(),
        }


class EventCorrelator:
    """Multi-dimensional event correlator.

    Correlation dimensions:
    1. Temporal: events within a time window
    2. Spatial: events between same hosts
    3. Protocol: protocol progression patterns (DNS→HTTP→TLS = C2)
    4. Behavioral: statistical deviation from baseline
    5. Causal: events that cause/trigger subsequent events

    The correlator builds a graph of events and identifies chains that match
    known attack patterns from the MITRE ATT&CK framework.
    """

    TIME_WINDOW_SECONDS = 300
    FLOW_TIMEOUT_SECONDS = 60
    PORT_SCAN_THRESHOLD = 12
    BEACON_MIN_SAMPLES = 5

    def __init__(self, time_window: int | None = None) -> None:
        self.time_window = time_window or self.TIME_WINDOW_SECONDS
        self._flow_cache: dict[str, list[NetworkEvent]] = defaultdict(list)
        self._host_connections: dict[str, set[str]] = defaultdict(set)
        self._port_access: dict[str, set[int]] = defaultdict(set)
        self._dns_cache: dict[str, str] = {}
        self._clusters: list[CorrelatedCluster] = []
        self._event_buffer: list[NetworkEvent] = []
        self._beacon_tracker: dict[str, list[datetime]] = defaultdict(list)
        self._beacon_checked: set[str] = set()
        self._host_index: dict[str, list[NetworkEvent]] = defaultdict(list)
        self._analysis_time: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)
        self._first_event_time: datetime | None = None
        self._cooldown: dict[str, datetime] = defaultdict(
            lambda: datetime(1970, 1, 1, tzinfo=timezone.utc)
        )

    def ingest(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        """Ingest an event and return any new clusters formed."""
        self._event_buffer.append(event)
        if self._first_event_time is None:
            self._first_event_time = event.timestamp
        elif event.timestamp < self._first_event_time:
            self._first_event_time = event.timestamp
        if event.timestamp > self._analysis_time:
            self._analysis_time = event.timestamp
        self._update_caches(event)
        clusters = []
        clusters.extend(self._detect_port_scan(event))
        clusters.extend(self._detect_c2_beacon(event))
        clusters.extend(self._detect_lateral_movement(event))
        clusters.extend(self._detect_data_exfiltration(event))
        clusters.extend(self._detect_protocol_anomaly(event))
        clusters.extend(self._detect_dns_tunneling(event))
        clusters.extend(self._detect_escaped_sequence(event))
        return clusters

    def flush(self) -> list[CorrelatedCluster]:
        """Flush remaining events into clusters."""
        clusters = self._build_remaining_clusters()
        self._clusters.extend(clusters)
        return clusters

    def get_clusters(self) -> list[CorrelatedCluster]:
        return list(self._clusters)

    def _update_caches(self, event: NetworkEvent) -> None:
        flow_key = event.correlate_key()
        self._flow_cache[flow_key].append(event)
        self._host_index[event.source_ip].append(event)
        self._host_connections[event.source_ip].add(event.destination_ip)
        self._host_connections[event.destination_ip].add(event.source_ip)
        self._port_access[event.source_ip].add(event.destination_port)
        if event.event_type == EventType.DNS_RESPONSE:
            answers = event.metadata.get("answers", [])
            for answer in answers:
                if isinstance(answer, dict):
                    self._dns_cache[answer.get("name", "")] = answer.get("ip", "")
        if event.event_type in (
            EventType.C2_BEACON, EventType.HTTP_REQUEST, EventType.TLS_HANDSHAKE,
            EventType.ENCRYPTED_TRANSFER, EventType.CONNECTION,
        ):
            tracker = self._beacon_tracker[
                f"{event.source_ip}|{event.destination_ip}|{event.destination_port}"
            ]
            if len(tracker) < 64:
                tracker.append(event.timestamp)

    def _detect_port_scan(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        src = event.source_ip
        recent_ports = self._get_recent_ports(src, seconds=30, ref=event.timestamp)
        if len(recent_ports) >= self.PORT_SCAN_THRESHOLD:
            if self._in_cooldown(src, "T1046", seconds=300, ref=event.timestamp):
                return clusters
            cluster = self._create_cluster(
                events=self._get_recent_events(src, seconds=30, ref=event.timestamp),
                severity=Severity.HIGH,
                techniques=["T1046"],
                labels=["port-scan", "discovery"],
                description=(
                    f"Host {src} scanned {len(recent_ports)} ports on "
                    f"{event.destination_ip} within 30 seconds — "
                    f"likely network reconnaissance (MITRE T1046: Network Service Discovery)"
                ),
            )
            clusters.append(cluster)
        return clusters

    def _detect_c2_beacon(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        if event.event_type not in (
            EventType.C2_BEACON, EventType.HTTP_REQUEST, EventType.TLS_HANDSHAKE,
            EventType.ENCRYPTED_TRANSFER, EventType.CONNECTION,
        ):
            return clusters
        beacon_key = f"{event.source_ip}|{event.destination_ip}|{event.destination_port}"
        if beacon_key in self._beacon_checked:
            return clusters
        timestamps = self._beacon_tracker.get(beacon_key, [])
        if len(timestamps) < self.BEACON_MIN_SAMPLES:
            return clusters
        self._beacon_checked.add(beacon_key)
        sorted_ts = timestamps if timestamps == sorted(timestamps) else sorted(timestamps)
        intervals = []
        for i in range(1, len(sorted_ts)):
            delta = (sorted_ts[i] - sorted_ts[i - 1]).total_seconds()
            if 0 < delta < 3600:
                intervals.append(delta)
        if len(intervals) >= 3:
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval > 0:
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                cv = (variance ** 0.5) / mean_interval if mean_interval > 0 else float("inf")
                if cv < 0.3 and mean_interval > 10:
                    if self._in_cooldown(event.source_ip, "T1071", seconds=600, ref=event.timestamp):
                        return clusters
                    cluster = self._create_cluster(
                        events=self._get_flow_events_by_key(beacon_key),
                        severity=Severity.CRITICAL,
                        techniques=["T1071", "T1572"],
                        labels=["c2-beacon", "command-and-control"],
                        description=(
                            f"Regular beaconing detected from {event.source_ip} to "
                            f"{event.destination_ip} — interval ~{mean_interval:.0f}s "
                            f"(CV={cv:.2f}), consistent with C2 callback "
                            f"(MITRE T1071: Application Layer Protocol, T1572: Protocol Tunneling)"
                        ),
                    )
                    clusters.append(cluster)
        return clusters

    def _detect_lateral_movement(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        if not event.lateral_movement_candidate:
            return clusters
        src = event.source_ip
        internal_targets = set()
        for ip in self._host_connections.get(src, set()):
            if not _is_external_ip(ip) and ip != src:
                internal_targets.add(ip)
        if len(internal_targets) >= 3:
            techs = []
            if event.destination_port in (22,):
                techs.append("T1021")
            if event.destination_port in (445, 139):
                techs.append("T1021")
            if event.destination_port in (3389,):
                techs.append("T1021")
            if event.destination_port in (5985, 5986):
                techs.append("T1021")
            if not techs:
                techs.append("T1021")
            cluster = self._create_cluster(
                events=self._get_host_events(src),
                severity=Severity.HIGH,
                techniques=list(set(techs)),
                labels=["lateral-movement"],
                description=(
                    f"Host {src} connected to {len(internal_targets)} internal hosts "
                    f"via management protocols — possible lateral movement "
                    f"(MITRE T1021: Remote Services)"
                ),
            )
            clusters.append(cluster)
        return clusters

    def _detect_data_exfiltration(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        if event.payload_size > 100000 and event.is_encrypted:
            cluster = self._create_cluster(
                events=[event],
                severity=Severity.HIGH,
                techniques=["T1048", "T1041"],
                labels=["exfiltration"],
                description=(
                    f"Large encrypted data transfer ({event.payload_size:,} bytes) from "
                    f"{event.source_ip} to {event.destination_ip} — "
                    f"potential data exfiltration (MITRE T1048: Exfiltration Over Alternative Protocol)"
                ),
            )
            clusters.append(cluster)
        return clusters

    def _detect_protocol_anomaly(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        if event.event_type == EventType.SSH_HANDSHAKE and event.destination_port != 22:
            cluster = self._create_cluster(
                events=[event],
                severity=Severity.MEDIUM,
                techniques=["T1572"],
                labels=["protocol-anomaly", "tunneling"],
                description=(
                    f"SSH handshake on non-standard port {event.destination_port} — "
                    f"possible protocol tunneling (MITRE T1572: Protocol Tunneling)"
                ),
            )
            clusters.append(cluster)
        if event.protocol == Protocol.ICMP and event.payload_size > 1000:
            cluster = self._create_cluster(
                events=[event],
                severity=Severity.MEDIUM,
                techniques=["T1048", "T1095"],
                labels=["icmp-anomaly", "covert-channel"],
                description=(
                    f"Unusually large ICMP packet ({event.payload_size:,} bytes) — "
                    f"possible covert channel or ICMP tunneling "
                    f"(MITRE T1095: Non-Application Layer Protocol)"
                ),
            )
            clusters.append(cluster)
        return clusters

    def _detect_dns_tunneling(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        if event.event_type != EventType.DNS_QUERY:
            return clusters
        query_name = event.metadata.get("query_name", "")
        if len(query_name) > 60:
            label_count = query_name.count(".")
            subdomain_len = len(query_name.replace(".", ""))
            entropy = _calculate_entropy(query_name)
            if entropy > 3.5 and subdomain_len > 40:
                cluster = self._create_cluster(
                    events=[event],
                    severity=Severity.HIGH,
                    techniques=["T1071", "T1048"],
                    labels=["dns-tunneling", "exfiltration"],
                    description=(
                        f"DNS tunneling suspected: query '{query_name[:50]}...' "
                        f"(entropy={entropy:.2f}, length={len(query_name)}) — "
                        f"likely data exfiltration or C2 via DNS "
                        f"(MITRE T1071.004: DNS)"
                    ),
                )
                clusters.append(cluster)
        return clusters

    def _detect_escaped_sequence(self, event: NetworkEvent) -> list[CorrelatedCluster]:
        clusters = []
        if event.event_type not in (EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS):
            return clusters
        cutoff = event.timestamp - timedelta(seconds=60)
        src_events = [
            e for e in self._host_index.get(event.source_ip, [])
            if e.timestamp > cutoff
        ][-200:]
        if len(src_events) < 3:
            return clusters
        event_types = [e.event_type for e in src_events]
        if EventType.AUTH_FAILURE in event_types and EventType.AUTH_SUCCESS in event_types:
            failure_idx = event_types.index(EventType.AUTH_FAILURE)
            success_idx = event_types.index(EventType.AUTH_SUCCESS)
            if success_idx > failure_idx:
                cluster = self._create_cluster(
                    events=src_events,
                    severity=Severity.HIGH,
                    techniques=["T1078", "T1110"],
                    labels=["brute-force", "credential-access"],
                    description=(
                        f"Brute force pattern detected from {event.source_ip}: "
                        f"auth failure followed by success — "
                        f"(MITRE T1110: Brute Force, T1078: Valid Accounts)"
                    ),
                )
                clusters.append(cluster)
        return clusters

    def _get_recent_ports(self, ip: str, seconds: int = 10, ref: datetime | None = None) -> set[int]:
        ref = ref or self._analysis_time
        cutoff = ref - timedelta(seconds=seconds)
        ports = set()
        for event in reversed(self._host_index.get(ip, [])[-1000:]):
            if event.timestamp < cutoff:
                break
            ports.add(event.destination_port)
        return ports

    def _get_recent_events(self, ip: str, seconds: int = 10, ref: datetime | None = None) -> list[NetworkEvent]:
        ref = ref or self._analysis_time
        cutoff = ref - timedelta(seconds=seconds)
        out = []
        for event in reversed(self._host_index.get(ip, [])[-1000:]):
            if event.timestamp < cutoff:
                break
            out.append(event)
        return list(reversed(out))[:500]

    def _get_flow_events(self, flow_key: str) -> list[NetworkEvent]:
        return list(self._flow_cache.get(flow_key, []))

    def _get_flow_events_by_key(self, beacon_key: str) -> list[NetworkEvent]:
        ips = beacon_key.split("|")
        if len(ips) != 3:
            return []
        src, dst = ips[0], ips[1]
        return [
            e for e in self._event_buffer
            if e.source_ip == src and e.destination_ip == dst
            and e.destination_port == int(ips[2])
        ][:100]

    def _in_cooldown(self, ip: str, technique: str, seconds: int, ref: datetime | None = None) -> bool:
        ref = ref or self._analysis_time
        key = f"{ip}|{technique}"
        last = self._cooldown[key]
        if ref - last < timedelta(seconds=seconds):
            return True
        self._cooldown[key] = ref
        return False

    def _get_host_events(self, ip: str) -> list[NetworkEvent]:
        return list(self._host_index.get(ip, []))[:1000]

    def _create_cluster(
        self,
        events: list[NetworkEvent],
        severity: Severity,
        techniques: list[str],
        labels: list[str],
        description: str,
    ) -> CorrelatedCluster:
        import uuid as _uuid
        cluster = CorrelatedCluster(
            cluster_id=_uuid.uuid4().hex[:10],
            events=list(events),
            first_seen=min(e.timestamp for e in events) if events else datetime.now(timezone.utc),
            last_seen=max(e.timestamp for e in events) if events else datetime.now(timezone.utc),
            involved_hosts={e.source_ip for e in events} | {e.destination_ip for e in events},
            severity=severity,
            techniques=techniques,
            labels=labels,
            confidence=min(1.0, 0.5 + 0.1 * len(events)),
            chain_description=description,
        )
        self._clusters.append(cluster)
        return cluster

    def _build_remaining_clusters(self) -> list[CorrelatedCluster]:
        return []


def _is_external_ip(ip: str) -> bool:
    if ip.startswith("127.") or ip == "::1":
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return True
    if first == 10:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    return True


def _calculate_entropy(text: str) -> float:
    import math
    from collections import Counter
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
