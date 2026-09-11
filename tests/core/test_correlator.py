"""Tests for the EventCorrelator."""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelwall.core.correlator import EventCorrelator
from sentinelwall.core.events import EventType, Protocol, Severity
from tests.conftest import make_event, make_flow


class TestCorrelatorBasics:
    def test_ingest_no_clusters_for_benign(self):
        corr = EventCorrelator()
        for e in make_flow(10):
            assert corr.ingest(e) == []

    def test_get_clusters_empty(self):
        assert EventCorrelator().get_clusters() == []

    def test_ingest_accumulates_buffer(self):
        corr = EventCorrelator()
        corr.ingest(make_event())
        assert len(corr.get_clusters()) == 0


class TestPortScanDetection:
    def test_detects_port_scan(self):
        corr = EventCorrelator()
        events = []
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i, port in enumerate(range(1000, 1040)):
            events.append(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="203.0.113.9", destination_ip="10.0.0.1",
                destination_port=port, protocol=Protocol.TCP,
                event_type=EventType.PORT_SCAN,
            ))
        all_clusters = []
        for e in events:
            all_clusters.extend(corr.ingest(e))
        labeled = [c for c in all_clusters if "port-scan" in c.labels]
        assert labeled, "expected port-scan cluster"
        assert "T1046" in labeled[0].techniques

    def test_no_scan_below_threshold(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(3):
            cluster = corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="203.0.113.9", destination_ip="10.0.0.1",
                destination_port=1000 + i, protocol=Protocol.TCP,
                event_type=EventType.PORT_SCAN,
            ))
            assert cluster == []

    def test_scan_is_deduplicated_once(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        clusters = []
        for i, port in enumerate(range(1000, 1040)):
            clusters.extend(corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="203.0.113.9", destination_ip="10.0.0.1",
                destination_port=port, protocol=Protocol.TCP,
                event_type=EventType.PORT_SCAN,
            )))
        port_scans = [c for c in clusters if "port-scan" in c.labels]
        assert len(port_scans) == 1


class TestBeaconDetection:
    def test_detects_regular_beacon(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        clusters = []
        for i in range(6):
            clusters.extend(corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i * 20),
                source_ip="10.0.0.5", destination_ip="185.220.101.34",
                source_port=50000 + i, destination_port=443,
                protocol=Protocol.HTTPS, event_type=EventType.C2_BEACON,
                severity=Severity.HIGH,
            )))
        beacons = [c for c in clusters if "c2-beacon" in c.labels]
        assert beacons, "expected beacon cluster"
        assert beacons[0].severity == Severity.CRITICAL

    def test_irregular_traffic_not_beacon(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        clusters = []
        # deliberately irregular interval sequence: high variance
        offsets = [0, 5, 40, 55, 90, 150]
        for i, off in enumerate(offsets):
            clusters.extend(corr.ingest(make_event(
                timestamp=start + timedelta(seconds=off),
                source_ip="10.0.0.5", destination_ip="185.220.101.34",
                destination_port=443, protocol=Protocol.HTTPS,
                event_type=EventType.C2_BEACON,
            )))
        assert all("c2-beacon" not in c.labels for c in clusters)


class TestLateralMovement:
    def test_detects_lateral_movement(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        clusters = []
        for i, tgt in enumerate(["10.0.0.20", "10.0.0.21", "10.0.0.22"]):
            clusters.extend(corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="10.0.0.15", destination_ip=tgt,
                destination_port=445, protocol=Protocol.SMB,
                event_type=EventType.SMB_CONNECT,
            )))
        lateral = [c for c in clusters if "lateral-movement" in c.labels]
        assert lateral, "expected lateral movement cluster"

    def test_single_connection_not_lateral(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(2):
            clusters = corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="10.0.0.15", destination_ip="10.0.0.20",
                destination_port=445, protocol=Protocol.SMB,
                event_type=EventType.SMB_CONNECT,
            ))
            assert all("lateral-movement" not in c.labels for c in clusters)


class TestExfiltration:
    def test_detects_large_encrypted_transfer(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            event_type=EventType.ENCRYPTED_TRANSFER,
            protocol=Protocol.HTTPS, payload_size=250000,
            destination_ip="185.220.101.34",
        ))
        exfil = [c for c in clusters if "exfiltration" in c.labels]
        assert exfil

    def test_small_transfer_not_exfil(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            event_type=EventType.ENCRYPTED_TRANSFER,
            protocol=Protocol.HTTPS, payload_size=500,
        ))
        assert all("exfiltration" not in c.labels for c in clusters)


class TestProtocolAnomalies:
    def test_ssh_non_standard_port(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            protocol=Protocol.SSH, event_type=EventType.SSH_HANDSHAKE,
            destination_port=2222,
        ))
        asserted = [c for c in clusters if "protocol-anomaly" in c.labels]
        assert asserted, "expected protocol anomaly"
        assert "T1572" in asserted[0].techniques

    def test_icmp_large_payload(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            protocol=Protocol.ICMP, event_type=EventType.ICMP_ECHO,
            payload_size=5000,
        ))
        assert any("covert-channel" in c.labels for c in clusters)


class TestDnsTunneling:
    def test_long_high_entropy_query(self):
        corr = EventCorrelator()
        qname = "a" * 30 + "7f3d9a1b2c4e5f60718293a4b5c6d7e8f9091a2b3c.dns.evil.net"
        clusters = corr.ingest(make_event(
            protocol=Protocol.DNS, event_type=EventType.DNS_QUERY,
            destination_port=53, payload_size=300,
            payload_preview=f"query: {qname[:50]}",
            metadata={"query_name": qname},
        ))
        tunnel = [c for c in clusters if "dns-tunneling" in c.labels]
        assert tunnel, "expected dns tunneling detection"

    def test_normal_domain_not_tunnel(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            protocol=Protocol.DNS, event_type=EventType.DNS_QUERY,
            destination_port=53, payload_size=60,
            metadata={"query_name": "www.example.com"},
        ))
        assert all("dns-tunneling" not in c.labels for c in clusters)


class TestBruteForceSequence:
    def test_failure_then_success(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        clusters = []
        for i in range(3):
            clusters.extend(corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="203.0.113.9", destination_ip="10.0.0.1",
                destination_port=22, protocol=Protocol.SSH,
                event_type=EventType.AUTH_FAILURE,
            )))
        clusters.extend(corr.ingest(make_event(
            timestamp=start + timedelta(seconds=3),
            source_ip="203.0.113.9", destination_ip="10.0.0.1",
            destination_port=22, protocol=Protocol.SSH,
            event_type=EventType.AUTH_SUCCESS,
        )))
        brute = [c for c in clusters if "brute-force" in c.labels]
        assert brute
        assert "T1110" in brute[0].techniques

    def test_success_without_failure(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            protocol=Protocol.SSH, event_type=EventType.AUTH_SUCCESS,
        ))
        assert all("brute-force" not in c.labels for c in clusters)


class TestClusterProperties:
    def test_cluster_metrics(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            event_type=EventType.ENCRYPTED_TRANSFER,
            protocol=Protocol.HTTPS, payload_size=300000,
        ))
        assert clusters
        cluster = clusters[0]
        assert cluster.event_count >= 1
        assert cluster.confidence > 0
        assert cluster.first_seen <= cluster.last_seen
        assert cluster.unique_protocols
        assert cluster.involved_hosts

    def test_cluster_dict_fields(self):
        corr = EventCorrelator()
        clusters = corr.ingest(make_event(
            event_type=EventType.ENCRYPTED_TRANSFER, protocol=Protocol.HTTPS,
            payload_size=300000,
        ))
        d = clusters[0].to_dict()
        for key in ("cluster_id", "event_count", "first_seen", "involved_hosts",
                    "severity", "techniques", "labels", "confidence"):
            assert key in d

    def test_cluster_duration(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(7):
            corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i * 20),
                source_ip="10.0.0.5", destination_ip="185.220.101.34",
                destination_port=443, protocol=Protocol.HTTPS,
                event_type=EventType.C2_BEACON,
            ))
        clusters = corr.get_clusters()
        beacon = [c for c in clusters if "c2-beacon" in c.labels][0]
        assert beacon.duration.total_seconds() > 60


class TestCorrelatorTimehandling:
    def test_historical_events_still_correlate(self):
        """Events far in the past must still be correlated in batch mode."""
        corr = EventCorrelator()
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        clusters = []
        for i, port in enumerate(range(1000, 1040)):
            clusters.extend(corr.ingest(make_event(
                timestamp=start + timedelta(seconds=i),
                source_ip="203.0.113.9", destination_ip="10.0.0.1",
                destination_port=port, protocol=Protocol.TCP,
                event_type=EventType.PORT_SCAN,
            )))
        assert any("port-scan" in c.labels for c in clusters)

    def test_out_of_order_events(self):
        corr = EventCorrelator()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        e1 = make_event(timestamp=start, source_ip="10.0.0.1",
                        destination_ip="1.1.1.1", destination_port=80)
        e2 = make_event(timestamp=start - timedelta(seconds=5),
                        source_ip="10.0.0.1", destination_ip="2.2.2.2",
                        destination_port=81)
        corr.ingest(e1)
        corr.ingest(e2)
        assert corr.get_clusters() == []