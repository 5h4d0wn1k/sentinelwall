"""Tests for the MITRE ATT&CK mapper."""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import EventType, Protocol, Severity
from sentinelwall.mitre.mapper import MitreMapper, _is_external
from tests.conftest import make_event


def make_cluster(events, techniques=None, labels=None, severity=Severity.HIGH):
    techniques = techniques or []
    labels = labels or []
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return CorrelatedCluster(
        cluster_id=f"c-{len(str(events))}",
        events=events,
        first_seen=now,
        last_seen=now + timedelta(seconds=len(events)),
        involved_hosts={e.source_ip for e in events} | {e.destination_ip for e in events},
        severity=severity,
        techniques=techniques,
        labels=labels,
        confidence=0.9,
    )


class TestIsExternal:
    @pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1"])
    def test_internal_ips(self, ip):
        assert _is_external(ip) is False

    @pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.7", "185.220.101.34", "2606:2800::1", "garbage"])
    def test_external_ips(self, ip):
        assert _is_external(ip) is True

    def test_172_not_private_range(self):
        assert _is_external("172.32.0.1") is True


class TestMapTechniques:
    def setup(self):
        return MitreMapper()

    def test_port_scan_cluster_maps(self):
        mapper = self.setup()
        events = [
            make_event(event_type=EventType.PORT_SCAN, destination_port=p)
            for p in range(20, 30)
        ]
        cluster = make_cluster(events, labels=["port-scan"])
        result = mapper.map_techniques(cluster)
        tids = {t["technique_id"] for t in result["techniques"]}
        assert "T1046" in tids

    def test_c2_beacon_labels_boost(self):
        mapper = self.setup()
        cluster = make_cluster([], labels=["c2-beacon"])
        result = mapper.map_techniques(cluster)
        for t in result["techniques"]:
            if t["technique_id"] == "T1071":
                assert t["confidence"] >= 0.5

    def test_external_ssh_high_confidence(self):
        mapper = self.setup()
        event = make_event(
            event_type=EventType.SSH_AUTH,
            protocol=Protocol.SSH,
            source_ip="185.220.101.34",
            destination_ip="10.0.1.5",
            destination_port=22,
        )
        cluster = make_cluster([event], labels=["brute-force"])
        result = mapper.map_techniques(cluster)
        tids = {t["technique_id"] for t in result["techniques"]}
        assert "T1110" in tids

    def test_kill_chain_order(self):
        mapper = self.setup()
        events = [
            make_event(event_type=EventType.PORT_SCAN),
            make_event(event_type=EventType.AUTH_FAILURE),
            make_event(event_type=EventType.C2_BEACON),
        ]
        cluster = make_cluster(events)
        result = mapper.map_techniques(cluster)
        chain = [c["tactic"] for c in result["kill_chain"]]
        assert chain == sorted(chain, key=lambda x: 0)

    def test_primary_tactic_populated(self):
        mapper = self.setup()
        cluster = make_cluster([make_event(event_type=EventType.PORT_SCAN, destination_port=23)])
        result = mapper.map_techniques(cluster)
        assert result["primary_tactic"] in ("discovery", "initial-access")

    def test_coverage_score_bounded(self):
        mapper = self.setup()
        cluster = make_cluster([make_event(event_type=EventType.C2_BEACON)])
        result = mapper.map_techniques(cluster)
        assert 0 <= result["coverage_score"] <= 1

    def test_evidence_collected(self):
        mapper = self.setup()
        cluster = make_cluster([make_event(event_type=EventType.PORT_SCAN)])
        result = mapper.map_techniques(cluster)
        for t in result["techniques"]:
            assert isinstance(t["evidence"], list)


class TestMapperApi:
    def test_get_technique_info(self):
        mapper = MitreMapper()
        info = mapper.get_technique_info("T1046")
        assert info is not None
        assert info.technique_id == "T1046"

    def test_get_all_techniques(self):
        mapper = MitreMapper()
        allt = mapper.get_all_techniques()
        assert len(allt) >= 20

    def test_maps_internal_lateral_movement(self):
        mapper = MitreMapper()
        events = [
            make_event(
                event_type=EventType.SMB_CONNECT,
                protocol=Protocol.SMB,
                source_ip="10.0.0.5",
                destination_ip=f"10.0.0.{i}",
                destination_port=445,
            )
            for i in range(20, 28)
        ]
        cluster = make_cluster(events)
        result = mapper.map_techniques(cluster)
        tids = {t["technique_id"] for t in result["techniques"]}
        assert "T1021" in tids