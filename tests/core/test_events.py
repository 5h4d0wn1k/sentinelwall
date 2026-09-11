"""Tests for the NetworkEvent model."""

from datetime import datetime, timezone

import pytest

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity, _is_external
from tests.conftest import make_event


class TestNetworkEventConstruction:
    def test_minimal_event(self):
        event = make_event()
        assert event.event_id
        assert isinstance(event.event_id, str)

    def test_protocol_string_coercion(self):
        event = NetworkEvent(
            timestamp=datetime.now(timezone.utc), source_ip="1.1.1.1",
            destination_ip="2.2.2.2", source_port=1, destination_port=2,
            protocol="dns", event_type="DNS_QUERY", severity="LOW",
        )
        assert event.protocol == Protocol.DNS
        assert event.event_type == EventType.DNS_QUERY
        assert event.severity == Severity.LOW

    def test_unique_ids(self):
        a, b = make_event(), make_event()
        assert a.event_id != b.event_id


class TestEventProperties:
    def test_direction_outbound(self):
        event = make_event(source_ip="10.0.0.1", destination_ip="8.8.8.8")
        assert event.direction == "outbound"

    def test_direction_inbound(self):
        event = make_event(source_ip="203.0.113.5", destination_ip="10.0.0.1")
        assert event.direction == "inbound"

    def test_hash_stable(self):
        assert make_event().hash == make_event().hash

    def test_hash_content_sensitive(self):
        a = make_event(destination_port=443)
        b = make_event(destination_port=80)
        assert a.hash != b.hash

    def test_is_encrypted(self):
        assert make_event(protocol=Protocol.TLS).is_encrypted
        assert make_event(protocol=Protocol.SSH).is_encrypted
        assert make_event(protocol=Protocol.HTTP).is_encrypted is False

    def test_lateral_movement_candidate(self):
        event = make_event(
            source_ip="10.0.0.1", destination_ip="10.0.0.2",
            destination_port=445, protocol=Protocol.SMB,
        )
        assert event.lateral_movement_candidate

    def test_lateral_movement_not_external_src(self):
        event = make_event(
            source_ip="8.8.8.8", destination_ip="10.0.0.2",
            destination_port=445, protocol=Protocol.SMB,
        )
        assert not event.lateral_movement_candidate

    def test_lateral_movement_not_mgmt_port(self):
        event = make_event(
            source_ip="10.0.0.1", destination_ip="10.0.0.2",
            destination_port=8080,
        )
        assert not event.lateral_movement_candidate


class TestEventSerialization:
    def test_to_dict_fields(self):
        event = make_event(source_ip="10.1.1.1")
        d = event.to_dict()
        assert d["source_ip"] == "10.1.1.1"
        assert "event_type" in d and "severity" in d
        assert d["protocol"] == Protocol.HTTPS.value

    def test_to_json_serializable(self):
        import json
        parsed = json.loads(make_event().to_json())
        assert parsed["protocol"] == "https"

    def test_from_dict_roundtrip(self):
        event = make_event(payload_size=777, tags=["x"])
        clone = NetworkEvent.from_dict(event.to_dict())
        assert clone.payload_size == 777
        assert clone.tags == ["x"]
        assert clone.event_type == event.event_type

    def test_from_dict_timestamp_string(self):
        d = {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "protocol": "dns", "event_type": "DNS_QUERY",
            "severity": "HIGH",
        }
        event = NetworkEvent.from_dict(d)
        assert event.protocol == Protocol.DNS
        assert event.event_type == EventType.DNS_QUERY
        assert event.severity == Severity.HIGH

    def test_correlate_key_symmetric(self):
        a = make_event(source_ip="10.0.0.1", destination_ip="10.0.0.2",
                       source_port=1234, destination_port=443)
        b = make_event(source_ip="10.0.0.2", destination_ip="10.0.0.1",
                       source_port=443, destination_port=1234)
        assert a.correlate_key() == b.correlate_key()


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFORMATIONAL

    def test_comparison_equality(self):
        assert Severity.MEDIUM >= Severity.MEDIUM
        assert Severity.HIGH <= Severity.HIGH

    def test_from_name(self):
        assert Severity["CRITICAL"] == Severity.CRITICAL


class TestEventHelpers:
    @pytest.mark.parametrize("ip,expected", [
        ("10.0.0.1", False), ("172.16.0.1", False), ("172.31.255.255", False),
        ("192.168.1.1", False), ("127.0.0.1", False), ("169.254.1.1", False),
        ("8.8.8.8", True), ("203.0.113.5", True), ("172.32.0.1", True),
        ("::1", False), ("2001:db8::1", True),
    ])
    def test_is_external(self, ip, expected):
        assert _is_external(ip) is expected

    def test_event_dict_supports_metadata(self):
        event = make_event(metadata={"custom": {"nested": [1, 2]}})
        d = event.to_dict()
        assert d["metadata"]["custom"]["nested"] == [1, 2]