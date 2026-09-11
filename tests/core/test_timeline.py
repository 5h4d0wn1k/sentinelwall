"""Tests for the TimelineAnalyzer."""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelwall.core.timeline import AttackTimeline, TimelineAnalyzer
from sentinelwall.core.events import EventType, Protocol, Severity
from tests.conftest import make_event


def attack_events():
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(timestamp=start, event_type=EventType.PORT_SCAN,
                   source_ip="203.0.113.9", destination_ip="10.0.0.1",
                   destination_port=22),
        make_event(timestamp=start + timedelta(seconds=5),
                   event_type=EventType.SSH_HANDSHAKE,
                   protocol=Protocol.SSH, source_ip="203.0.113.9",
                   destination_ip="10.0.0.1", destination_port=22),
        make_event(timestamp=start + timedelta(seconds=10),
                   event_type=EventType.AUTH_FAILURE,
                   protocol=Protocol.SSH, source_ip="203.0.113.9",
                   destination_ip="10.0.0.1", destination_port=22),
        make_event(timestamp=start + timedelta(seconds=15),
                   event_type=EventType.AUTH_SUCCESS,
                   protocol=Protocol.SSH, source_ip="203.0.113.9",
                   destination_ip="10.0.0.1", destination_port=22),
        make_event(timestamp=start + timedelta(seconds=60),
                   event_type=EventType.C2_BEACON,
                   protocol=Protocol.HTTPS, source_ip="10.0.0.1",
                   destination_ip="185.220.101.34", destination_port=443),
        make_event(timestamp=start + timedelta(seconds=90),
                   event_type=EventType.ENCRYPTED_TRANSFER,
                   protocol=Protocol.HTTPS, source_ip="10.0.0.1",
                   destination_ip="185.220.101.34", destination_port=443,
                   payload_size=200000),
    ]
    return events


class TestTimelineConstruction:
    def test_empty_events(self):
        tl = TimelineAnalyzer().build_timeline([])
        assert tl.event_count == 0

    def test_builds_chronological(self):
        analyzer = TimelineAnalyzer()
        tl = analyzer.build_timeline(attack_events())
        assert tl.event_count == 6
        times = [e.timestamp for e in tl.entries]
        assert times == sorted(times)

    def test_sequence_numbers(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        assert [e.sequence_number for e in tl.entries] == [1, 2, 3, 4, 5, 6]

    def test_gap_from_previous(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        assert tl.entries[0].gap_from_previous.total_seconds() == 0
        assert tl.entries[1].gap_from_previous.total_seconds() == 5

    def test_attacker_identification(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        assert tl.attacker_ip == "203.0.113.9"

    def test_target_identification(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        assert tl.target_ip == "10.0.0.1"

    def test_kill_chain_phases_ordered(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        assert "reconnaissance" in tl.kill_chain_phases
        assert "credential-access" in tl.kill_chain_phases
        assert "command-and-control" in tl.kill_chain_phases
        assert tl.kill_chain_phases == list(dict.fromkeys(tl.kill_chain_phases))

    def test_total_duration(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        assert tl.total_duration.total_seconds() == 90

    def test_timeline_stored(self):
        analyzer = TimelineAnalyzer()
        analyzer.build_timeline(attack_events())
        assert len(analyzer.get_timelines()) == 1

    def test_multiple_timelines(self):
        analyzer = TimelineAnalyzer()
        analyzer.build_timeline(attack_events())
        analyzer.build_timeline(attack_events())
        assert len(analyzer.get_timelines()) == 2


class TestTimelinePhaseMapping:
    @pytest.mark.parametrize("event_type,phase", [
        (EventType.PORT_SCAN, "reconnaissance"),
        (EventType.DNS_QUERY, "reconnaissance"),
        (EventType.SSH_HANDSHAKE, "initial-access"),
        (EventType.SSH_AUTH, "initial-access"),
        (EventType.AUTH_FAILURE, "credential-access"),
        (EventType.AUTH_SUCCESS, "initial-access"),
        (EventType.HTTP_REQUEST, "execution"),
        (EventType.SMB_TRANSACTION, "lateral-movement"),
        (EventType.C2_BEACON, "command-and-control"),
        (EventType.ENCRYPTED_TRANSFER, "exfiltration"),
        (EventType.DATA_TRANSFER, "exfiltration"),
        (EventType.PERSISTENCE, "persistence"),
        (EventType.PRIVILEGE_ESCALATION, "privilege-escalation"),
        (EventType.DEFENSE_EVASION, "defense-evasion"),
        (EventType.COLLECTION, "collection"),
        (EventType.IMPACT, "impact"),
    ])
    def test_phase_map(self, event_type, phase):
        assert TimelineAnalyzer.PHASE_MAP[event_type] == phase

    def test_unknown_event_type(self):
        tl = TimelineAnalyzer().build_timeline([make_event(event_type=EventType.UNKNOWN)])
        assert tl.entries[0].phase == "unknown"


class TestTimelineSerialization:
    def test_to_dict(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        d = tl.to_dict()
        assert d["event_count"] == 6
        assert len(d["entries"]) == 6
        assert "timeline_id" in d
        assert "kill_chain_phases" in d

    def test_entry_dict(self):
        tl = TimelineAnalyzer().build_timeline(attack_events())
        entry = tl.entries[1]
        d = tl.to_dict()["entries"][1]
        assert d["gap_seconds"] == 5
        assert d["event_type"] == entry.event.event_type.name