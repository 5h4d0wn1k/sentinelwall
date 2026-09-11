"""Tests for the synthetic traffic generator."""

import pytest

from sentinelwall.core.events import EventType, Protocol
from sentinelwall.ml.synthetic import generate_attack_scenario, generate_benign_traffic


class TestBenignTraffic:
    def test_count_matches_params(self):
        events = generate_benign_traffic(duration_minutes=10, samples_per_minute=5, seed=1)
        assert len(events) == 50

    def test_default_count(self):
        events = generate_benign_traffic(seed=2)
        assert len(events) == 60 * 5

    def test_deterministic_with_seed(self):
        a = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=99)
        b = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=99)
        assert len(a) == len(b)
        assert all(
            ea.source_ip == eb.source_ip
            and ea.destination_ip == eb.destination_ip
            and ea.destination_port == eb.destination_port
            for ea, eb in zip(a, b)
        )

    def test_timestamps_chronological(self):
        events = generate_benign_traffic(duration_minutes=10, samples_per_minute=6, seed=3)
        ts = [e.timestamp for e in events]
        assert ts == sorted(ts)

    def test_internal_sources(self):
        events = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=4)
        for e in events:
            assert e.source_ip.startswith("10.")

    def test_only_benign_event_types(self):
        events = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=5)
        types = {e.event_type for e in events}
        assert types <= {EventType.DNS_QUERY, EventType.HTTP_REQUEST, EventType.CONNECTION}

    def test_informational_severity(self):
        events = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=6)
        assert all(e.severity.name == "INFORMATIONAL" for e in events)

    def test_uses_common_destinations(self):
        events = generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=7)
        assert events


class TestAttackScenarios:
    @pytest.mark.parametrize("scenario", [
        "multi-stage", "exfiltration", "brute-force",
        "lateral-movement", "c2-beacon", "dns-tunneling",
    ])
    def test_known_scenarios(self, scenario):
        events, techniques = generate_attack_scenario(scenario)
        assert events
        assert techniques

    def test_unknown_scenario(self):
        events, techniques = generate_attack_scenario("nonsense")
        assert events == []
        assert techniques == []

    def test_deterministic_scenario_seed(self):
        a, ta = generate_attack_scenario("multi-stage", seed=0xC0FFEE)
        b, tb = generate_attack_scenario("multi-stage", seed=0xC0FFEE)
        assert len(a) == len(b)
        assert ta == tb

    def test_scenario_timestamps_chronological(self):
        events, _ = generate_attack_scenario("multi-stage")
        ts = [e.timestamp for e in events]
        assert ts == sorted(ts)

    def test_different_seeds_vary(self):
        a, _ = generate_attack_scenario("multi-stage", seed=1)
        b, _ = generate_attack_scenario("multi-stage", seed=2)
        assert a != b


class TestScenarioGroundTruth:
    def test_multi_stage_techniques(self):
        _, techniques = generate_attack_scenario("multi-stage")
        for tech in ["T1046", "T1110", "T1071", "T1572", "T1048", "T1021"]:
            assert tech in techniques

    def test_exfiltration_techniques(self):
        _, techniques = generate_attack_scenario("exfiltration")
        assert "T1048" in techniques
        assert "T1071" in techniques

    def test_brute_force_techniques(self):
        events, techniques = generate_attack_scenario("brute-force")
        assert "T1110" in techniques
        assert len(events) >= 10
        assert all(e.event_type == EventType.AUTH_FAILURE for e in events)

    def test_lateral_movement_techniques(self):
        events, techniques = generate_attack_scenario("lateral-movement")
        assert "T1021" in techniques
        assert len(events) >= 9

    def test_c2_beacon_techniques(self):
        events, techniques = generate_attack_scenario("c2-beacon")
        assert "T1071" in techniques
        assert "T1572" in techniques
        beacon_types = {e.event_type for e in events}
        assert EventType.HTTP_REQUEST in beacon_types

    def test_dns_tunneling_techniques(self):
        events, techniques = generate_attack_scenario("dns-tunneling")
        assert "T1071" in techniques
        assert "T1048" in techniques
        assert len(events) == 8


class TestScenarioEventProperties:
    def test_multistage_has_c2_beacon_events(self):
        events, _ = generate_attack_scenario("multi-stage")
        beacon = [e for e in events if e.event_type == EventType.C2_BEACON]
        assert len(beacon) >= 5

    def test_multistage_has_bruteforce_events(self):
        events, _ = generate_attack_scenario("multi-stage")
        failures = [e for e in events if e.event_type == EventType.AUTH_FAILURE]
        assert len(failures) >= 5

    def test_multistage_has_port_scan(self):
        events, _ = generate_attack_scenario("multi-stage")
        scans = [e for e in events if e.event_type == EventType.PORT_SCAN]
        assert len(scans) >= 10

    def test_multistage_has_lateral_movement(self):
        events, _ = generate_attack_scenario("multi-stage")
        smb = [e for e in events if e.event_type == EventType.SMB_CONNECT]
        assert len(smb) >= 3

    def test_multistage_has_exfil(self):
        events, _ = generate_attack_scenario("multi-stage")
        exfil = [e for e in events if e.event_type == EventType.ENCRYPTED_TRANSFER]
        assert exfil

    def test_lateral_movement_targets_internal(self):
        events, _ = generate_attack_scenario("lateral-movement")
        assert all(e.protocol == Protocol.SMB for e in events)

    def test_c2_beacon_interval_consistent(self):
        events, _ = generate_attack_scenario("c2-beacon")
        http = [e for e in events if e.event_type == EventType.HTTP_REQUEST]
        deltas = [
            (http[i].timestamp - http[i - 1].timestamp).total_seconds()
            for i in range(1, len(http))
        ]
        assert all(50 <= d <= 70 for d in deltas)