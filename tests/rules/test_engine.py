"""Tests for the rule engine and built-in rules."""

import pytest

from sentinelwall.core.events import Protocol, Severity
from sentinelwall.rules.engine import RuleEngine
from sentinelwall.rules.parser import Rule, RuleCondition
from tests.conftest import make_event


class TestRuleEngineEvaluate:
    def test_no_matches_on_benign(self):
        engine = RuleEngine()
        event = make_event(protocol=Protocol.DNS, destination_port=53)
        assert engine.evaluate(event) == []

    def test_ssh_non_standard_fires(self):
        engine = RuleEngine()
        event = make_event(
            protocol=Protocol.SSH,
            event_type="SSH_HANDSHAKE",
            destination_port=2222,
        )
        matches = engine.evaluate(event)
        names = {m["rule_name"] for m in matches}
        assert "ssh_non_standard_port" in names

    def test_match_structure(self):
        engine = RuleEngine()
        event = make_event(protocol=Protocol.SSH, event_type="SSH_HANDSHAKE", destination_port=2222)
        match = engine.evaluate(event)[0]
        assert "rule_name" in match
        assert "severity" in match
        assert "techniques" in match
        assert "description" in match
        assert "tags" in match

    def test_add_rule_programmatic(self):
        engine = RuleEngine()
        n_builtin = len(engine.get_builtin_rules())
        engine.add_rule(Rule(
            name="test_rule", description="t",
            severity=Severity.HIGH,
            conditions=[RuleCondition("destination_port", "eq", 9999)],
        ))
        assert len(engine.get_custom_rules()) == 1
        event = make_event(destination_port=9999)
        assert engine.evaluate(event)

    def test_load_rules_from_string(self):
        engine = RuleEngine()
        count = engine.load_rules_from_string(
            "rule r1:\n    condition:\n        protocol == tcp"
        )
        assert count == 1
        assert len(engine.get_custom_rules()) == 1

    def test_load_rules_from_file(self, tmp_path):
        path = tmp_path / "r.swl"
        path.write_text("rule r2:\n    condition:\n        protocol == icmp")
        engine = RuleEngine()
        assert engine.load_rules_from_file(str(path)) == 1

    def test_get_rules_combined(self):
        engine = RuleEngine()
        all_rules = engine.get_rules()
        assert len(all_rules) == len(engine.get_builtin_rules())

    def test_event_to_dict_fields(self):
        engine = RuleEngine()
        event = make_event()
        d = engine._event_to_dict(event)
        for key in [
            "event_id", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "event_type", "severity",
            "payload_size", "payload_preview", "direction", "tags",
            "confidence", "is_encrypted", "lateral_movement_candidate",
            "metadata",
        ]:
            assert key in d


class TestBuiltinRules:
    @pytest.mark.parametrize("rule_name,event_kwargs", [
        ("port_scan_high_volume", {"event_type": "PORT_SCAN"}),
        ("brute_force_auth_failure", {"event_type": "AUTH_FAILURE"}),
        ("icmp_large_payload", {"event_type": "ICMP_ECHO", "protocol": Protocol.ICMP, "payload_size": 5000}),
        ("rdp_external_access", {"protocol": Protocol.SSH, "event_type": "SSH_HANDSHAKE", "destination_port": 3389}),
        ("http_post_large_upload", {"event_type": "HTTP_REQUEST", "payload_size": 60000}),
        ("large_encrypted_transfer", {"event_type": "ENCRYPTED_TRANSFER", "protocol": Protocol.HTTPS, "payload_size": 200000}),
        ("dns_query_long_subdomain", {"event_type": "DNS_QUERY", "protocol": Protocol.DNS, "payload_size": 300}),
        ("ftp_data_transfer", {"event_type": "DATA_TRANSFER", "destination_port": 20}),
        ("sensitive_port_access", {"destination_port": 5985}),
        ("vnc_remote_access", {"destination_port": 5900}),
        ("ntp_reconnaissance", {"event_type": "DNS_QUERY", "protocol": Protocol.DNS, "destination_port": 123}),
        ("tls_certificate_anomaly", {"event_type": "TLS_HANDSHAKE", "payload_preview": "self-signed cert"}),
        ("kerberoasting", {"event_type": "DNS_QUERY", "protocol": Protocol.DNS, "destination_port": 88, "payload_size": 600}),
        ("icmp_tunneling_suspected", {"event_type": "ICMP_ECHO", "protocol": Protocol.ICMP, "payload_size": 800}),
        ("smb_lateral_movement", {
            "event_type": "SMB_CONNECT", "protocol": Protocol.SMB,
            "source_ip": "10.0.0.5", "destination_ip": "10.0.0.9",
            "destination_port": 445,
        }),
        ("encrypted_transfer_internal", {
            "event_type": "ENCRYPTED_TRANSFER", "protocol": Protocol.HTTPS,
            "source_ip": "10.0.0.5", "destination_ip": "10.0.0.9",
            "destination_port": 443, "payload_size": 80000,
        }),
        ("smtp_data_exfil", {
            "event_type": "HTTP_REQUEST", "destination_port": 587,
            "payload_size": 20000,
        }),
        ("ssh_non_standard_port", {"protocol": Protocol.SSH, "event_type": "SSH_HANDSHAKE", "destination_port": 2222}),
    ])
    def test_builtin_fires(self, rule_name, event_kwargs):
        engine = RuleEngine()
        event = make_event(**event_kwargs)
        names = {m["rule_name"] for m in engine.evaluate(event)}
        assert rule_name in names, f"{rule_name} should fire for {event_kwargs}"

    def test_eighteen_builtin_rules(self):
        engine = RuleEngine()
        assert len(engine.get_builtin_rules()) == 18

    def test_all_builtins_have_techniques(self):
        engine = RuleEngine()
        for rule in engine.get_builtin_rules():
            assert rule.techniques, f"{rule.name} missing MITRE techniques"

    def test_builtin_benign_no_false_positives(self):
        engine = RuleEngine()
        event = make_event(protocol=Protocol.DNS, destination_port=53, payload_size=40)
        assert engine.evaluate(event) == []

    def test_port_scan_rule_lists_mitre(self):
        engine = RuleEngine()
        event = make_event(event_type="PORT_SCAN")
        for match in engine.evaluate(event):
            if match["rule_name"] == "port_scan_high_volume":
                assert "T1046" in match["techniques"]

    def test_negative_case_ssh_standard(self):
        engine = RuleEngine()
        event = make_event(
            protocol=Protocol.SSH, event_type="SSH_HANDSHAKE", destination_port=22
        )
        names = {m["rule_name"] for m in engine.evaluate(event)}
        assert "ssh_non_standard_port" not in names