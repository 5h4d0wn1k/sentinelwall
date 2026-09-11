"""Tests for the Suricata eve.json importer."""

import json

from sentinelwall.core.events import EventType, Protocol, Severity
from sentinelwall.integrations.suricata import SuricataImporter


class TestEveAlert:
    def test_reads_alerts(self, suricata_eve_log):
        events = SuricataImporter().read(str(suricata_eve_log))
        assert len(events) == 3

    def test_alert_fields(self, suricata_eve_log):
        events = SuricataImporter().read(str(suricata_eve_log))
        e = events[0]
        assert e.source_ip == "203.0.113.7"
        assert e.destination_ip == "192.168.1.5"
        assert e.destination_port == 22
        assert e.protocol == Protocol.TCP
        assert e.metadata["signature"].startswith("ET SCAN")
        assert e.metadata["signature_id"] == 2010931

    def test_alert_severity_mapping(self, suricata_eve_log):
        events = SuricataImporter().read(str(suricata_eve_log))
        assert events[0].severity == Severity.HIGH  # alert severity 2

    def test_dns_record(self, suricata_eve_log):
        events = SuricataImporter().read(str(suricata_eve_log))
        e = events[1]
        assert e.event_type == EventType.DNS_QUERY
        assert e.metadata["query_name"] == "malware-example.com"
        assert e.protocol == Protocol.DNS

    def test_tls_record(self, suricata_eve_log):
        events = SuricataImporter().read(str(suricata_eve_log))
        e = events[2]
        assert e.event_type == EventType.TLS_HANDSHAKE
        assert e.metadata["server_name"] == "evil-cc.example.org"
        assert e.protocol == Protocol.HTTPS


class TestFlowsAndSsh:
    def test_flow_large_transfer(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "timestamp": "2026-01-01T00:00:00.000000+0000",
            "event_type": "flow",
            "src_ip": "10.0.0.5", "src_port": 40000,
            "dest_ip": "203.0.113.9", "dest_port": 443,
            "proto": "TCP",
            "flow": {"bytes_toserver": 200000, "bytes_toclient": 5000},
        }))
        events = SuricataImporter().read(str(path))
        e = events[0]
        assert e.event_type == EventType.DATA_TRANSFER
        assert e.payload_size == 205000
        assert e.severity == Severity.MEDIUM

    def test_ssh_failed_attempt(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "timestamp": "2026-01-01T00:00:00.000000+0000",
            "event_type": "ssh",
            "src_ip": "185.220.101.34", "src_port": 40010,
            "dest_ip": "10.0.1.5", "dest_port": 22,
            "proto": "TCP",
            "ssh": {"auth_success": "failed", "client_software_version": "PuTTY"},
        }))
        e = SuricataImporter().read(str(path))[0]
        assert e.event_type == EventType.AUTH_FAILURE
        assert e.protocol == Protocol.SSH

    def test_ssh_success(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "timestamp": "2026-01-01T00:00:00.000000+0000",
            "event_type": "ssh",
            "src_ip": "10.0.1.5", "src_port": 40010,
            "dest_ip": "10.0.1.6", "dest_port": 22,
            "ssh": {"auth_success": "success"},
        }))
        e = SuricataImporter().read(str(path))[0]
        assert e.event_type == EventType.SSH_AUTH

    def test_http_record(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "timestamp": "2026-01-01T00:00:00.000000+0000",
            "event_type": "http",
            "src_ip": "10.0.0.5", "src_port": 50000,
            "dest_ip": "93.184.216.34", "dest_port": 80,
            "http": {"http_method": "POST", "hostname": "example.com", "url": "/api", "length": 400},
        }))
        e = SuricataImporter().read(str(path))[0]
        assert e.event_type == EventType.HTTP_REQUEST
        assert e.metadata["method"] == "POST"


class TestEdgeCases:
    def test_malformed_line_skipped(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text("{not json}\n")
        assert SuricataImporter().read(str(path)) == []

    def test_unknown_event_type_none(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({"event_type": "stats"}))
        assert SuricataImporter().read(str(path)) == []

    def test_empty_file(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text("")
        assert SuricataImporter().read(str(path)) == []

    def test_protocol_mapping(self):
        importer = SuricataImporter()
        assert importer._protocol_from_str("UDP") == Protocol.UDP
        assert importer._protocol_from_str("nope") == Protocol.UNKNOWN

    def test_port_scan_signature_detection(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "event_type": "alert",
            "src_ip": "203.0.113.1", "src_port": 1,
            "dest_ip": "192.168.1.5", "dest_port": 80,
            "alert": {"signature": "ET SCAN SYN Portscan Detection", "severity": 3},
        }))
        e = SuricataImporter().read(str(path))[0]
        assert e.event_type == EventType.PORT_SCAN

    def test_c2_signature_detection(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "event_type": "alert",
            "src_ip": "10.0.1.5", "src_port": 50000,
            "dest_ip": "185.220.41.99", "dest_port": 443,
            "alert": {"signature": "ET MALWARE C2 Beaconing Detected", "severity": 1},
        }))
        e = SuricataImporter().read(str(path))[0]
        assert e.event_type == EventType.C2_BEACON
        assert e.severity == Severity.CRITICAL

    def test_exfil_signature_detection(self, tmp_path):
        path = tmp_path / "eve.json"
        path.write_text(json.dumps({
            "event_type": "alert",
            "src_ip": "10.0.1.5", "src_port": 50000,
            "dest_ip": "203.0.113.9", "dest_port": 443,
            "alert": {"signature": "ET POLICY Large Exfil HTTP POST", "severity": 2},
        }))
        e = SuricataImporter().read(str(path))[0]
        assert e.event_type == EventType.EXFILTRATION