"""Tests for the Zeek log importer."""

import pytest

from sentinelwall.core.events import EventType, Protocol, Severity
from sentinelwall.integrations.zeek import ZeekImporter


class TestConnLog:
    def test_reads_events(self, zeek_conn_log):
        importer = ZeekImporter()
        events = importer.read(str(zeek_conn_log))
        assert len(events) == 2

    def test_connection_fields(self, zeek_conn_log):
        importer = ZeekImporter()
        events = importer.read(str(zeek_conn_log))
        e = events[0]
        assert e.source_ip == "192.168.1.10"
        assert e.destination_ip == "8.8.8.8"
        assert e.source_port == 54321
        assert e.destination_port == 443
        assert e.protocol == Protocol.TCP
        assert e.payload_size == 6000
        assert e.metadata["conn_state"] == "SF"

    def test_ports_parsed(self, zeek_conn_log):
        importer = ZeekImporter()
        events = importer.read(str(zeek_conn_log))
        assert events[1].destination_port == 53
        assert events[1].source_ip == "10.0.0.5"


class TestSshLog:
    def test_auth_failure_high_attempts(self, zeek_ssh_log):
        importer = ZeekImporter()
        events = importer.read(str(zeek_ssh_log))
        assert len(events) == 2
        e = events[0]
        assert e.event_type == EventType.AUTH_FAILURE
        assert e.protocol == Protocol.SSH
        assert e.metadata["auth_attempts"] == 3

    def test_auth_success(self, zeek_ssh_log):
        importer = ZeekImporter()
        events = importer.read(str(zeek_ssh_log))
        assert events[1].event_type == EventType.SSH_AUTH
        assert events[1].metadata["auth_success"] == "T"


class TestDnsLog:
    def test_dns_query_and_response(self, tmp_path):
        path = tmp_path / "dns.log"
        content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tquery\tqtype_name\tanswers\n"
            "1700000000.0\tD1\t10.0.0.5\t52000\t8.8.8.8\t53\tgoogle.com\tA\t7.8.7.8\n"
            "1700000100.0\tD2\t10.0.0.6\t52001\t8.8.8.8\t53\texample.com\tA\t-\n"
        )
        path.write_text(content)
        events = ZeekImporter().read(str(path))
        assert events[0].event_type == EventType.DNS_RESPONSE
        assert events[0].metadata["query_name"] == "google.com"
        assert events[0].metadata["answers"][0]["name"] == "7.8.7.8"
        assert events[1].event_type == EventType.DNS_QUERY


class TestHttpLog:
    def test_http_row(self, tmp_path):
        path = tmp_path / "http.log"
        content = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code\tresponse_body_len\tuser_agent\n"
            "1700000000.0\tH1\t10.0.0.5\t53000\t93.184.216.34\t80\tGET\texample.com\t/index.html\t200\t4200\tcurl/8.0\n"
        )
        path.write_text(content)
        events = ZeekImporter().read(str(path))
        e = events[0]
        assert e.event_type == EventType.HTTP_REQUEST
        assert e.metadata["method"] == "GET"
        assert e.metadata["host"] == "example.com"
        assert e.payload_size >= 4200


class TestSslLog:
    def test_ssl_row(self, tmp_path):
        path = tmp_path / "ssl.log"
        content = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\tversion\tcipher\testablished\n"
            "1700000000.0\tS1\t10.0.0.5\t54000\t185.220.41.99\t443\tevil.example.org\tTLSv1.2\tTLS_AES_128_GCM_SHA256\tT\n"
        )
        path.write_text(content)
        events = ZeekImporter().read(str(path))
        e = events[0]
        assert e.event_type == EventType.TLS_HANDSHAKE
        assert e.protocol == Protocol.HTTPS
        assert e.metadata["server_name"] == "evil.example.org"


class TestSmbLog:
    def test_smb_connect(self, tmp_path):
        path = tmp_path / "smb.log"
        content = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tcommand\tfilename\tpath\n"
            "1700000000.0\tM1\t10.0.0.5\t55000\t10.0.0.9\t445\tSMB2_CONNECT\t-\t\\\\10.0.0.9\\ADMIN$\n"
        )
        path.write_text(content)
        events = ZeekImporter().read(str(path))
        assert events[0].event_type == EventType.SMB_CONNECT
        assert events[0].protocol == Protocol.SMB


class TestLogTypeDetection:
    def test_detects_conn_by_fields(self, tmp_path):
        path = tmp_path / "custom.log"
        path.write_text("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n")
        assert ZeekImporter()._detect_log_type(str(path)) == "conn.log"

    def test_detects_dns_by_fields(self, tmp_path):
        path = tmp_path / "custom.log"
        path.write_text("#fields\tts\tuid\tquery\tanswer\tid.orig_h\tid.resp_h\n")
        assert ZeekImporter()._detect_log_type(str(path)) == "dns.log"

    def test_detects_ssl_by_fields(self, tmp_path):
        path = tmp_path / "custom.log"
        path.write_text("#fields\tts\tuid\tserver_name\tid.orig_h\tid.resp_h\n")
        assert ZeekImporter()._detect_log_type(str(path)) == "ssl.log"

    def test_detects_ssh_by_fields(self, tmp_path):
        path = tmp_path / "custom.log"
        path.write_text("#fields\tts\tuid\tauth_success\tid.orig_h\tid.resp_h\n")
        assert ZeekImporter()._detect_log_type(str(path)) == "ssh.log"

    def test_unknown_falls_back_to_conn(self, tmp_path):
        path = tmp_path / "custom.log"
        path.write_text("#fields\tfoo\tbar\n")
        assert ZeekImporter()._detect_log_type(str(path)) == "conn.log"


class TestEdgeCases:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(OSError):
            ZeekImporter().read(str(tmp_path / "nope.log"))

    def test_row_mismatch_skipped(self, tmp_path):
        path = tmp_path / "conn.log"
        content = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "1700000000.0\tC1\t10.0.0.5\t53000\n"
        )
        path.write_text(content)
        assert ZeekImporter().read(str(path)) == []

    def test_bad_ports_return_none(self, tmp_path):
        path = tmp_path / "conn.log"
        content = (
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "1700000000.0\tC1\t10.0.0.5\tnotaport\t8.8.8.8\t443\ttcp\n"
        )
        path.write_text(content)
        assert ZeekImporter().read(str(path)) == []

    def test_protocol_mapping(self):
        importer = ZeekImporter()
        assert importer._protocol_from_str("udp") == Protocol.UDP
        assert importer._protocol_from_str("bogus") == Protocol.UNKNOWN

    def test_timestamp_parse(self):
        importer = ZeekImporter()
        dt = importer._parse_ts("1700000000.500000")
        assert dt.timestamp() == pytest.approx(1700000000.5)