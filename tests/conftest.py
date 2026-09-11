"""Shared pytest fixtures and test utilities."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

import pytest

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity


def make_event(
    *,
    source_ip: str = "10.0.0.10",
    destination_ip: str = "93.184.216.34",
    source_port: int = 54321,
    destination_port: int = 443,
    protocol: Protocol = Protocol.HTTPS,
    event_type: EventType = EventType.TLS_HANDSHAKE,
    severity: Severity = Severity.INFORMATIONAL,
    payload_size: int = 100,
    payload_preview: str = "",
    timestamp: datetime | None = None,
    tags: list[str] | None = None,
    metadata: dict | None = None,
) -> NetworkEvent:
    return NetworkEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        event_type=event_type,
        severity=severity,
        payload_size=payload_size,
        payload_preview=payload_preview,
        tags=tags or [],
        metadata=metadata or {},
    )


def make_flow(
    n: int,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    start: datetime | None = None,
    interval: float = 1.0,
    **kwargs,
) -> list[NetworkEvent]:
    """Make n events forming a chronological flow."""
    base = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        make_event(
            timestamp=base + timedelta(seconds=i * interval),
            source_ip=src, destination_ip=dst,
            **kwargs,
        )
        for i in range(n)
    ]


def make_benign_flow(n: int = 50, **kwargs) -> list[NetworkEvent]:
    """Standard benign internal->web flow for correlation tests."""
    return make_flow(n, src="10.0.0.10", dst="8.8.8.8", port_override=None, **kwargs)


class MockPcapBuilder:
    """Builds minimal syntactically-valid pcap files for reader tests."""

    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101

    def build(self, packets: list[bytes], linktype: int = 1) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
        out = [header]
        ts = 1700000000
        for pkt in packets:
            out.append(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)))
            out.append(pkt)
            ts += 1
        return b"".join(out)

    def ethernet_frame(self, payload: bytes, eth_type: int = 0x0800) -> bytes:
        src = b"\x00\x11\x22\x33\x44\x55"
        dst = b"\x66\x77\x88\x99\xaa\xbb"
        return src + dst + struct.pack(">H", eth_type) + payload

    def ipv4(self, payload: bytes, src: str, dst: str, proto: int = 6) -> bytes:
        import socket
        ihl = 5
        ver_ihl = (4 << 4) | ihl
        total_len = 20 + len(payload)
        header = struct.pack(
            ">BBHHHBBH4s4s",
            ver_ihl, 0, total_len, 0x1234, 0x4000, 64, proto, 0,
            socket.inet_aton(src), socket.inet_aton(dst),
        )
        return header + payload

    def tcp(self, payload: bytes, sport: int, dport: int, syn: bool = True) -> bytes:
        flags = 0x02 if syn else 0x18

        header = struct.pack(">HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, flags, 65535, 0, 0)
        return header + payload

    def udp(self, payload: bytes, sport: int, dport: int) -> bytes:
        header = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
        return header + payload

    def icmp(self, payload: bytes, icmp_type: int = 8) -> bytes:
        return struct.pack(">BBH", icmp_type, 0, 0) + payload

    def ipv6(self, payload: bytes, src: str, dst: str, proto: int = 6) -> bytes:
        header = struct.pack(">IHBB16s16s", 0, 0, 1, proto, src.encode(), dst.encode())
        return header + payload

    def dns_query(self, name: str = "example.com", qtype: int = 1) -> bytes:
        import random
        txn = random.randint(0, 0xFFFF)
        flags = 0x0100
        body = struct.pack(">HHHHHH", txn, flags, 1, 0, 0, 0)
        for label in name.split("."):
            body += bytes([len(label)]) + label.encode()
        body += b"\x00"
        body += struct.pack(">HH", qtype, 1)
        return body


@pytest.fixture
def event() -> NetworkEvent:
    return make_event()


@pytest.fixture
def pcap_builder() -> MockPcapBuilder:
    return MockPcapBuilder()


@pytest.fixture
def benign_events() -> list[NetworkEvent]:
    from sentinelwall.ml.synthetic import generate_benign_traffic
    return generate_benign_traffic(duration_minutes=5, samples_per_minute=4, seed=7)


@pytest.fixture
def attack_events() -> list[NetworkEvent]:
    from sentinelwall.ml.synthetic import generate_attack_scenario
    events, _ = generate_attack_scenario("multi-stage")
    return events


@pytest.fixture
def zeek_conn_log(tmp_path):
    """Create a sample Zeek conn.log and return its path."""
    path = tmp_path / "conn.log"
    content = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2026-01-01-00-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
        "#types\ttime\tstring\tip\tport\tip\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n"
    )
    lines = [
        "1700000000.000000\tCID1\t192.168.1.10\t54321\t8.8.8.8\t443\ttcp\ttls\t0.5\t1000\t5000\tSF\tT\tT\t0\tShADadfF\t10\t2000\t10\t8000\t-\n",
        "1700000100.000000\tCID2\t10.0.0.5\t22\t8.8.8.8\t53\ttcp\tdns\t0.1\t50\t100\tSF\tT\tF\t0\tShADadfF\t5\t500\t5\t800\t-\n",
    ]
    path.write_text(content + "".join(lines))
    return path


@pytest.fixture
def zeek_ssh_log(tmp_path):
    path = tmp_path / "ssh.log"
    content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tauth_attempts\tdirection\tclient\tserver\tcipher_alg\tmac_alg\tcompression_alg\tkex_alg\thost_key_alg\thost_key\tgeo\n"
    )
    lines = [
        "1700000000.000000\tSSH1\t185.220.101.34\t40000\t10.0.1.5\t22\tSSH-2.0-OpenSSH_7.4\tF\t3\tINBOUND\tSSH-2.0-PuTTY_Release_0.70\tSSH-2.0-OpenSSH_7.4\taes128-ctr\thmac-sha2-256\tnone\tcurve25519-sha256\trsa-sha2-512\t-\t-\n",
        "1700000040.000000\tSSH2\t185.220.101.34\t40001\t10.0.1.5\t22\tSSH-2.0-OpenSSH_7.4\tT\t4\tINBOUND\tSSH-2.0-PuTTY_Release_0.70\tSSH-2.0-OpenSSH_7.4\taes128-ctr\thmac-sha2-256\tnone\tcurve25519-sha256\trsa-sha2-512\t-\t-\n",
    ]
    path.write_text(content + "".join(lines))
    return path


@pytest.fixture
def suricata_eve_log(tmp_path):
    path = tmp_path / "eve.json"
    lines = [
        '{"timestamp":"2026-01-01T00:00:00.000000+0000","flow_id":100,"event_type":"alert","src_ip":"203.0.113.7","src_port":4444,"dest_ip":"192.168.1.5","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2010931,"rev":5,"signature":"ET SCAN Suspicious inbound to mySQL port 3306","category":"Misc Attack","severity":2}}',
        '{"timestamp":"2026-01-01T00:00:05.000000+0000","event_type":"dns","src_ip":"10.0.0.4","src_port":54000,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":100,"query":"malware-example.com","rrtype":"A"}}',
        '{"timestamp":"2026-01-01T00:00:10.000000+0000","event_type":"tls","src_ip":"10.0.0.4","src_port":54001,"dest_ip":"185.220.41.99","dest_port":443,"proto":"TCP","tls":{"version":"TLS 1.2","sni":"evil-cc.example.org"}}',
    ]
    path.write_text("\n".join(lines))
    return path