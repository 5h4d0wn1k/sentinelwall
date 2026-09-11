"""Tests for the pure-Python pcap reader."""

import socket
import struct
from datetime import datetime, timezone

import pytest

from sentinelwall.core.events import EventType, NetworkEvent, Protocol
from sentinelwall.integrations.pcap_reader import PcapReader
from tests.conftest import make_event, MockPcapBuilder


def read_builder(builder, packets, linktype=MockPcapBuilder.LINKTYPE_ETHERNET):
    data = builder.build(packets, linktype)
    return PcapReader()._parse(data)


class TestPcapHeader:
    def test_empty_data(self):
        assert PcapReader()._parse(b"") == []
        assert PcapReader()._parse(b"\x00" * 10) == []

    def test_truncated_global_header(self):
        assert PcapReader()._parse(b"") == []

    def test_magic_endianness_little_endian(self):
        data = MockPcapBuilder().build([])
        assert PcapReader()._parse(data) == []


class TestEthernetParsing:
    def test_tcp_syn_https(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 50000, 443), "10.0.0.5", "8.8.8.8")
        )
        events = read_builder(pcap_builder, [pkt])
        assert len(events) == 1
        e = events[0]
        assert e.event_type == EventType.TLS_HANDSHAKE
        assert e.protocol == Protocol.HTTPS
        assert e.source_ip == "10.0.0.5"
        assert e.destination_ip == "8.8.8.8"
        assert e.destination_port == 443

    def test_ssh_handshake_port(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"SSH-2.0-OpenSSH_8.9\r\n", 40000, 22), "10.0.0.5", "8.8.8.8")
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].event_type == EventType.SSH_HANDSHAKE
        assert events[0].protocol == Protocol.SSH
        assert "ssh_version" in events[0].metadata

    def test_http_get_parsed(self, pcap_builder):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(payload, 50001, 80, syn=False), "10.0.0.5", "93.184.216.34")
        )
        events = read_builder(pcap_builder, [pkt])
        e = events[0]
        assert e.event_type == EventType.HTTP_REQUEST
        assert e.protocol == Protocol.HTTP
        assert e.metadata["http"]["method"] == "GET"
        assert e.metadata["http"]["path"] == "/index.html"

    def test_smb_syn_frames(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 51000, 445), "10.0.0.5", "10.0.0.6")
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].event_type == EventType.SMB_CONNECT
        assert events[0].protocol == Protocol.SMB

    def test_rdp_and_vnc_ports(self, pcap_builder):
        rdp = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 52000, 3389), "10.0.0.5", "10.0.0.6")
        )
        vnc = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 52001, 5900), "10.0.0.5", "10.0.0.6")
        )
        events = read_builder(pcap_builder, [rdp, vnc])
        assert events[0].protocol == Protocol.RDP
        assert events[1].protocol == Protocol.VNC

    def test_large_tcp_payload_is_data_transfer(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"x" * 20000, 53000, 80, syn=False), "10.0.0.5", "8.8.8.8")
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].event_type == EventType.DATA_TRANSFER

    def test_non_ip_ethernet_ignored(self, pcap_builder):
        arp = pcap_builder.ethernet_frame(b"\x00\x01\x02\x03\x04\x05\x06\x07", eth_type=0x0806)
        assert read_builder(pcap_builder, [arp]) == []


class TestUdpParsing:
    def test_dns_query(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(
                pcap_builder.udp(pcap_builder.dns_query("example.com"), 54000, 53),
                "10.0.0.5", "8.8.8.8", proto=17,
            )
        )
        events = read_builder(pcap_builder, [pkt])
        e = events[0]
        assert e.event_type == EventType.DNS_QUERY
        assert e.protocol == Protocol.DNS
        assert e.metadata["query_name"] == "example.com"

    def test_dns_response_with_answer(self, pcap_builder):
        txn = 42
        header = struct.pack(">HHHHHH", txn, 0x8180, 1, 1, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")
        dns = header + question + answer
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.udp(dns, 54000, 53), "8.8.8.8", "10.0.0.5", proto=17)
        )
        events = read_builder(pcap_builder, [pkt])
        e = events[0]
        assert e.event_type == EventType.DNS_RESPONSE
        assert e.metadata["answers"][0]["ip"] == "93.184.216.34"

    def test_ntp_udp(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.udp(b"\x1b" + b"\x00" * 47, 50000, 123), "10.0.0.5", "162.159.200.1", proto=17)
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].protocol == Protocol.NTP

    def test_dhcp_udp(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.udp(b"\x01" + b"\x00" * 20, 68, 67), "0.0.0.0", "255.255.255.255", proto=17)
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].protocol == Protocol.DHCP


class TestIcmpParsing:
    def test_icmp_echo(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.icmp(b"\x00" * 40), "10.0.0.5", "8.8.8.8", proto=1)
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].event_type == EventType.ICMP_ECHO
        assert events[0].protocol == Protocol.ICMP

    def test_icmp_unreachable(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.icmp(b"\x00" * 8, icmp_type=3), "8.8.8.8", "10.0.0.5", proto=1)
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].event_type == EventType.ICMP_UNREACHABLE

    def test_large_icmp_medium_severity(self, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.icmp(b"\x00" * 1200), "10.0.0.5", "8.8.8.8", proto=1)
        )
        events = read_builder(pcap_builder, [pkt])
        assert events[0].severity.name == "MEDIUM"


class TestIpv6AndRaw:
    def test_ipv6_parsed(self, pcap_builder):
        src = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        dst = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        ip6 = struct.pack(">IHBB16s16s", 0x60000000, 0, 6, 6, src, dst)
        tcp = pcap_builder.tcp(b"", 50000, 443)
        pkt = pcap_builder.ethernet_frame(ip6 + tcp, eth_type=0x86DD)
        events = read_builder(pcap_builder, [pkt])
        assert len(events) == 1
        assert events[0].event_type == EventType.TLS_HANDSHAKE

    def test_raw_linktype(self, pcap_builder):
        raw_ipv4 = pcap_builder.ipv4(pcap_builder.tcp(b"", 43333, 80, syn=False), "10.0.0.5", "8.8.8.8")
        events = read_builder(pcap_builder, [raw_ipv4], linktype=MockPcapBuilder.LINKTYPE_RAW)
        assert events[0].event_type == EventType.HTTP_REQUEST

    def test_truncated_packet_skipped(self, pcap_builder):
        good = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 44000, 443), "10.0.0.5", "8.8.8.8")
        )
        bad = b"\x45" * 8  # too short to be an IP packet
        events = read_builder(pcap_builder, [bad, good])
        assert len(events) == 1


class TestWriteRoundTrip:
    def test_write_then_read(self, tmp_path):
        reader = PcapReader()
        out = tmp_path / "out.pcap"
        events = [
            NetworkEvent(
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                source_ip="10.0.0.5", destination_ip="93.184.216.34",
                source_port=50000, destination_port=80,
                protocol=Protocol.HTTP, event_type=EventType.HTTP_REQUEST,
                payload_size=30, raw_data=b"GET /test HTTP/1.1\r\nHost: x\r\n\r\n",
            )
        ]
        reader.write(str(out), events)
        assert out.exists()
        parsed = reader.read(str(out))
        assert len(parsed) == 1
        e = parsed[0]
        assert e.source_ip == "10.0.0.5"
        assert e.destination_ip == "93.184.216.34"
        assert e.destination_port == 80
        assert e.event_type == EventType.HTTP_REQUEST