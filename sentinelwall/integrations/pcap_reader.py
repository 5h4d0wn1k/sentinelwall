"""PCAP reader — parses pcap files using only Python standard library."""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity


class PcapReader:
    """Reads pcap files and converts packets to NetworkEvents.

    Uses a pure-Python parser (no external dependencies required) that
    understands the pcap global header, packet headers, Ethernet frames,
    IPv4/IPv6, TCP/UDP/ICMP, and basic application layer protocols
    (DNS, HTTP, TLS/SSH handshakes).
    """

    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101

    def read(self, path: str | Path) -> list[NetworkEvent]:
        """Read a pcap file and return a list of NetworkEvents."""
        with open(path, "rb") as f:
            data = f.read()
        return self._parse(data)

    def _parse(self, data: bytes) -> list[NetworkEvent]:
        if len(data) < 24:
            return []
        endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        magic = int.from_bytes(data[:4], "little")
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = "<"
        elif int.from_bytes(data[:4], "big") == 0xA1B2C3D4:
            endian = ">"
        elif int.from_bytes(data[:4], "big") == 0xD4C3B2A1:
            endian = ">"
        _magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            endian + "IHHiIII", data[0:24]
        )
        linktype = network
        events = []
        offset = 24
        ts_correction = getattr(self, "_ts_correction", 0)
        while offset + 16 <= len(data):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + "IIII", data[offset:offset + 16]
            )
            offset += 16
            if offset + incl_len > len(data):
                break
            packet_data = data[offset:offset + incl_len]
            offset += incl_len
            timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1e6 + ts_correction, tz=timezone.utc)
            event = self._parse_packet(packet_data, timestamp, linktype)
            if event:
                events.append(event)
        return events

    def _parse_packet(
        self, packet: bytes, timestamp: datetime, linktype: int
    ) -> NetworkEvent | None:
        if linktype == self.LINKTYPE_ETHERNET:
            if len(packet) < 14:
                return None
            eth_type = struct.unpack(">H", packet[12:14])[0]
            payload = packet[14:]
        elif linktype == self.LINKTYPE_RAW:
            if not packet:
                return None
            version = packet[0] >> 4
            if version == 4:
                eth_type = 0x0800
                payload = packet
            elif version == 6:
                eth_type = 0x86DD
                payload = packet
            else:
                return None
        else:
            return None
        if eth_type == 0x0800:
            return self._parse_ipv4(payload, timestamp)
        if eth_type == 0x86DD:
            return self._parse_ipv6(payload, timestamp)
        return None

    def _parse_ipv4(self, packet: bytes, timestamp: datetime) -> NetworkEvent | None:
        if len(packet) < 20:
            return None
        version_ihl = packet[0]
        if version_ihl >> 4 != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        protocol_id = packet[9]
        src_ip = socket.inet_ntoa(packet[12:16])
        dst_ip = socket.inet_ntoa(packet[16:20])
        if ihl > len(packet):
            return None
        payload = packet[ihl:]
        return self._parse_transport(payload, src_ip, dst_ip, protocol_id, timestamp)

    def _parse_ipv6(self, packet: bytes, timestamp: datetime) -> NetworkEvent | None:
        if len(packet) < 40:
            return None
        protocol_id = packet[6]
        src_raw = packet[8:24]
        dst_raw = packet[24:40]
        src_ip = _ipv6_to_string(src_raw)
        dst_ip = _ipv6_to_string(dst_raw)
        payload = packet[40:]
        return self._parse_transport(payload, src_ip, dst_ip, protocol_id, timestamp)

    def _parse_transport(
        self, payload: bytes, src_ip: str, dst_ip: str, protocol_id: int, timestamp: datetime
    ) -> NetworkEvent | None:
        if protocol_id == 6:  # TCP
            if len(payload) < 20:
                return None
            src_port, dst_port = struct.unpack(">HH", payload[0:4])
            offset_flags = payload[12]
            tcp_offset = ((offset_flags >> 4) & 0x0F) * 4
            app_payload = payload[tcp_offset:] if tcp_offset <= len(payload) else b""
            return self._classify_tcp(
                src_ip, dst_ip, src_port, dst_port, app_payload, payload, timestamp
            )
        elif protocol_id == 17:  # UDP
            if len(payload) < 8:
                return None
            src_port, dst_port, length = struct.unpack(">HHH", payload[0:6])
            app_payload = payload[8:] if len(payload) > 8 else b""
            return self._classify_udp(
                src_ip, dst_ip, src_port, dst_port, app_payload, timestamp
            )
        elif protocol_id == 1:  # ICMP
            return self._parse_icmp(src_ip, dst_ip, payload, timestamp)
        return None

    def _classify_tcp(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        app_payload: bytes, raw_tcp: bytes, timestamp: datetime,
    ) -> NetworkEvent:
        event_type = EventType.CONNECTION
        protocol = Protocol.TCP
        severity = Severity.INFORMATIONAL
        metadata: dict[str, Any] = {}
        flags = raw_tcp[13] if len(raw_tcp) > 13 else 0
        if dst_port == 22 or src_port == 22:
            protocol = Protocol.SSH
            event_type = EventType.SSH_HANDSHAKE
            if app_payload:
                metadata["ssh_version"] = _extract_ssh_version(app_payload)
        elif dst_port == 443 or src_port == 443:
            protocol = Protocol.HTTPS
            event_type = EventType.TLS_HANDSHAKE
            if len(app_payload) > 5 and app_payload[0] == 0x16:
                metadata["tls_record"] = "handshake"
        elif dst_port == 80 or src_port == 80:
            protocol = Protocol.HTTP
            event_type = EventType.HTTP_REQUEST
            if app_payload:
                metadata["http"] = _parse_http(app_payload)
        elif dst_port == 445 or src_port == 445 or dst_port == 139 or src_port == 139:
            protocol = Protocol.SMB
            event_type = EventType.SMB_CONNECT if (flags & 0x02) else EventType.SMB_TRANSACTION
        elif dst_port == 3389 or src_port == 3389:
            protocol = Protocol.RDP
            event_type = EventType.CONNECTION
        elif dst_port == 5900 or src_port == 5900:
            protocol = Protocol.VNC
            event_type = EventType.CONNECTION
        elif dst_port == 25 or src_port == 25 or dst_port == 587 or src_port == 587:
            protocol = Protocol.SMTP
            event_type = EventType.CONNECTION
        elif dst_port == 21 or src_port == 21:
            protocol = Protocol.FTP
            event_type = EventType.CONNECTION
        elif dst_port == 389 or src_port == 389:
            protocol = Protocol.LDAP
            event_type = EventType.CONNECTION
        elif dst_port == 88 or src_port == 88:
            protocol = Protocol.KERBEROS
            event_type = EventType.CONNECTION
        if len(app_payload) > 10000:
            event_type = EventType.DATA_TRANSFER
            severity = Severity.MEDIUM
        if protocol in (Protocol.SSH, Protocol.HTTPS) and len(app_payload) > 10000:
            event_type = EventType.ENCRYPTED_TRANSFER
            severity = Severity.HIGH
        preview = _payload_preview(app_payload)
        return NetworkEvent(
            timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
            source_port=src_port, destination_port=dst_port,
            protocol=protocol, event_type=event_type, severity=severity,
            payload_size=len(app_payload), payload_preview=preview,
            metadata=metadata, raw_data=raw_tcp,
        )

    def _classify_udp(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        app_payload: bytes, timestamp: datetime,
    ) -> NetworkEvent:
        if dst_port == 53 or src_port == 53:
            protocol = Protocol.DNS
            event_type, metadata = _parse_dns(app_payload)
            if event_type == EventType.DNS_RESPONSE:
                severity = Severity.INFORMATIONAL
            else:
                severity = Severity.INFORMATIONAL
            return NetworkEvent(
                timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
                source_port=src_port, destination_port=dst_port,
                protocol=protocol, event_type=event_type, severity=severity,
                payload_size=len(app_payload),
                payload_preview=_payload_preview(app_payload),
                metadata=metadata, raw_data=app_payload,
            )
        elif dst_port == 123:
            protocol = Protocol.NTP
            return NetworkEvent(
                timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
                source_port=src_port, destination_port=dst_port,
                protocol=protocol, event_type=EventType.CONNECTION,
                severity=Severity.INFORMATIONAL,
                payload_size=len(app_payload),
                payload_preview=_payload_preview(app_payload),
                raw_data=app_payload,
            )
        elif dst_port == 67 or dst_port == 68:
            protocol = Protocol.DHCP
            return NetworkEvent(
                timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
                source_port=src_port, destination_port=dst_port,
                protocol=protocol, event_type=EventType.CONNECTION,
                severity=Severity.INFORMATIONAL,
                payload_size=len(app_payload),
                payload_preview=_payload_preview(app_payload),
                raw_data=app_payload,
            )
        return NetworkEvent(
            timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
            source_port=src_port, destination_port=dst_port,
            protocol=Protocol.UDP, event_type=EventType.CONNECTION,
            severity=Severity.INFORMATIONAL,
            payload_size=len(app_payload),
            payload_preview=_payload_preview(app_payload),
            raw_data=app_payload,
        )

    def _parse_icmp(
        self, src_ip: str, dst_ip: str, payload: bytes, timestamp: datetime
    ) -> NetworkEvent:
        if len(payload) < 4:
            return NetworkEvent(
                timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
                source_port=0, destination_port=0,
                protocol=Protocol.ICMP, event_type=EventType.ICMP_ECHO,
                severity=Severity.INFORMATIONAL, payload_size=len(payload),
                payload_preview=_payload_preview(payload), raw_data=payload,
            )
        icmp_type = payload[0]
        event_type = EventType.ICMP_ECHO
        severity = Severity.INFORMATIONAL
        if icmp_type == 3:
            event_type = EventType.ICMP_UNREACHABLE
        if len(payload) > 1000:
            severity = Severity.MEDIUM
        return NetworkEvent(
            timestamp=timestamp, source_ip=src_ip, destination_ip=dst_ip,
            source_port=0, destination_port=0,
            protocol=Protocol.ICMP, event_type=event_type, severity=severity,
            payload_size=len(payload), payload_preview=_payload_preview(payload),
            metadata={"icmp_type": icmp_type}, raw_data=payload,
        )

    def write(self, path: str | Path, events: list[NetworkEvent]) -> None:
        """Write events to a synthetic pcap file."""
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, self.LINKTYPE_ETHERNET))
            for i, event in enumerate(events):
                packet = self._build_packet(event)
                ts = int(event.timestamp.timestamp())
                usec = int((event.timestamp.timestamp() - ts) * 1e6)
                f.write(struct.pack("<IIII", ts, usec, len(packet), len(packet)))
                f.write(packet)

    def _build_packet(self, event: NetworkEvent) -> bytes:
        eth = struct.pack(">6s6sH", b"\x00\x11\x22\x33\x44\x55", b"\x66\x77\x88\x99\xaa\xbb", 0x0800)
        version_ihl = 0x45
        total_len = 20 + 20 + len(event.raw_data or b"payload")
        flags_frag = 0x4000
        ttl = 64
        protocol_id = 6 if event.protocol in (Protocol.TCP, Protocol.SSH, Protocol.HTTPS, Protocol.HTTP, Protocol.SMB, Protocol.RDP) else 17
        if event.protocol == Protocol.ICMP:
            protocol_id = 1
        header = struct.pack(
            ">BBHHHBBH4s4s",
            version_ihl, 0, min(total_len, 65535), 0x1234, flags_frag,
            ttl, protocol_id, 0,
            socket.inet_aton(event.source_ip) if _valid_ipv4(event.source_ip) else b"\x0a\x00\x00\x01",
            socket.inet_aton(event.destination_ip) if _valid_ipv4(event.destination_ip) else b"\x0a\x00\x00\x02",
        )
        tcp = struct.pack(">HHIIBBHHH", event.source_port, event.destination_port, 1000, 2000, 0x50, 0x18, 0, 0, 0)
        payload = event.raw_data[:1400] if event.raw_data else b"P" * min(event.payload_size, 50)
        tcp += payload
        return eth + header + tcp


def _parse_http(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return result
    lines = text.split("\r\n")
    if lines:
        parts = lines[0].split(" ")
        if len(parts) >= 3:
            if parts[0].upper().startswith(("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS")):
                result["method"] = parts[0]
                result["path"] = parts[1]
                result["version"] = parts[2]
            else:
                result["version"] = parts[0]
                result["status_code"] = parts[1] if len(parts) > 1 else ""
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            result.setdefault("headers", {})[key.strip()] = value.strip()
    return result


def _parse_dns(data: bytes) -> tuple[EventType, dict[str, Any]]:
    metadata: dict[str, Any] = {}
    if len(data) < 12:
        return EventType.DNS_QUERY, metadata
    flags = struct.unpack(">H", data[2:4])[0]
    qr = (flags >> 15) & 0x1
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    offset = 12
    query_name = ""
    try:
        query_name = _parse_dns_name(data, offset)[0]
        offset = 12 + len(_encode_dns_name(query_name)) + 4
    except Exception:
        offset = 12
    answers = []
    if qr and ancount > 0 and offset < len(data):
        try:
            for _ in range(min(ancount, 20)):
                if offset >= len(data) - 11:
                    break
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    name, consumed = _parse_dns_name(data, offset)
                    offset += consumed
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                if offset + rdlength > len(data):
                    break
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                if rtype == 1 and rdlength == 4:
                    answers.append({
                        "type": "A",
                        "ip": socket.inet_ntoa(rdata),
                    })
                elif rtype == 5:
                    try:
                        cname, _ = _parse_dns_name(data, data.index(rdata[0]) if False else offset - rdlength)
                        answers.append({"type": "CNAME", "name": cname})
                    except Exception:
                        answers.append({"type": "CNAME", "raw": rdata.hex()})
        except Exception:
            pass
    metadata["query_name"] = query_name
    metadata["qr"] = bool(qr)
    metadata["qtype"] = struct.unpack(">H", data[offset - 4:offset - 2])[0] if offset >= 4 else 0
    if answers:
        metadata["answers"] = answers
    return (EventType.DNS_RESPONSE if qr else EventType.DNS_QUERY), metadata


def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    consumed = 0
    idx = offset
    while idx < len(data):
        length = data[idx]
        if length == 0:
            idx += 1
            consumed += 1
            break
        if length & 0xC0 == 0xC0:
            idx += 2
            consumed += 2
            break
        idx += 1
        consumed += 1
        if idx + length > len(data):
            break
        labels.append(data[idx:idx + length].decode("utf-8", errors="replace"))
        idx += length
        consumed += length
        if len(labels) > 64:
            break
    return ".".join(labels), consumed


def _encode_dns_name(name: str) -> bytes:
    result = b""
    for label in name.split("."):
        lb = label.encode()
        if len(lb) < 64:
            result += bytes([len(lb)]) + lb
    return result + b"\x00"


def _extract_ssh_version(data: bytes) -> str:
    try:
        text = data.decode("utf-8", errors="replace")
        if text.startswith("SSH-"):
            return text.split("\r")[0].split("\n")[0][:40]
    except Exception:
        pass
    return ""


def _payload_preview(data: bytes, length: int = 60) -> str:
    if not data:
        return ""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return data[:length].hex()
    preview = text.replace("\r", " ").replace("\n", " ")[:length]
    try:
        return "".join(c if c.isprintable() else "." for c in preview)
    except Exception:
        return ""


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _ipv6_to_string(raw: bytes) -> str:
    groups = []
    for i in range(0, 16, 2):
        groups.append(f"{raw[i]:02x}{raw[i+1]:02x}")
    return ":".join(groups)