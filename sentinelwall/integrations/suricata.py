"""Suricata/Snort log importer — reads EVE-JSON and unified2 alert logs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity


class SuricataImporter:
    """Imports Suricata eve.json and Snort alerts as NetworkEvents.

    Handles:
    - Suricata EVE-JSON format (alert events)
    - Snort-style flow events
    - Suricata DNS, HTTP transactions
    """

    SEVERITY_MAP = {
        1: Severity.CRITICAL,
        2: Severity.HIGH,
        3: Severity.MEDIUM,
        4: Severity.LOW,
    }

    def read(self, path: str | Path) -> list[NetworkEvent]:
        """Read an eve.json file. Returns list of NetworkEvents."""
        events = []
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = self._convert_record(record)
                if event:
                    events.append(event)
        return events

    def _convert_record(self, record: dict[str, Any]) -> NetworkEvent | None:
        event_type = record.get("event_type", "")
        if event_type == "alert":
            return self._parse_alert(record)
        if event_type == "dns":
            return self._parse_dns(record)
        if event_type == "http":
            return self._parse_http(record)
        if event_type == "tls":
            return self._parse_tls(record)
        if event_type == "flow":
            return self._parse_flow(record)
        if event_type == "ssh":
            return self._parse_ssh(record)
        return None

    def _parse_alert(self, record: dict[str, Any]) -> NetworkEvent | None:
        flow = record.get("flow", {})
        src = flow.get("src_ip") or record.get("src_ip", "0.0.0.0")
        dst = flow.get("dest_ip") or record.get("dest_ip", "0.0.0.0")
        sport = int(flow.get("src_port", record.get("src_port", 0)))
        dport = int(flow.get("dest_port", record.get("dest_port", 0)))
        proto = (flow.get("proto") or record.get("proto", "tcp")).lower()
        alert = record.get("alert", {})
        severity_num = alert.get("severity", 3)
        severity = self.SEVERITY_MAP.get(severity_num, Severity.MEDIUM)
        metadata = {
            "signature": alert.get("signature", ""),
            "signature_id": alert.get("signature_id", 0),
            "rev": alert.get("rev", 0),
            "category": alert.get("category", ""),
            "rule_source": "suricata",
        }
        event_type = EventType.ANOMALOUS_TRAFFIC
        signature = alert.get("signature", "").lower()
        if "port scan" in signature or "portscan" in signature:
            event_type = EventType.PORT_SCAN
        elif "dns query" in signature or "dns" in signature:
            event_type = EventType.SUSPICIOUS_DNS
        elif "beacon" in signature or "c2" in signature:
            event_type = EventType.C2_BEACON
        elif "exfil" in signature:
            event_type = EventType.EXFILTRATION
        elif "lateral" in signature:
            event_type = EventType.LATERAL_MOVEMENT
        return NetworkEvent(
            timestamp=self._parse_timestamp(record.get("timestamp", "")),
            source_ip=src, destination_ip=dst,
            source_port=sport, destination_port=dport,
            protocol=self._protocol_from_str(proto),
            event_type=event_type, severity=severity,
            payload_size=record.get("bytes", 0) or 0,
            metadata=metadata,
        )

    def _parse_dns(self, record: dict[str, Any]) -> NetworkEvent | None:
        dns = record.get("dns", {})
        rrtype = dns.get("rrtype", "")
        query = dns.get("query", "")
        type_name = dns.get("type", "query")
        event_type = EventType.DNS_RESPONSE if type_name == "answer" else EventType.DNS_QUERY
        return NetworkEvent(
            timestamp=self._parse_timestamp(record.get("timestamp", "")),
            source_ip=record.get("src_ip", "0.0.0.0"),
            destination_ip=record.get("dest_ip", "0.0.0.0"),
            source_port=int(record.get("src_port", 0)),
            destination_port=int(record.get("dest_port", 0)),
            protocol=Protocol.DNS, event_type=event_type,
            severity=Severity.INFORMATIONAL,
            payload_size=len(query) + len(rrtype),
            metadata={
                "query_name": query,
                "rrtype": rrtype,
                "dns_type": type_name,
                "answers": dns.get("answers", []),
            },
        )

    def _parse_http(self, record: dict[str, Any]) -> NetworkEvent | None:
        http = record.get("http", {})
        host = http.get("hostname", "")
        uri = http.get("url", "")
        method = http.get("http_method", "")
        status = http.get("status", 0)
        event_type = EventType.HTTP_REQUEST if method else EventType.HTTP_RESPONSE
        return NetworkEvent(
            timestamp=self._parse_timestamp(record.get("timestamp", "")),
            source_ip=record.get("src_ip", "0.0.0.0"),
            destination_ip=record.get("dest_ip", "0.0.0.0"),
            source_port=int(record.get("src_port", 0)),
            destination_port=int(record.get("dest_port", 0)),
            protocol=Protocol.HTTP, event_type=event_type,
            severity=Severity.INFORMATIONAL,
            payload_size=len(uri) + int(http.get("length", 0)),
            metadata={
                "method": method, "host": host, "uri": uri,
                "status_code": status, "user_agent": http.get("http_user_agent", ""),
            },
        )

    def _parse_tls(self, record: dict[str, Any]) -> NetworkEvent | None:
        tls = record.get("tls", {})
        return NetworkEvent(
            timestamp=self._parse_timestamp(record.get("timestamp", "")),
            source_ip=record.get("src_ip", "0.0.0.0"),
            destination_ip=record.get("dest_ip", "0.0.0.0"),
            source_port=int(record.get("src_port", 0)),
            destination_port=int(record.get("dest_port", 0)),
            protocol=Protocol.HTTPS, event_type=EventType.TLS_HANDSHAKE,
            severity=Severity.INFORMATIONAL,
            payload_size=len(tls.get("sni", "")),
            metadata={
                "server_name": tls.get("sni", ""),
                "version": tls.get("version", ""),
                "ja3": tls.get("ja3", {}),
            },
        )

    def _parse_flow(self, record: dict[str, Any]) -> NetworkEvent | None:
        flow = record.get("flow", {})
        bytes_toserver = int(flow.get("bytes_toserver", 0) or 0)
        bytes_toclient = int(flow.get("bytes_toclient", 0) or 0)
        payload_size = bytes_toserver + bytes_toclient
        event_type = EventType.DATA_TRANSFER if payload_size > 10000 else EventType.CONNECTION
        severity = Severity.MEDIUM if payload_size > 100000 else Severity.INFORMATIONAL
        return NetworkEvent(
            timestamp=self._parse_timestamp(record.get("timestamp", "")),
            source_ip=record.get("src_ip", "0.0.0.0"),
            destination_ip=record.get("dest_ip", "0.0.0.0"),
            source_port=int(record.get("src_port", 0)),
            destination_port=int(record.get("dest_port", 0)),
            protocol=self._protocol_from_str(record.get("proto", "tcp")),
            event_type=event_type, severity=severity, payload_size=payload_size,
            metadata={
                "bytes_toserver": bytes_toserver,
                "bytes_toclient": bytes_toclient,
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
            },
        )

    def _parse_ssh(self, record: dict[str, Any]) -> NetworkEvent | None:
        ssh = record.get("ssh", {})
        auth_success = ssh.get("auth_success", "failed")
        event_type = EventType.SSH_AUTH if auth_success == "success" else EventType.AUTH_FAILURE
        severity = Severity.INFORMATIONAL if auth_success == "success" else Severity.MEDIUM
        return NetworkEvent(
            timestamp=self._parse_timestamp(record.get("timestamp", "")),
            source_ip=record.get("src_ip", "0.0.0.0"),
            destination_ip=record.get("dest_ip", "0.0.0.0"),
            source_port=int(record.get("src_port", 0)),
            destination_port=int(record.get("dest_port", 0)),
            protocol=Protocol.SSH, event_type=event_type, severity=severity,
            payload_size=len(ssh.get("client_software_version", "")),
            metadata={
                "auth_success": auth_success,
                "server_version": ssh.get("server_software_version", ""),
                "client_version": ssh.get("client_software_version", ""),
            },
        )

    def _parse_timestamp(self, ts: str) -> datetime:
        if not ts:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    def _protocol_from_str(self, proto: str) -> Protocol:
        proto = proto.lower()
        mapping = {
            "tcp": Protocol.TCP, "udp": Protocol.UDP, "icmp": Protocol.ICMP,
            "dns": Protocol.DNS, "http": Protocol.HTTP,
            "https": Protocol.HTTPS, "ssh": Protocol.SSH, "smb": Protocol.SMB,
        }
        return mapping.get(proto, Protocol.UNKNOWN)