"""Zeek log importer — reads Zeek (Bro) TSV logs and converts to NetworkEvents."""

from __future__ import annotations

import csv as _csv
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity


class ZeekImporter:
    """Imports Zeek logs (conn.log, dns.log, http.log, ssl.log, ssh.log)."""

    SUPPORTED_LOGS = {
        "conn.log", "dns.log", "http.log", "ssl.log", "ssh.log", "smb.log",
        "weird.log", "notice.log",
    }

    def read(self, path: str | Path) -> list[NetworkEvent]:
        """Read a Zeek log file and return a list of NetworkEvents."""
        log_name = Path(path).name
        if log_name not in self.SUPPORTED_LOGS:
            log_name = self._detect_log_type(path)
        return self._parse_log(path, log_name)

    def _detect_log_type(self, path: str | Path) -> str:
        try:
            lines = Path(path).read_text().splitlines()
            for line in lines[:50]:
                if line.startswith("#separator" ):
                    separator = line.split("\x09")[1].replace("\\x09", "\t") if "\x09" in line else "\t"
                    break
            for line in lines[:50]:
                if "#fields" in line:
                    fields = line.split()[2:]
                    if "orig_ip" in fields and "resp_ip" in fields:
                        return "conn.log"
                    if "query" in fields and "answer" in fields:
                        return "dns.log"
                    if "host" in fields and "uri" in fields:
                        return "http.log"
                    if "server_name" in fields:
                        return "ssl.log"
                    if "auth_success" in fields:
                        return "ssh.log"
        except Exception:
            pass
        return "conn.log"

    def _parse_log(self, path: str | Path, log_type: str) -> list[NetworkEvent]:
        content = Path(path).read_text(errors="replace")
        separator = "\t"
        fields: list[str] = []
        lines = content.splitlines()
        parser_lines = []
        for line in lines:
            if line.startswith("#separator"):
                sep_part = line.split()[1] if len(line.split()) > 1 else "\\x09"
                separator = sep_part.replace("\\x09", "\t").replace("\\x1c", chr(0x1c))
            elif line.startswith("#fields"):
                parts = line.replace("#fields", "").strip().split(separator)
                fields = [p.strip() for p in parts if p.strip()]
            elif line.startswith("#"):
                continue

        events = []
        for line in lines:
            if line.startswith("#"):
                continue
            if not line.strip():
                continue
            values = line.split(separator)
            if len(values) != len(fields):
                continue
            row = dict(zip(fields, values))
            event = self._convert_row(row, log_type)
            if event:
                events.append(event)
        return events

    def _convert_row(self, row: dict[str, str], log_type: str) -> NetworkEvent | None:
        if log_type == "conn.log":
            return self._parse_conn(row)
        if log_type == "dns.log":
            return self._parse_dns(row)
        if log_type == "http.log":
            return self._parse_http(row)
        if log_type == "ssl.log":
            return self._parse_ssl(row)
        if log_type == "ssh.log":
            return self._parse_ssh(row)
        if log_type == "smb.log":
            return self._parse_smb(row)
        return None

    def _parse_conn(self, row: dict[str, str]) -> NetworkEvent | None:
        try:
            ts = self._parse_ts(row.get("ts", "0"))
            src = row.get("id.orig_h", "0.0.0.0")
            dst = row.get("id.resp_h", "0.0.0.0")
            sport = int(row.get("id.orig_p", 0))
            dport = int(row.get("id.resp_p", 0))
            proto = row.get("proto", "tcp").lower()
            protocol = self._protocol_from_str(proto)
            orig_bytes = int(row.get("orig_bytes", 0) or 0)
            resp_bytes = int(row.get("resp_bytes", 0) or 0)
            payload_size = orig_bytes + resp_bytes
            state = row.get("conn_state", "")
            severity = Severity.INFORMATIONAL
            if row.get("history", "").count("s") >= 3:
                event_type = EventType.PORT_SCAN
                severity = Severity.MEDIUM
            elif state == "REJ":
                event_type = EventType.CONNECTION
                severity = Severity.LOW
            else:
                event_type = EventType.CONNECTION
            metadata = {
                "conn_state": state,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "duration": float(row.get("duration", 0) or 0),
                "service": row.get("service", ""),
            }
            return NetworkEvent(
                timestamp=ts, source_ip=src, destination_ip=dst,
                source_port=sport, destination_port=dport,
                protocol=protocol, event_type=event_type, severity=severity,
                payload_size=payload_size, metadata=metadata,
            )
        except (ValueError, TypeError):
            return None

    def _parse_dns(self, row: dict[str, str]) -> NetworkEvent | None:
        try:
            ts = self._parse_ts(row.get("ts", "0"))
            src = row.get("id.orig_h", "0.0.0.0")
            dst = row.get("id.resp_h", "0.0.0.0")
            query = row.get("query", "")
            answers = row.get("answers", "")
            qtype = row.get("qtype_name", row.get("qtype", ""))
            event_type = EventType.DNS_RESPONSE if answers else EventType.DNS_QUERY
            rcode = row.get("rcode_name", "")
            metadata = {
                "query_name": query,
                "qtype": qtype,
                "rcode": rcode,
                "answers": [{"type": qtype, "name": a} for a in answers.split(",") if a],
            }
            return NetworkEvent(
                timestamp=ts, source_ip=src, destination_ip=dst,
                source_port=int(row.get("id.orig_p", 0) or 0),
                destination_port=int(row.get("id.resp_p", 0) or 0),
                protocol=Protocol.DNS, event_type=event_type,
                severity=Severity.INFORMATIONAL,
                payload_size=len(query) + len(answers), metadata=metadata,
            )
        except (ValueError, TypeError):
            return None

    def _parse_http(self, row: dict[str, str]) -> NetworkEvent | None:
        try:
            ts = self._parse_ts(row.get("ts", "0"))
            src = row.get("id.orig_h", "0.0.0.0")
            dst = row.get("id.resp_h", "0.0.0.0")
            method = row.get("method", "")
            host = row.get("host", "")
            uri = row.get("uri", "")
            status = row.get("status_code", "")
            resp_body_size = int(row.get("response_body_len", 0) or 0)
            event_type = EventType.HTTP_REQUEST if method else EventType.HTTP_RESPONSE
            severity = Severity.INFORMATIONAL
            if resp_body_size > 100000:
                severity = Severity.MEDIUM
            metadata = {
                "method": method,
                "host": host,
                "uri": uri,
                "status_code": status,
                "user_agent": row.get("user_agent", ""),
                "referrer": row.get("referrer", ""),
            }
            return NetworkEvent(
                timestamp=ts, source_ip=src, destination_ip=dst,
                source_port=int(row.get("id.orig_p", 0) or 0),
                destination_port=int(row.get("id.resp_p", 0) or 0),
                protocol=Protocol.HTTP, event_type=event_type, severity=severity,
                payload_size=len(uri) + resp_body_size, metadata=metadata,
            )
        except (ValueError, TypeError):
            return None

    def _parse_ssl(self, row: dict[str, str]) -> NetworkEvent | None:
        try:
            ts = self._parse_ts(row.get("ts", "0"))
            src = row.get("id.orig_h", "0.0.0.0")
            dst = row.get("id.resp_h", "0.0.0.0")
            server_name = row.get("server_name", "")
            version = row.get("version", "")
            cipher = row.get("cipher", "")
            established = row.get("established", "") == "T"
            event_type = EventType.TLS_HANDSHAKE
            metadata = {
                "server_name": server_name,
                "version": version,
                "cipher": cipher,
                "established": established,
            }
            return NetworkEvent(
                timestamp=ts, source_ip=src, destination_ip=dst,
                source_port=int(row.get("id.orig_p", 0) or 0),
                destination_port=int(row.get("id.resp_p", 0) or 0),
                protocol=Protocol.HTTPS, event_type=event_type,
                severity=Severity.INFORMATIONAL,
                payload_size=len(server_name) + len(cipher), metadata=metadata,
            )
        except (ValueError, TypeError):
            return None

    def _parse_ssh(self, row: dict[str, str]) -> NetworkEvent | None:
        try:
            ts = self._parse_ts(row.get("ts", "0"))
            src = row.get("id.orig_h", "0.0.0.0")
            dst = row.get("id.resp_h", "0.0.0.0")
            version = row.get("version", "")
            auth_success = row.get("auth_success", "")
            auth_attempts = int(row.get("auth_attempts", 0) or 0)
            if auth_success == "T":
                event_type = EventType.SSH_AUTH
                severity = Severity.INFORMATIONAL
            elif auth_attempts >= 3:
                event_type = EventType.AUTH_FAILURE
                severity = Severity.MEDIUM
            else:
                event_type = EventType.SSH_AUTH
                severity = Severity.INFORMATIONAL
            if auth_attempts > 10:
                severity = Severity.HIGH
            metadata = {
                "version": version,
                "auth_success": auth_success,
                "auth_attempts": auth_attempts,
                "client": row.get("client", ""),
            }
            return NetworkEvent(
                timestamp=ts, source_ip=src, destination_ip=dst,
                source_port=int(row.get("id.orig_p", 0) or 0),
                destination_port=int(row.get("id.resp_p", 0) or 0),
                protocol=Protocol.SSH, event_type=event_type, severity=severity,
                payload_size=len(version) + len(row.get("client", "")), metadata=metadata,
            )
        except (ValueError, TypeError):
            return None

    def _parse_smb(self, row: dict[str, str]) -> NetworkEvent | None:
        try:
            ts = self._parse_ts(row.get("ts", "0"))
            src = row.get("id.orig_h", "0.0.0.0")
            dst = row.get("id.resp_h", "0.0.0.0")
            command = row.get("command", "")
            filename = row.get("filename", "")
            event_type = EventType.SMB_CONNECT if command == "SMB2_CONNECT" else EventType.SMB_TRANSACTION
            metadata = {
                "command": command,
                "filename": filename,
                "path": row.get("path", ""),
            }
            return NetworkEvent(
                timestamp=ts, source_ip=src, destination_ip=dst,
                source_port=int(row.get("id.orig_p", 0) or 0),
                destination_port=int(row.get("id.resp_p", 0) or 0),
                protocol=Protocol.SMB, event_type=event_type,
                severity=Severity.INFORMATIONAL,
                payload_size=len(command) + len(filename), metadata=metadata,
            )
        except (ValueError, TypeError):
            return None

    def _parse_ts(self, ts_str: str) -> datetime:
        try:
            return datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
        except ValueError:
            try:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                return datetime(1970, 1, 1, tzinfo=timezone.utc)

    def _protocol_from_str(self, proto: str) -> Protocol:
        proto = proto.lower()
        mapping = {
            "tcp": Protocol.TCP,
            "udp": Protocol.UDP,
            "icmp": Protocol.ICMP,
            "dns": Protocol.DNS,
            "http": Protocol.HTTP,
            "https": Protocol.HTTPS,
            "ssh": Protocol.SSH,
            "smb": Protocol.SMB,
        }
        return mapping.get(proto, Protocol.UNKNOWN)