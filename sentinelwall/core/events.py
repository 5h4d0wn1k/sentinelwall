"""Network event model — the fundamental unit of analysis in SentinelWall."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any


class Protocol(Enum):
    """Supported network protocols."""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    SSH = "ssh"
    SMB = "smb"
    ICMP = "icmp"
    TCP = "tcp"
    UDP = "udp"
    DHCP = "dhcp"
    NTP = "ntp"
    SMTP = "smtp"
    FTP = "ftp"
    RDP = "rdp"
    VNC = "vnc"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    UNKNOWN = "unknown"


class EventType(Enum):
    """Classification of network events."""
    CONNECTION = auto()
    DNS_QUERY = auto()
    DNS_RESPONSE = auto()
    HTTP_REQUEST = auto()
    HTTP_RESPONSE = auto()
    TLS_HANDSHAKE = auto()
    TLS_CERTIFICATE = auto()
    SSH_HANDSHAKE = auto()
    SSH_AUTH = auto()
    SMB_TRANSACTION = auto()
    SMB_CONNECT = auto()
    ICMP_ECHO = auto()
    ICMP_UNREACHABLE = auto()
    PORT_SCAN = auto()
    DATA_TRANSFER = auto()
    ENCRYPTED_TRANSFER = auto()
    AUTH_FAILURE = auto()
    AUTH_SUCCESS = auto()
    ANOMALOUS_TRAFFIC = auto()
    SUSPICIOUS_DNS = auto()
    C2_BEACON = auto()
    EXFILTRATION = auto()
    LATERAL_MOVEMENT = auto()
    PERSISTENCE = auto()
    PRIVILEGE_ESCALATION = auto()
    DEFENSE_EVASION = auto()
    COLLECTION = auto()
    IMPACT = auto()
    RESOURCE_HARVESTING = auto()
    UNKNOWN = auto()


class Severity(Enum):
    """Threat severity levels (NIST-aligned)."""
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __ge__(self, other: Severity) -> bool:
        return self.value >= other.value

    def __gt__(self, other: Severity) -> bool:
        return self.value > other.value

    def __le__(self, other: Severity) -> bool:
        return self.value <= other.value

    def __lt__(self, other: Severity) -> bool:
        return self.value < other.value


@dataclass
class NetworkEvent:
    """A single observed network event with full metadata.

    This is the atomic unit that flows through the entire detection pipeline:
    capture → enrichment → detection → correlation → narrative → export.
    """
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: Protocol
    event_type: EventType
    severity: Severity = Severity.INFORMATIONAL
    payload_size: int = 0
    payload_preview: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    parent_id: str | None = None
    tags: list[str] = field(default_factory=list)
    raw_data: bytes = b""
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if isinstance(self.protocol, str):
            self.protocol = Protocol(self.protocol)
        if isinstance(self.event_type, str):
            self.event_type = EventType[self.event_type.upper()]
        if isinstance(self.severity, str):
            self.severity = Severity[self.severity.upper()]

    @property
    def direction(self) -> str:
        """Classify traffic direction from RFC 1918 perspective."""
        return "inbound" if _is_external(self.source_ip) else "outbound"

    @property
    def hash(self) -> str:
        """Content-based hash for deduplication."""
        content = f"{self.source_ip}:{self.source_port}-{self.destination_ip}:{self.destination_port}:{self.protocol.value}:{self.event_type.name}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def is_encrypted(self) -> bool:
        return self.protocol in (Protocol.TLS, Protocol.HTTPS, Protocol.SSH)

    @property
    def lateral_movement_candidate(self) -> bool:
        internal = not _is_external(self.source_ip) and not _is_external(self.destination_ip)
        interesting_ports = {22, 23, 3389, 445, 139, 5985, 5986, 135}
        return internal and self.destination_port in interesting_ports

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol.value,
            "event_type": self.event_type.name,
            "severity": self.severity.name,
            "payload_size": self.payload_size,
            "payload_preview": self.payload_preview,
            "metadata": self.metadata,
            "parent_id": self.parent_id,
            "tags": self.tags,
            "confidence": self.confidence,
            "direction": self.direction,
            "hash": self.hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkEvent:
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            event_id=data.get("event_id", uuid.uuid4().hex[:12]),
            timestamp=ts or datetime.now(timezone.utc),
            source_ip=data.get("source_ip", "0.0.0.0"),
            destination_ip=data.get("destination_ip", "0.0.0.0"),
            source_port=data.get("source_port", 0),
            destination_port=data.get("destination_port", 0),
            protocol=Protocol(data.get("protocol", "unknown")),
            event_type=EventType[data.get("event_type", "UNKNOWN").upper()],
            severity=Severity[data.get("severity", "INFORMATIONAL").upper()],
            payload_size=data.get("payload_size", 0),
            payload_preview=data.get("payload_preview", ""),
            metadata=data.get("metadata", {}),
            parent_id=data.get("parent_id"),
            tags=data.get("tags", []),
            confidence=data.get("confidence", 1.0),
        )

    def correlate_key(self) -> str:
        """Key for grouping related events (same session/flow)."""
        src = min(self.source_ip, self.destination_ip)
        dst = max(self.source_ip, self.destination_ip)
        sport = min(self.source_port, self.destination_port)
        dport = max(self.source_port, self.destination_port)
        return f"{src}:{sport}-{dst}:{dport}:{self.protocol.value}"


def _is_external(ip: str) -> bool:
    """Check if IP is external (not RFC 1918/loopback/link-local)."""
    if ip.startswith("127.") or ip == "::1":
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return True
    if first == 10:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 192 and second == 168:
        return False
    if first == 169 and second == 254:
        return False
    return True
