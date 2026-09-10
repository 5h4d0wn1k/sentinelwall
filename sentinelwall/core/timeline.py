"""Timeline analysis for temporal attack pattern detection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelwall.core.events import EventType, NetworkEvent, Severity


@dataclass
class TimelineEntry:
    """A point on the attack timeline."""
    timestamp: datetime
    event: NetworkEvent
    sequence_number: int
    gap_from_previous: timedelta
    phase: str = "unknown"


@dataclass
class AttackTimeline:
    """Ordered sequence of events forming an attack chain."""
    timeline_id: str
    entries: list[TimelineEntry] = field(default_factory=list)
    attacker_ip: str = ""
    target_ip: str = ""
    kill_chain_phases: list[str] = field(default_factory=list)
    total_duration: timedelta = field(default_factory=lambda: timedelta())
    event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeline_id": self.timeline_id,
            "attacker_ip": self.attacker_ip,
            "target_ip": self.target_ip,
            "event_count": self.event_count,
            "total_duration_seconds": self.total_duration.total_seconds(),
            "kill_chain_phases": self.kill_chain_phases,
            "entries": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "event_id": e.event.event_id,
                    "event_type": e.event.event_type.name,
                    "protocol": e.event.protocol.value,
                    "source_ip": e.event.source_ip,
                    "destination_ip": e.event.destination_ip,
                    "destination_port": e.event.destination_port,
                    "severity": e.event.severity.name,
                    "sequence_number": e.sequence_number,
                    "gap_seconds": e.gap_from_previous.total_seconds(),
                    "phase": e.phase,
                }
                for e in self.entries
            ],
        }


class TimelineAnalyzer:
    """Builds attack timelines from correlated event clusters."""

    PHASE_MAP = {
        EventType.PORT_SCAN: "reconnaissance",
        EventType.DNS_QUERY: "reconnaissance",
        EventType.SSH_HANDSHAKE: "initial-access",
        EventType.SSH_AUTH: "initial-access",
        EventType.AUTH_FAILURE: "credential-access",
        EventType.AUTH_SUCCESS: "initial-access",
        EventType.HTTP_REQUEST: "execution",
        EventType.SMB_TRANSACTION: "lateral-movement",
        EventType.SMB_CONNECT: "lateral-movement",
        EventType.DATA_TRANSFER: "exfiltration",
        EventType.ENCRYPTED_TRANSFER: "exfiltration",
        EventType.C2_BEACON: "command-and-control",
        EventType.EXFILTRATION: "exfiltration",
        EventType.LATERAL_MOVEMENT: "lateral-movement",
        EventType.PERSISTENCE: "persistence",
        EventType.PRIVILEGE_ESCALATION: "privilege-escalation",
        EventType.DEFENSE_EVASION: "defense-evasion",
        EventType.COLLECTION: "collection",
        EventType.IMPACT: "impact",
    }

    def __init__(self) -> None:
        self._timelines: list[AttackTimeline] = []

    def build_timeline(self, events: list[NetworkEvent]) -> AttackTimeline:
        """Build an attack timeline from a list of events."""
        import uuid as _uuid
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        if not sorted_events:
            return AttackTimeline(timeline_id=_uuid.uuid4().hex[:10])

        entries = []
        prev_ts = None
        for i, event in enumerate(sorted_events):
            gap = (event.timestamp - prev_ts) if prev_ts else timedelta()
            phase = self.PHASE_MAP.get(event.event_type, "unknown")
            entries.append(TimelineEntry(
                timestamp=event.timestamp,
                event=event,
                sequence_number=i + 1,
                gap_from_previous=gap,
                phase=phase,
            ))
            prev_ts = event.timestamp

        attacker = self._identify_primary_attacker(sorted_events)
        target = self._identify_primary_target(sorted_events)
        phases = list(dict.fromkeys(e.phase for e in entries if e.phase != "unknown"))
        duration = sorted_events[-1].timestamp - sorted_events[0].timestamp

        timeline = AttackTimeline(
            timeline_id=_uuid.uuid4().hex[:10],
            entries=entries,
            attacker_ip=attacker,
            target_ip=target,
            kill_chain_phases=phases,
            total_duration=duration,
            event_count=len(entries),
        )
        self._timelines.append(timeline)
        return timeline

    def get_timelines(self) -> list[AttackTimeline]:
        return list(self._timelines)

    def _identify_primary_attacker(self, events: list[NetworkEvent]) -> str:
        if not events:
            return ""
        from collections import Counter
        counter = Counter(e.source_ip for e in events)
        return counter.most_common(1)[0][0] if counter else ""

    def _identify_primary_target(self, events: list[NetworkEvent]) -> str:
        if not events:
            return ""
        from collections import Counter
        counter = Counter(e.destination_ip for e in events)
        return counter.most_common(1)[0][0] if counter else ""
