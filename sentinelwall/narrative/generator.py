"""Threat narrative generator — creates human-readable attack stories."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity
from sentinelwall.core.timeline import AttackTimeline
from sentinelwall.mitre.techniques import MITRE_TECHNIQUES


@dataclass
class NarrativeSegment:
    """A single segment of a threat narrative."""
    phase: str
    title: str
    body: str
    events: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFORMATIONAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "title": self.title,
            "body": self.body,
            "events": self.events,
            "techniques": self.techniques,
            "severity": self.severity.name,
        }


@dataclass
class ThreatNarrative:
    """A complete threat narrative with summary and segments."""
    title: str
    summary: str
    severity: Severity
    confidence: float
    attacker_ip: str
    target_ip: str
    segments: list[NarrativeSegment] = field(default_factory=list)
    techniques_used: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    mitre_kill_chain: list[dict[str, str]] = field(default_factory=list)
    total_events: int = 0
    time_range: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity.name,
            "confidence": self.confidence,
            "attacker_ip": self.attacker_ip,
            "target_ip": self.target_ip,
            "segments": [s.to_dict() for s in self.segments],
            "techniques_used": self.techniques_used,
            "recommended_actions": self.recommended_actions,
            "mitre_kill_chain": self.mitre_kill_chain,
            "total_events": self.total_events,
            "time_range": self.time_range,
        }

    def to_text(self) -> str:
        lines = [
            f"# {self.title}",
            "",
            f"**Severity:** {self.severity.name}  ",
            f"**Confidence:** {self.confidence:.0%}  ",
            f"**Attacker:** {self.attacker_ip}  ",
            f"**Target:** {self.target_ip}  ",
            f"**Events Analyzed:** {self.total_events}  ",
            f"**Time Range:** {self.time_range}",
            "",
            "## Summary",
            self.summary,
            "",
        ]
        if self.segments:
            lines.append("## Attack Chain")
            lines.append("")
            for i, seg in enumerate(self.segments, 1):
                lines.append(f"### Phase {i}: {seg.title}")
                lines.append(f"*{seg.phase}* | Severity: {seg.severity.name}")
                lines.append("")
                lines.append(seg.body)
                lines.append("")
                if seg.techniques:
                    lines.append(f"**Techniques:** {', '.join(seg.techniques)}")
                    lines.append("")
        if self.recommended_actions:
            lines.append("## Recommended Actions")
            lines.append("")
            for action in self.recommended_actions:
                lines.append(f"- {action}")
            lines.append("")
        if self.mitre_kill_chain:
            lines.append("## MITRE ATT&CK Kill Chain")
            lines.append("")
            for phase in self.mitre_kill_chain:
                lines.append(f"- **{phase['tactic']}**: {', '.join(phase['techniques'])}")
            lines.append("")
        return "\n".join(lines)


class NarrativeGenerator:
    """Generates human-readable threat narratives from correlated events.

    The narrative engine transforms raw correlated events into coherent
    threat stories that answer:
    - WHO is attacking?
    - WHAT did they do (step by step)?
    - WHY are they doing it (likely goal)?
    - HOW should we respond?
    """

    KILL_CHAIN_TACTICS = {
        "reconnaissance": "Reconnaissance",
        "resource-development": "Resource Development",
        "initial-access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "defense-evasion": "Defense Evasion",
        "credential-access": "Credential Access",
        "discovery": "Discovery",
        "lateral-movement": "Lateral Movement",
        "collection": "Collection",
        "command-and-control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }

    SEVERITY_RESPONSES = {
        Severity.CRITICAL: [
            "Isolate the affected systems from the network immediately",
            "Engage incident response team",
            "Preserve forensic evidence (memory dumps, disk images)",
            "Check for lateral movement to other systems",
            "Review and rotate all credentials for affected accounts",
            "Block identified IOCs at network perimeter",
        ],
        Severity.HIGH: [
            "Investigate the source IP and block if confirmed malicious",
            "Review authentication logs for compromised accounts",
            "Check for persistence mechanisms on affected systems",
            "Update IDS/IPS signatures based on observed patterns",
            "Monitor for follow-up activity from the same source",
        ],
        Severity.MEDIUM: [
            "Monitor the involved hosts for escalation",
            "Review firewall rules for the affected ports",
            "Check if the traffic pattern is expected for the environment",
            "Consider adding the source to a watch list",
        ],
        Severity.LOW: [
            "Log for future correlation",
            "Verify this is expected traffic",
            "No immediate action required",
        ],
    }

    def __init__(self) -> None:
        self._narratives: list[ThreatNarrative] = []

    def generate(
        self,
        events: list[NetworkEvent],
        clusters: list[CorrelatedCluster],
        timelines: list[AttackTimeline] | None = None,
    ) -> str:
        """Generate a complete threat narrative report."""
        narrative = self._build_narrative(events, clusters, timelines)
        self._narratives.append(narrative)
        return narrative.to_text()

    def generate_json(
        self,
        events: list[NetworkEvent],
        clusters: list[CorrelatedCluster],
        timelines: list[AttackTimeline] | None = None,
    ) -> dict[str, Any]:
        narrative = self._build_narrative(events, clusters, timelines)
        return narrative.to_dict()

    def get_narratives(self) -> list[ThreatNarrative]:
        return list(self._narratives)

    def _build_narrative(
        self,
        events: list[NetworkEvent],
        clusters: list[CorrelatedCluster],
        timelines: list[AttackTimeline] | None,
    ) -> ThreatNarrative:
        if not events and not clusters:
            return ThreatNarrative(
                title="No Threats Detected",
                summary="No suspicious activity was observed during the analysis period.",
                severity=Severity.INFORMATIONAL,
                confidence=1.0,
                attacker_ip="",
                target_ip="",
            )
        max_severity = max(
            (c.severity for c in clusters),
            default=Severity.INFORMATIONAL,
            key=lambda s: s.value,
        )
        all_techniques = list({t for c in clusters for t in c.techniques})
        attacker = self._identify_attacker(events, clusters)
        target = self._identify_target(events, clusters)
        segments = self._build_segments(clusters, events)
        kill_chain = self._build_kill_chain(all_techniques)
        title = self._generate_title(clusters, max_severity, attacker, target)
        summary = self._generate_summary(clusters, events, attacker, target, max_severity)
        actions = self._generate_actions(max_severity, all_techniques, clusters)
        confidence = sum(c.confidence for c in clusters) / len(clusters) if clusters else 0
        time_range = self._format_time_range(events)
        return ThreatNarrative(
            title=title,
            summary=summary,
            severity=max_severity,
            confidence=confidence,
            attacker_ip=attacker,
            target_ip=target,
            segments=segments,
            techniques_used=all_techniques,
            recommended_actions=actions,
            mitre_kill_chain=kill_chain,
            total_events=len(events),
            time_range=time_range,
        )

    def _generate_title(
        self,
        clusters: list[CorrelatedCluster],
        severity: Severity,
        attacker: str,
        target: str,
    ) -> str:
        if not clusters:
            return "Network Analysis Report"
        primary_labels = set()
        for c in clusters:
            primary_labels.update(c.labels)
        label_str = ", ".join(sorted(primary_labels)[:3])
        if severity == Severity.CRITICAL:
            return f"CRITICAL: Multi-stage attack from {attacker} targeting {target} ({label_str})"
        if severity == Severity.HIGH:
            return f"HIGH: Suspicious activity from {attacker} ({label_str})"
        if severity == Severity.MEDIUM:
            return f"MEDIUM: Anomalous behavior detected ({label_str})"
        return f"LOW: Informational events ({label_str})"

    def _generate_summary(
        self,
        clusters: list[CorrelatedCluster],
        events: list[NetworkEvent],
        attacker: str,
        target: str,
        severity: Severity,
    ) -> str:
        if not clusters:
            return "No correlated threat activity was detected."
        parts = []
        parts.append(
            f"Analysis of {len(events)} network events identified {len(clusters)} "
            f"threat cluster(s) with a maximum severity of {severity.name}."
        )
        if attacker:
            parts.append(
                f"The primary source of suspicious activity is {attacker}."
            )
        if target:
            parts.append(
                f"The primary target appears to be {target}."
            )
        all_techniques = set()
        for c in clusters:
            all_techniques.update(c.techniques)
        if all_techniques:
            tech_list = ", ".join(sorted(all_techniques)[:5])
            parts.append(f"MITRE ATT&CK techniques identified: {tech_list}.")
        label_counts = defaultdict(int)
        for c in clusters:
            for label in c.labels:
                label_counts[label] += 1
        if label_counts:
            top_labels = sorted(label_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            label_str = ", ".join(f"{l} ({n})" for l, n in top_labels)
            parts.append(f"Primary threat categories: {label_str}.")
        if severity.value >= Severity.HIGH.value:
            parts.append(
                "Immediate investigation and response is recommended."
            )
        return " ".join(parts)

    def _build_segments(
        self,
        clusters: list[CorrelatedCluster],
        events: list[NetworkEvent],
    ) -> list[NarrativeSegment]:
        segments = []
        phase_events = defaultdict(list)
        for event in events:
            phase = self._event_to_phase(event)
            phase_events[phase].append(event)
        for cluster in clusters:
            for label in cluster.labels:
                phase = self._label_to_phase(label)
                segment = self._create_segment(phase, cluster, phase_events.get(phase, []))
                if segment:
                    segments.append(segment)
        if not segments and events:
            segment = NarrativeSegment(
                phase="analysis",
                title="Network Activity Observed",
                body=self._describe_generic_activity(events),
                events=[e.event_id for e in events[:10]],
                techniques=[],
                severity=max((e.severity for e in events), default=Severity.INFORMATIONAL, key=lambda s: s.value),
            )
            segments.append(segment)
        return segments

    def _create_segment(
        self,
        phase: str,
        cluster: CorrelatedCluster,
        phase_events: list[NetworkEvent],
    ) -> NarrativeSegment | None:
        body = cluster.chain_description
        if not body:
            body = self._describe_cluster(cluster)
        return NarrativeSegment(
            phase=phase,
            title=self._phase_title(phase),
            body=body,
            events=[e.event_id for e in cluster.events[:5]],
            techniques=cluster.techniques,
            severity=cluster.severity,
        )

    def _describe_cluster(self, cluster: CorrelatedCluster) -> str:
        hosts = list(cluster.involved_hosts)
        parts = [f"Detected {cluster.event_count} events"]
        if len(hosts) >= 2:
            parts[0] += f" between {hosts[0]} and {hosts[1]}"
        parts[0] += f" over {cluster.duration.total_seconds():.0f} seconds."
        if cluster.techniques:
            tech_names = []
            for tid in cluster.techniques:
                info = MITRE_TECHNIQUES.get(tid)
                tech_names.append(f"{tid} ({info.name})" if info else tid)
            parts.append(f"Techniques: {', '.join(tech_names[:3])}.")
        return " ".join(parts)

    def _describe_generic_activity(self, events: list[NetworkEvent]) -> str:
        protocols = set(e.protocol.value for e in events)
        ports = set(e.destination_port for e in events)
        return (
            f"Observed {len(events)} events using protocols: {', '.join(sorted(protocols))}. "
            f"Targeted ports: {', '.join(str(p) for p in sorted(ports)[:10])}. "
            f"No specific threat pattern was identified, but activity has been logged for correlation."
        )

    def _event_to_phase(self, event: NetworkEvent) -> str:
        mapping = {
            EventType.PORT_SCAN: "discovery",
            EventType.DNS_QUERY: "reconnaissance",
            EventType.DNS_RESPONSE: "reconnaissance",
            EventType.SSH_HANDSHAKE: "initial-access",
            EventType.SSH_AUTH: "credential-access",
            EventType.HTTP_REQUEST: "execution",
            EventType.SMB_TRANSACTION: "lateral-movement",
            EventType.SMB_CONNECT: "lateral-movement",
            EventType.AUTH_FAILURE: "credential-access",
            EventType.AUTH_SUCCESS: "initial-access",
            EventType.DATA_TRANSFER: "exfiltration",
            EventType.ENCRYPTED_TRANSFER: "exfiltration",
            EventType.C2_BEACON: "command-and-control",
            EventType.EXFILTRATION: "exfiltration",
            EventType.LATERAL_MOVEMENT: "lateral-movement",
            EventType.PERSISTENCE: "persistence",
            EventType.ICMP_ECHO: "discovery",
        }
        return mapping.get(event.event_type, "analysis")

    def _label_to_phase(self, label: str) -> str:
        mapping = {
            "port-scan": "discovery",
            "c2-beacon": "command-and-control",
            "lateral-movement": "lateral-movement",
            "exfiltration": "exfiltration",
            "dns-tunneling": "command-and-control",
            "brute-force": "credential-access",
            "protocol-anomaly": "defense-evasion",
            "covert-channel": "command-and-control",
        }
        return mapping.get(label, "analysis")

    def _phase_title(self, phase: str) -> str:
        titles = {
            "reconnaissance": "Network Reconnaissance",
            "discovery": "System Discovery",
            "initial-access": "Initial Access Attempt",
            "execution": "Code Execution",
            "persistence": "Persistence Mechanism",
            "privilege-escalation": "Privilege Escalation",
            "defense-evasion": "Defense Evasion",
            "credential-access": "Credential Attack",
            "lateral-movement": "Lateral Movement",
            "collection": "Data Collection",
            "command-and-control": "Command & Control",
            "exfiltration": "Data Exfiltration",
            "impact": "Impact",
            "analysis": "General Analysis",
        }
        return titles.get(phase, phase.replace("-", " ").title())

    def _generate_actions(
        self,
        severity: Severity,
        techniques: list[str],
        clusters: list[CorrelatedCluster],
    ) -> list[str]:
        actions = list(self.SEVERITY_RESPONSES.get(severity, []))
        labels = {l for c in clusters for l in c.labels}
        if "c2-beacon" in labels:
            actions.append("Block the C2 server IP at the firewall/proxy")
            actions.append("Hunt for additional compromised hosts beaconing to the same IP")
        if "lateral-movement" in labels:
            actions.append("Reset credentials for all accounts on affected hosts")
            actions.append("Review network segmentation between VLANs/subnets")
        if "exfiltration" in labels:
            actions.append("Monitor egress bandwidth for anomalies")
            actions.append("Check DLP policies and email gateway logs")
        if "dns-tunneling" in labels:
            actions.append("Implement DNS query logging and analytics")
            actions.append("Consider DNS filtering solution (e.g., Pi-hole, Umbrella)")
        if "brute-force" in labels:
            actions.append("Implement account lockout or rate limiting")
            actions.append("Enable MFA on all externally accessible services")
        if "port-scan" in labels:
            actions.append("Implement port knocking or allowlisting")
            actions.append("Review and restrict exposed services")
        return actions

    def _build_kill_chain(self, techniques: list[str]) -> list[dict[str, str]]:
        tactic_techs: dict[str, list[str]] = defaultdict(list)
        for tid in techniques:
            info = MITRE_TECHNIQUES.get(tid)
            if info:
                tactic_techs[info.tactic].append(tid)
        from sentinelwall.mitre.techniques import TACTIC_ORDER
        chain = []
        for tactic in TACTIC_ORDER:
            if tactic in tactic_techs:
                chain.append({
                    "tactic": tactic,
                    "tactic_name": self.KILL_CHAIN_TACTICS.get(tactic, tactic),
                    "techniques": tactic_techs[tactic],
                })
        return chain

    def _identify_attacker(self, events: list[NetworkEvent], clusters: list[CorrelatedCluster]) -> str:
        from collections import Counter
        external_sources = [
            e.source_ip for e in events
            if _is_external(e.source_ip)
        ]
        if external_sources:
            return Counter(external_sources).most_common(1)[0][0]
        if events:
            return Counter(e.source_ip for e in events).most_common(1)[0][0]
        return ""

    def _identify_target(self, events: list[NetworkEvent], clusters: list[CorrelatedCluster]) -> str:
        from collections import Counter
        internal_targets = [
            e.destination_ip for e in events
            if not _is_external(e.destination_ip)
        ]
        if internal_targets:
            return Counter(internal_targets).most_common(1)[0][0]
        if events:
            return Counter(e.destination_ip for e in events).most_common(1)[0][0]
        return ""

    def _format_time_range(self, events: list[NetworkEvent]) -> str:
        if not events:
            return "N/A"
        timestamps = [e.timestamp for e in events]
        earliest = min(timestamps)
        latest = max(timestamps)
        duration = (latest - earliest).total_seconds()
        if duration < 60:
            return f"{earliest.strftime('%H:%M:%S')} — {latest.strftime('%H:%M:%S')} ({duration:.0f}s)"
        if duration < 3600:
            return f"{earliest.strftime('%H:%M:%S')} — {latest.strftime('%H:%M:%S')} ({duration/60:.1f}m)"
        return f"{earliest.strftime('%Y-%m-%d %H:%M:%S')} — {latest.strftime('%Y-%m-%d %H:%M:%S')} ({duration/3600:.1f}h)"


def _is_external(ip: str) -> bool:
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
    return True
