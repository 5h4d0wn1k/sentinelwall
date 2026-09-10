"""MITRE ATT&CK technique mapper — maps correlated events to ATT&CK techniques."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity
from sentinelwall.mitre.techniques import MITRE_TECHNIQUES, TechniqueInfo, TACTIC_ORDER


class MitreMapper:
    """Maps correlated event clusters to MITRE ATT&CK techniques.

    Uses a multi-signal approach:
    1. Direct event type mapping (e.g., PORT_SCAN → T1046)
    2. Protocol-based inference (e.g., SSH on non-standard port → T1572)
    3. Behavioral pattern matching (e.g., regular beaconing → T1071)
    4. Contextual enrichment (e.g., multiple lateral connections → T1021)
    5. Kill chain phase reconstruction
    """

    def __init__(self) -> None:
        self._event_technique_map: dict[EventType, list[str]] = self._build_event_map()
        self._protocol_technique_map: dict[Protocol, list[str]] = self._build_protocol_map()
        self._port_technique_map: dict[int, list[str]] = self._build_port_map()

    def map_techniques(self, cluster: CorrelatedCluster) -> dict[str, Any]:
        """Map a cluster to MITRE ATT&CK techniques with confidence scores."""
        technique_scores: dict[str, float] = defaultdict(float)
        technique_evidence: dict[str, list[str]] = defaultdict(list)

        for event in cluster.events:
            self._map_event_techniques(event, technique_scores, technique_evidence)
            self._map_protocol_techniques(event, technique_scores, technique_evidence)
            self._map_port_techniques(event, technique_scores, technique_evidence)

        self._map_behavioral_patterns(cluster, technique_scores, technique_evidence)
        self._map_cluster_labels(cluster, technique_scores, technique_evidence)

        ranked = sorted(technique_scores.items(), key=lambda x: x[1], reverse=True)
        techniques = []
        for tech_id, score in ranked[:10]:
            info = MITRE_TECHNIQUES.get(tech_id)
            if info:
                techniques.append({
                    "technique_id": tech_id,
                    "name": info.name,
                    "tactic": info.tactic,
                    "confidence": min(1.0, score),
                    "evidence": technique_evidence.get(tech_id, []),
                    "sub_techniques": info.sub_techniques,
                })

        kill_chain = self._build_kill_chain(techniques)
        return {
            "techniques": techniques,
            "kill_chain": kill_chain,
            "primary_tactic": techniques[0]["tactic"] if techniques else "unknown",
            "coverage_score": len(techniques) / len(MITRE_TECHNIQUES),
        }

    def get_technique_info(self, technique_id: str) -> TechniqueInfo | None:
        return MITRE_TECHNIQUES.get(technique_id)

    def get_all_techniques(self) -> dict[str, dict[str, Any]]:
        return {tid: info.to_dict() for tid, info in MITRE_TECHNIQUES.items()}

    def _map_event_techniques(
        self,
        event: NetworkEvent,
        scores: dict[str, float],
        evidence: dict[str, list[str]],
    ) -> None:
        for tech_id, info in MITRE_TECHNIQUES.items():
            if event.event_type.name in info.event_type_hints:
                scores[tech_id] += 0.4
                evidence[tech_id].append(f"event_type={event.event_type.name}")

    def _map_protocol_techniques(
        self,
        event: NetworkEvent,
        scores: dict[str, float],
        evidence: dict[str, list[str]],
    ) -> None:
        for tech_id, info in MITRE_TECHNIQUES.items():
            if event.protocol.value in info.protocol_hints:
                scores[tech_id] += 0.2
                evidence[tech_id].append(f"protocol={event.protocol.value}")

    def _map_port_techniques(
        self,
        event: NetworkEvent,
        scores: dict[str, float],
        evidence: dict[str, list[str]],
    ) -> None:
        for tech_id, info in MITRE_TECHNIQUES.items():
            if event.destination_port in info.port_hints:
                scores[tech_id] += 0.3
                evidence[tech_id].append(f"port={event.destination_port}")

    def _map_behavioral_patterns(
        self,
        cluster: CorrelatedCluster,
        scores: dict[str, float],
        evidence: dict[str, list[str]],
    ) -> None:
        if cluster.event_count > 5 and cluster.severity.value >= Severity.HIGH.value:
            scores["T1046"] += 0.2
            evidence["T1046"].append("high_event_volume")
        internal_events = [
            e for e in cluster.events
            if not _is_external(e.source_ip) and not _is_external(e.destination_ip)
        ]
        if len(internal_events) > 3:
            unique_targets = {e.destination_ip for e in internal_events}
            if len(unique_targets) >= 3:
                scores["T1021"] += 0.5
                evidence["T1021"].append(f"lateral_movement_to_{len(unique_targets)}_hosts")
        encrypted = [e for e in cluster.events if e.is_encrypted and e.payload_size > 10000]
        if encrypted:
            scores["T1048"] += 0.3
            scores["T1041"] += 0.3
            evidence["T1048"].append("large_encrypted_transfer")
            evidence["T1041"].append("encrypted_data_over_connection")
        protocols = cluster.unique_protocols
        if len(protocols) >= 3:
            scores["T1572"] += 0.2
            evidence["T1572"].append(f"multi_protocol_usage_{len(protocols)}_protocols")

    def _map_cluster_labels(
        self,
        cluster: CorrelatedCluster,
        scores: dict[str, float],
        evidence: dict[str, list[str]],
    ) -> None:
        label_map = {
            "port-scan": ("T1046", 0.8),
            "c2-beacon": ("T1071", 0.9),
            "lateral-movement": ("T1021", 0.8),
            "exfiltration": ("T1048", 0.7),
            "dns-tunneling": ("T1071", 0.6),
            "brute-force": ("T1110", 0.9),
            "protocol-anomaly": ("T1572", 0.6),
            "covert-channel": ("T1095", 0.7),
        }
        for label in cluster.labels:
            if label in label_map:
                tech_id, bonus = label_map[label]
                scores[tech_id] += bonus
                evidence[tech_id].append(f"cluster_label={label}")

    def _build_kill_chain(self, techniques: list[dict[str, Any]]) -> list[dict[str, str]]:
        tactic_map: dict[str, list[str]] = defaultdict(list)
        for tech in techniques:
            tactic_map[tech["tactic"]].append(tech["technique_id"])
        kill_chain = []
        for tactic in TACTIC_ORDER:
            if tactic in tactic_map:
                kill_chain.append({
                    "tactic": tactic,
                    "techniques": tactic_map[tactic],
                })
        return kill_chain

    def _build_event_map(self) -> dict[EventType, list[str]]:
        mapping: dict[EventType, list[str]] = {
            EventType.PORT_SCAN: ["T1046", "T1018"],
            EventType.DNS_QUERY: ["T1071"],
            EventType.DNS_RESPONSE: ["T1071"],
            EventType.HTTP_REQUEST: ["T1071", "T1190", "T1105"],
            EventType.TLS_HANDSHAKE: ["T1572"],
            EventType.SSH_HANDSHAKE: ["T1021", "T1133"],
            EventType.SSH_AUTH: ["T1021", "T1110", "T1078"],
            EventType.SMB_TRANSACTION: ["T1021", "T1083", "T1005"],
            EventType.SMB_CONNECT: ["T1021"],
            EventType.ICMP_ECHO: ["T1095"],
            EventType.DATA_TRANSFER: ["T1048", "T1041", "T1560"],
            EventType.ENCRYPTED_TRANSFER: ["T1048", "T1560"],
            EventType.AUTH_FAILURE: ["T1110"],
            EventType.AUTH_SUCCESS: ["T1078"],
            EventType.C2_BEACON: ["T1071", "T1572"],
            EventType.EXFILTRATION: ["T1048", "T1041"],
            EventType.LATERAL_MOVEMENT: ["T1021"],
            EventType.PERSISTENCE: ["T1053", "T1133"],
            EventType.PRIVILEGE_ESCALATION: ["T1078"],
            EventType.DEFENSE_EVASION: ["T1027", "T1562"],
            EventType.COLLECTION: ["T1560", "T1005"],
            EventType.IMPACT: ["T1486"],
        }
        return mapping

    def _build_protocol_map(self) -> dict[Protocol, list[str]]:
        return {
            Protocol.SSH: ["T1021", "T1133"],
            Protocol.SMB: ["T1021", "T1083"],
            Protocol.DNS: ["T1071"],
            Protocol.HTTP: ["T1071", "T1190"],
            Protocol.HTTPS: ["T1071", "T1572"],
            Protocol.ICMP: ["T1095"],
            Protocol.RDP: ["T1021", "T1133"],
            Protocol.VNC: ["T1021"],
        }

    def _build_port_map(self) -> dict[int, list[str]]:
        return {
            22: ["T1021", "T1133"],
            23: ["T1021", "T1133"],
            53: ["T1071"],
            80: ["T1071", "T1190"],
            443: ["T1071", "T1572"],
            445: ["T1021", "T1083"],
            139: ["T1021", "T1083"],
            3389: ["T1021", "T1133"],
            5985: ["T1021"],
            5986: ["T1021"],
            8080: ["T1071", "T1190"],
            8443: ["T1071", "T1190"],
        }


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
