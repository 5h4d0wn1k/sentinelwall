"""STIX 2.1 exporter — exports findings in STIX 2.1 JSON format."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import NetworkEvent
from sentinelwall.core.timeline import AttackTimeline
from sentinelwall.mitre.techniques import MITRE_TECHNIQUES


def _make_id(prefix: str) -> str:
    specific = uuid.uuid4()
    return f"{prefix}--{specific}"


class StixExporter:
    """Exports detections in STIX 2.1 format for SIEM/Threat Intel integration."""

    STIX_VERSION = "2.1"

    def export(
        self,
        events: list[NetworkEvent],
        clusters: list[CorrelatedCluster],
        timelines: list[AttackTimeline],
    ) -> dict[str, Any]:
        """Build a complete STIX 2.1 bundle."""
        objects: list[dict[str, Any]] = []

        # Identity
        identity_id = _make_id("identity")
        objects.append({
            "type": "identity",
            "id": identity_id,
            "identity_class": "organization",
            "name": "SentinelWall Analytics",
            "created": _now(),
            "modified": _now(),
        })

        # Observed events
        for event in events:
            observed = self._event_to_observed_data(event, identity_id)
            if observed:
                objects.append(observed)

        # Attack patterns (MITRE techniques)
        technique_ids = set()
        for cluster in clusters:
            technique_ids.update(cluster.techniques)
        attack_pattern_map: dict[str, str] = {}
        for tid in technique_ids:
            info = MITRE_TECHNIQUES.get(tid)
            if not info:
                continue
            ap_id = _make_id("attack-pattern")
            attack_pattern_map[tid] = ap_id
            objects.append({
                "type": "attack-pattern",
                "id": ap_id,
                "name": f"{tid} - {info.name}",
                "description": info.description,
                "created": _now(),
                "modified": _now(),
                "spec_version": self.STIX_VERSION,
                "x_mitre_technique_id": tid,
                "x_mitre_tactic": info.tactic,
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": info.tactic}],
            })

        # Indicators
        indicators = []
        for cluster in clusters:
            indicator = self._cluster_to_indicator(cluster, attack_pattern_map, identity_id)
            if indicator:
                objects.append(indicator)
                indicators.append(indicator["id"])

        # Incident
        if clusters:
            incident_id = _make_id("incident")
            objects.append({
                "type": "incident",
                "id": incident_id,
                "name": self._incident_name(clusters),
                "description": self._incident_description(clusters),
                "created": _now(),
                "modified": _now(),
                "spec_version": self.STIX_VERSION,
                "severity": self._severity_to_stix(clusters),
                "labels": [label for c in clusters for label in c.labels][:10],
                "object_refs": indicators,
            })

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": self.STIX_VERSION,
            "objects": objects,
        }

    def export_json(self, path: str) -> None:
        raise NotImplementedError("Use export_from_engine instead")

    def _event_to_observed_data(self, event: NetworkEvent, identity_id: str) -> dict[str, Any] | None:
        try:
            src_ref = _make_id("ipv4-addr")
            dst_ref = _make_id("ipv4-addr")
            nw_ref = _make_id("network-traffic")
            return {
                "type": "observed-data",
                "id": _make_id("observed-data"),
                "created": _now(),
                "modified": _now(),
                "first_observed": event.timestamp.isoformat(),
                "last_observed": event.timestamp.isoformat(),
                "number_observed": 1,
                "created_by_ref": identity_id,
                "objects": {
                    "src": {
                        "type": "ipv4-addr",
                        "value": event.source_ip,
                    },
                    "dst": {
                        "type": "ipv4-addr",
                        "value": event.destination_ip,
                    },
                    "traffic": {
                        "type": "network-traffic",
                        "src_ref": "src",
                        "dst_ref": "dst",
                        "src_port": event.source_port,
                        "dst_port": event.destination_port,
                        "protocols": [event.protocol.value.lower()],
                        "start": event.timestamp.isoformat(),
                        "end": event.timestamp.isoformat(),
                    },
                },
            }
        except Exception:
            return None

    def _cluster_to_indicator(
        self,
        cluster: CorrelatedCluster,
        attack_pattern_map: dict[str, str],
        identity_id: str,
    ) -> dict[str, Any] | None:
        if not cluster.involved_hosts:
            return None
        primary_host = sorted(cluster.involved_hosts)[0]
        pattern = f"[ipv4-addr:value = '{primary_host}']"
        indicator = {
            "type": "indicator",
            "id": _make_id("indicator"),
            "created": _now(),
            "modified": _now(),
            "name": f"SentinelWall correlation: {', '.join(cluster.techniques[:3])}",
            "pattern": pattern,
            "valid_from": cluster.first_seen.isoformat(),
            "created_by_ref": identity_id,
            "labels": cluster.labels,
            "confidence": int(cluster.confidence * 100),
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": MITRE_TECHNIQUES[t].tactic}
                for t in cluster.techniques if t in MITRE_TECHNIQUES
            ],
        }
        relationships = []
        for tid, ap_id in attack_pattern_map.items():
            if tid in cluster.techniques:
                relationships.append({
                    "type": "relationship",
                    "id": _make_id("relationship"),
                    "created": _now(),
                    "modified": _now(),
                    "relationship_type": "indicates",
                    "source_ref": indicator["id"],
                    "target_ref": ap_id,
                })
        if relationships:
            indicator["x_sentinelwall_relationships"] = relationships
        return indicator

    def _incident_name(self, clusters: list[CorrelatedCluster]) -> str:
        top = max(clusters, key=lambda c: c.severity.value)
        labels = ", ".join(top.labels[:3])
        return f"SentinelWall detection: {labels}"

    def _incident_description(self, clusters: list[CorrelatedCluster]) -> str:
        return (
            f"SentinelWall correlated {sum(c.event_count for c in clusters)} events "
            f"into {len(clusters)} threat clusters involving "
            f"{len({h for c in clusters for h in c.involved_hosts})} hosts."
        )

    def _severity_to_stix(self, clusters: list[CorrelatedCluster]) -> str:
        sev = max(c.severity for c in clusters)
        if sev.value >= 4:
            return "Critical"
        if sev.value == 3:
            return "High"
        if sev.value == 2:
            return "Medium"
        return "Low"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()