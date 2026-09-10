"""MITRE ATT&CK Navigator layer exporter."""

from __future__ import annotations

import json
import uuid
from typing import Any

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.mitre.techniques import MITRE_TECHNIQUES, TACTIC_ORDER


class NavigatorExporter:
    """Exports detections as MITRE ATT&CK Navigator layers."""

    def export(self, clusters: list[CorrelatedCluster]) -> dict[str, Any]:
        """Build a Navigator layer JSON."""
        technique_scores: dict[str, float] = {}
        technique_metadata: dict[str, list[str]] = {}

        for cluster in clusters:
            for tid in cluster.techniques:
                if tid not in MITRE_TECHNIQUES:
                    continue
                old = technique_scores.get(tid, 0.0)
                technique_scores[tid] = max(old, cluster.confidence * 1.0)
                technique_metadata.setdefault(tid, []).extend(cluster.labels)

        techniques = []
        for tid, score in technique_scores.items():
            info = MITRE_TECHNIQUES[tid]
            techniques.append({
                "techniqueID": tid,
                "score": round(score * 100, 1),
                "enabled": True,
                "comment": f"Detected {len(technique_metadata.get(tid, []))} times. "
                           f"Labels: {', '.join(sorted(set(technique_metadata.get(tid, []))))[:200]}",
            })

        colors = {
            "critical": "#ff1a1a",
            "high": "#ff4500",
            "medium": "#ffa500",
            "low": "#ffff00",
            "informational": "#98fb98",
        }

        return {
            "name": "SentinelWall Detections",
            "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": (
                "MITRE ATT&CK techniques detected by SentinelWall "
                f"across {len(clusters)} correlated threat clusters."
            ),
            "filters": {
                "platforms": ["Linux", "Windows", "macOS", "Cloud", "Network"],
            },
            "sorting": 0,
            "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": [colors["informational"], colors["low"], colors["medium"], colors["high"], colors["critical"]],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "0-24", "color": colors["informational"]},
                {"label": "25-49", "color": colors["low"]},
                {"label": "50-74", "color": colors["medium"]},
                {"label": "75-99", "color": colors["high"]},
                {"label": "100", "color": colors["critical"]},
            ],
            "metadata": {
                "generated_by": "SentinelWall v1.0.0",
                "generation_time": _now(),
                "cluster_count": len(clusters),
            },
            "tacticOrder": TACTIC_ORDER,
        }

    def export_json(self, path: str, clusters: list[CorrelatedCluster]) -> None:
        """Write the layer to a JSON file."""
        layer = self.export(clusters)
        with open(path, "w") as f:
            json.dump(layer, f, indent=2)


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()