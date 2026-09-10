"""Programmatic API for SentinelWall."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinelwall.core.engine import EngineConfig, SentinelEngine
from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity


class SentinelWall:
    """High-level programmatic interface to the SentinelWall engine.

    >>> from sentinelwall.api.client import SentinelWall
    >>> sw = SentinelWall()
    >>> sw.ingest_events([event1, event2])
    >>> report = sw.scan()
    """

    def __init__(
        self,
        enable_ml: bool = True,
        enable_mitre: bool = True,
        enable_narrative: bool = True,
        rules_path: str | None = None,
    ) -> None:
        config = EngineConfig(
            enable_ml=enable_ml,
            enable_mitre=enable_mitre,
            enable_narrative=enable_narrative,
            custom_rules_path=rules_path,
        )
        self._engine = SentinelEngine(config)

    @property
    def engine(self) -> SentinelEngine:
        return self._engine

    # --- Ingestion ---
    def ingest_events(self, events: list[NetworkEvent]) -> list[dict[str, Any]]:
        return self._engine.ingest_batch(events)

    def ingest_event(self, event: NetworkEvent) -> list[dict[str, Any]]:
        return self._engine.ingest_event(event)

    def load_pcap(self, path: str | Path) -> int:
        return self._engine.load_pcap(path)

    def load_zeek_log(self, path: str | Path) -> int:
        return self._engine.load_zeek_log(path)

    def load_suricata_eve(self, path: str | Path) -> int:
        return self._engine.load_suricata_eve(path)

    # --- Analysis ---
    def scan(self) -> dict[str, Any]:
        """Run full analysis and return a complete report."""
        stats = self._engine.process()
        narrative = self._engine.generate_narrative()
        return {
            "stats": stats.to_dict(),
            "clusters": [c.to_dict() for c in self._engine.get_clusters()],
            "timelines": [t.to_dict() for t in self._engine.get_timelines()],
            "narrative": narrative,
        }

    # --- Exports ---
    def export_stix(self) -> dict[str, Any]:
        return self._engine.export_stix()

    def export_mitre_navigator(self) -> dict[str, Any]:
        return self._engine.export_mitre_navigator()

    def export_html_report(self, path: str | Path | None = None) -> str:
        return self._engine.export_html_report(path)

    def write_exports(self, directory: str | Path) -> dict[str, str]:
        """Write all exports to a directory. Returns paths written."""
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        stix_path = out / "stix_report.json"
        navigator_path = out / "mitre_attck_navigator.json"
        html_path = out / "report.html"
        stix_path.write_text(json.dumps(self.export_stix(), indent=2))
        navigator_path.write_text(json.dumps(self.export_mitre_navigator(), indent=2))
        self.export_html_report(html_path)
        return {
            "stix": str(stix_path),
            "mitre_navigator": str(navigator_path),
            "html_report": str(html_path),
        }

    # --- Result accessors ---
    def get_events(self) -> list[NetworkEvent]:
        return self._engine.get_events()

    def get_clusters(self) -> list[Any]:
        return self._engine.get_clusters()

    def get_timelines(self) -> list[Any]:
        return self._engine.get_timelines()

    def get_stats(self) -> Any:
        return self._engine.get_stats()

    def reset(self) -> None:
        self._engine.reset()

    # --- Factory helpers ---
    @classmethod
    def from_pcap(cls, pcap_path: str | Path, **kwargs: Any) -> SentinelWall:
        instance = cls(**kwargs)
        instance.load_pcap(pcap_path)
        return instance

    @classmethod
    def from_zeek_dir(cls, directory: str | Path, **kwargs: Any) -> SentinelWall:
        instance = cls(**kwargs)
        d = Path(directory)
        for log_file in d.glob("*.log"):
            instance.load_zeek_log(log_file)
        return instance

    @classmethod
    def from_suricata_eve(cls, eve_path: str | Path, **kwargs: Any) -> SentinelWall:
        instance = cls(**kwargs)
        instance.load_suricata_eve(eve_path)
        return instance