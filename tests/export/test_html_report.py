"""Tests for the HTML report exporter."""

from sentinelwall.core.engine import SentinelEngine
from sentinelwall.core.events import Severity
from sentinelwall.export.html_report import HtmlReportExporter
from sentinelwall.ml.synthetic import generate_attack_scenario
from tests.conftest import make_event


def build_report():
    events, _ = generate_attack_scenario("multi-stage")
    engine = SentinelEngine()
    engine.ingest_batch(events)
    engine.process()
    exporter = HtmlReportExporter()
    html = exporter.export(
        engine.get_events(),
        engine.get_clusters(),
        engine.get_timelines(),
        engine.get_stats(),
    )
    return html, engine


class TestHtmlOutput:
    def test_html_structure(self):
        html, _ = build_report()
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html

    def test_branding(self):
        html, _ = build_report()
        assert "SENTINEL" in html.upper()

    def test_contains_event_table(self):
        html, _ = build_report()
        assert "<table" in html

    def test_contains_cards(self):
        html, _ = build_report()
        assert "class=\"card" in html

    def test_contains_technique_chips(self):
        html, _ = build_report()
        assert "chip-tech" in html

    def test_contains_severity_section(self):
        html, _ = build_report()
        assert "sev-line" in html

    def test_contains_masked_technique_ids(self):
        html, _ = build_report()
        assert "T1046" in html


class TestWrites:
    def test_writes_file(self, tmp_path):
        engine = SentinelEngine()
        events, _ = generate_attack_scenario("multi-stage")
        engine.ingest_batch(events)
        engine.process()
        out = tmp_path / "report.html"
        HtmlReportExporter().export(
            engine.get_events(), engine.get_clusters(),
            engine.get_timelines(), engine.get_stats(), out,
        )
        assert out.exists()
        assert out.stat().st_size > 2000

    def test_creates_parent_dir(self, tmp_path):
        engine = SentinelEngine()
        events, _ = generate_attack_scenario("brute-force")
        engine.ingest_batch(events)
        out = tmp_path / "nested" / "deep" / "report.html"
        HtmlReportExporter().export(
            engine.get_events(), engine.get_clusters(),
            engine.get_timelines(), engine.get_stats(), out,
        )
        assert out.exists()


class TestEmptyReports:
    def test_empty_report(self):
        html = HtmlReportExporter().export([], [], [], None)
        assert "<html" in html
        assert "SENTINEL" in html.upper()

    def test_benign_only_report(self):
        engine = SentinelEngine()
        engine.ingest_batch([make_event() for _ in range(10)])
        engine.process()
        html = HtmlReportExporter().export(
            engine.get_events(), [], [], engine.get_stats(),
        )
        assert "SENTINEL" in html.upper()