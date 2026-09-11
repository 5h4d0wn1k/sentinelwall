"""Tests for the SentinelWall programmatic API."""

from sentinelwall.api.client import SentinelWall
from sentinelwall.ml.synthetic import generate_attack_scenario, generate_benign_traffic
from tests.conftest import make_event


class TestIngestion:
    def test_ingest_events(self):
        sw = SentinelWall()
        alert_count = sw.ingest_events([make_event()])
        assert isinstance(alert_count, list)
        assert len(sw.get_events()) == 1

    def test_ingest_single(self):
        sw = SentinelWall()
        sw.ingest_event(make_event())
        assert len(sw.get_events()) == 1

    def test_get_events_copy(self):
        sw = SentinelWall()
        sw.ingest_event(make_event())
        assert sw.get_events() is not sw.get_events()


class TestScan:
    def test_scan_empty(self):
        sw = SentinelWall()
        result = sw.scan()
        assert result["stats"]["events_processed"] == 0

    def test_scan_report_keys(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        result = sw.scan()
        assert set(result.keys()) == {"stats", "clusters", "timelines", "narrative"}

    def test_scan_detects_clusters(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        result = sw.scan()
        assert result["stats"]["clusters_detected"] >= 3

    def test_scan_narrative_present(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        result = sw.scan()
        assert result["narrative"]

    def test_get_stats(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("c2-beacon")
        sw.ingest_events(events)
        sw.scan()
        stats = sw.get_stats()
        assert stats.events_processed == len(events)


class TestExports:
    def test_export_stix(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        sw.scan()
        bundle = sw.export_stix()
        assert bundle["type"] == "bundle"

    def test_export_navigator(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        sw.scan()
        layer = sw.export_mitre_navigator()
        assert layer["domain"] == "enterprise-attack"

    def test_export_html(self):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        sw.scan()
        assert "<html" in sw.export_html_report()

    def test_write_exports(self, tmp_path):
        sw = SentinelWall()
        events, _ = generate_attack_scenario("multi-stage")
        sw.ingest_events(events)
        sw.scan()
        paths = sw.write_exports(str(tmp_path))
        assert set(paths.keys()) == {"stix", "mitre_navigator", "html_report"}
        for p in paths.values():
            assert Path(p).exists()


class TestLoaders:
    def test_load_pcap(self, tmp_path, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 50000, 443), "10.0.0.5", "8.8.8.8")
        )
        pcap = tmp_path / "t.pcap"
        pcap.write_bytes(pcap_builder.build([pkt]))
        sw = SentinelWall()
        assert sw.load_pcap(str(pcap)) == 1

    def test_load_zeek(self, zeek_conn_log):
        sw = SentinelWall()
        assert sw.load_zeek_log(str(zeek_conn_log)) == 2

    def test_load_suricata(self, suricata_eve_log):
        sw = SentinelWall()
        assert sw.load_suricata_eve(str(suricata_eve_log)) == 3

    def test_factory_from_pcap(self, tmp_path, pcap_builder):
        pkt = pcap_builder.ethernet_frame(
            pcap_builder.ipv4(pcap_builder.tcp(b"", 50000, 80, syn=False), "10.0.0.5", "8.8.8.8")
        )
        pcap = tmp_path / "t.pcap"
        pcap.write_bytes(pcap_builder.build([pkt]))
        sw = SentinelWall.from_pcap(str(pcap))
        assert len(sw.get_events()) == 1

    def test_factory_from_zeek_dir(self, tmp_path, zeek_conn_log, zeek_ssh_log):
        sw = SentinelWall.from_zeek_dir(str(tmp_path))
        assert len(sw.get_events()) == 4

    def test_factory_from_suricata(self, suricata_eve_log):
        sw = SentinelWall.from_suricata_eve(str(suricata_eve_log))
        assert len(sw.get_events()) == 3


class TestConfigFlags:
    def test_disable_ml(self):
        sw = SentinelWall(enable_ml=False)
        assert sw.engine._ml_detector is None

    def test_disable_mitre(self):
        sw = SentinelWall(enable_mitre=False)
        assert sw.engine._mitre_mapper is None

    def test_disable_narrative(self):
        sw = SentinelWall(enable_narrative=False)
        assert sw.engine._narrative_generator is None

    def test_reset(self):
        sw = SentinelWall()
        sw.ingest_events([make_event() for _ in range(5)])
        sw.reset()
        assert sw.get_events() == []


class TestFullPipeline:
    def test_end_to_end(self):
        sw = SentinelWall()
        benign = generate_benign_traffic(duration_minutes=10, samples_per_minute=3, seed=11)
        attack, gt = generate_attack_scenario("multi-stage")
        sw.ingest_events(benign + attack)
        result = sw.scan()
        detected = set(result["stats"]["technique_counts"].keys())
        assert len(detected & set(gt)) / len(set(gt)) >= 0.5

    def test_engine_property(self):
        sw = SentinelWall()
        from sentinelwall.core.engine import SentinelEngine
        assert isinstance(sw.engine, SentinelEngine)


from pathlib import Path