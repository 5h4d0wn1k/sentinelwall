"""Tests for the SentinelWall CLI."""

import pytest

from sentinelwall import __version__
from sentinelwall.cli.main import (
    build_parser,
    main,
    run_check,
    run_mitre,
    run_rules,
)


def make_pcap(tmp_path, pcap_builder):
    pkt = pcap_builder.ethernet_frame(
        pcap_builder.ipv4(pcap_builder.tcp(b"", 50000, 443), "10.0.0.5", "8.8.8.8")
    )
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(pcap_builder.build([pkt]))
    return pcap


class TestParser:
    def test_parser_created(self):
        assert isinstance(build_parser().prog, str)

    def test_subcommands_present(self):
        parser = build_parser()
        subs = parser._subparsers._group_actions[0].choices
        for cmd in ["analyze", "demo", "rules", "mitre", "dashboard", "check"]:
            assert cmd in subs

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as e:
            main(["--version"])
        assert e.value.code == 0
        out = capsys.readouterr().out
        assert __version__ in out

    def test_no_args_prints_help(self, capsys):
        assert main([]) == 0
        out = capsys.readouterr().out
        assert "usage" in out.lower()


class TestMitreCommand:
    def test_mitre_lists_techniques(self, capsys):
        assert main(["mitre"]) == 0
        out = capsys.readouterr().out
        assert "MITRE ATT&CK coverage" in out
        assert "T1046" in out

    def test_mitre_technique_details(self, capsys):
        assert main(["mitre", "--technique", "T1046"]) == 0
        out = capsys.readouterr().out
        assert "Network Service Discovery" in out
        assert "discovery" in out

    def test_mitre_unknown_technique(self, capsys):
        assert main(["mitre", "--technique", "T9999"]) == 1
        err = capsys.readouterr().err
        assert "unknown technique" in err


class TestRulesCommand:
    def test_rules_list(self, capsys):
        assert main(["rules", "list"]) == 0
        out = capsys.readouterr().out
        assert "Built-in rules: 18" in out

    def test_rules_validate_valid(self, tmp_path, capsys):
        rule_file = tmp_path / "test.swl"
        rule_file.write_text(
            "rule r:\n    meta:\n        severity = HIGH\n    condition:\n        protocol == ssh\n"
        )
        assert main(["rules", "validate", str(rule_file)]) == 0
        out = capsys.readouterr().out
        assert "OK:" in out

    def test_rules_validate_missing_file(self, tmp_path, capsys):
        assert main(["rules", "validate", str(tmp_path / "nope.swl")]) == 1
        err = capsys.readouterr().err
        assert "invalid rule file" in err

    def test_run_rules_list_returns_zero(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["rules", "list"])
        assert run_rules(args, {}) == 0


class TestAnalyzeCommand:
    def test_analyze_pcap(self, tmp_path, pcap_builder, capsys):
        pcap = make_pcap(tmp_path, pcap_builder)
        assert main(["analyze", str(pcap)]) == 0
        out = capsys.readouterr().out
        assert "Loaded 1 events from pcap" in out
        assert "SENTINELWALL ANALYSIS REPORT" in out.upper()
        assert "Events processed" in out

    def test_analyze_missing_file(self, capsys):
        assert main(["analyze", "/nonexistent/x.pcap"]) == 1
        err = capsys.readouterr().err
        assert "file not found" in err

    def test_analyze_zeek(self, zeek_conn_log, capsys):
        assert main(["analyze", str(zeek_conn_log)]) == 0
        out = capsys.readouterr().out
        assert "Loaded 2 events from Zeek log" in out

    def test_analyze_suricata(self, suricata_eve_log, capsys):
        assert main(["analyze", str(suricata_eve_log)]) == 0
        out = capsys.readouterr().out
        assert "Loaded 3 events from Suricata EVE" in out

    def test_analyze_export_dir(self, tmp_path, pcap_builder, capsys, monkeypatch):
        pcap = make_pcap(tmp_path, pcap_builder)
        export_dir = tmp_path / "exports"
        monkeypatch.chdir(tmp_path)
        assert main(["analyze", str(pcap), "--export-dir", str(export_dir)]) == 0
        assert (export_dir / "stix_report.json").exists()
        assert (export_dir / "mitre_attck_navigator.json").exists()
        assert (export_dir / "report.html").exists()

    def test_analyze_json_output(self, tmp_path, pcap_builder, capsys):
        pcap = make_pcap(tmp_path, pcap_builder)
        assert main(["analyze", str(pcap), "--json"]) == 0
        out = capsys.readouterr().out
        assert '"events_processed"' in out


class TestDemoCommand:
    def test_demo_runs(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert main(["demo"]) == 0
        out = capsys.readouterr().out
        assert "SENTINELWALL DEMO" in out
        assert "Recall" in out
        assert "Precision" in out
        assert (tmp_path / "sentinelwall_demo_exports").exists()

    def test_demo_unknown_scenario(self, capsys, monkeypatch):
        assert main(["demo", "--scenario", "bogus"]) == 0


class TestCheckCommand:
    def test_check_ok(self, capsys):
        assert main(["check"]) == 0
        out = capsys.readouterr().out
        assert "status          : OK" in out

    def test_run_check_direct(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["check"])
        assert run_check(args) == 0


class TestFlagBehavior:
    def test_no_mitre_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--no-mitre", "analyze", "x.pcap"])
        assert args.no_mitre is True

    def test_rules_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--rules", "rules.swl", "analyze", "x.pcap"])
        assert args.rules == "rules.swl"