"""SentinelWall CLI — analyze network traffic, detect threats, export reports."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from sentinelwall import __version__
from sentinelwall.api.client import SentinelWall
from sentinelwall.ml.synthetic import generate_attack_scenario, generate_benign_traffic


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelwall",
        description=(
            "SentinelWall — Autonomous AI-powered network threat detection, "
            "correlation and response engine"
        ),
        epilog="For demos: 'sentinelwall demo' runs a full simulated attack analysis.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--no-ml", action="store_true", help="Disable ML anomaly detection"
    )
    parser.add_argument(
        "--no-mitre", action="store_true", help="Disable MITRE ATT&CK mapping"
    )
    parser.add_argument(
        "--rules", type=str, default="", help="Path to custom rule file"
    )

    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Analyze network event data")
    analyze.add_argument("input", type=str, nargs="+", help="Input files (pcap, Zeek .log, eve.json)")
    analyze.add_argument("--export-dir", type=str, default="", help="Directory for export files")
    analyze.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    demo = sub.add_parser("demo", help="Run a simulated multi-stage attack scenario")
    demo.add_argument("--scenario", type=str, default="multi-stage", help="Scenario name")

    rules_cmd = sub.add_parser("rules", help="Manage detection rules")
    rules_sub = rules_cmd.add_subparsers(dest="rules_command")
    rules_list = rules_sub.add_parser("list", help="List built-in rules")
    rules_validate = rules_sub.add_parser("validate", help="Validate a rule file")
    rules_validate.add_argument("file", type=str, help="Rule file to validate")

    mitre = sub.add_parser("mitre", help="Show MITRE ATT&CK coverage")
    mitre.add_argument("--technique", type=str, default="", help="Show details for a technique")

    dashboard = sub.add_parser("dashboard", help="Launch web dashboard")
    dashboard.add_argument("--host", type=str, default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=5000)

    check = sub.add_parser("check", help="Run engine self-check / health test")
    return parser


def run_analyze(args: argparse.Namespace, kwargs: dict[str, Any]) -> int:
    sw = SentinelWall(**kwargs)
    for path in args.input:
        p = Path(path)
        if not p.exists():
            print(f"error: file not found: {path}", file=sys.stderr)
            return 1
        if p.suffix == ".pcap":
            count = sw.load_pcap(p)
            print(f"Loaded {count} events from pcap: {path}")
        elif p.name == "eve.json" or p.name.endswith(".json"):
            count = sw.load_suricata_eve(p)
            print(f"Loaded {count} events from Suricata EVE: {path}")
        elif p.suffix == ".log":
            count = sw.load_zeek_log(p)
            print(f"Loaded {count} events from Zeek log: {path}")
        else:
            try:
                count = sw.load_pcap(p)
                print(f"Loaded {count} events from raw file: {path}")
            except OSError as exc:
                print(f"error: cannot parse {path}: {exc}", file=sys.stderr)
                return 1

    start = time.monotonic()
    result = sw.scan()
    elapsed = time.monotonic() - start
    stats = result["stats"]

    print()
    print("=" * 68)
    print(f"  SENTINELWALL ANALYSIS REPORT  (v{__version__})")
    print("=" * 68)
    print(f"  Events processed : {stats['events_processed']}")
    print(f"  Threat clusters  : {stats['clusters_detected']}")
    print(f"  Alerts generated : {stats['alerts_generated']}")
    print(f"  Timelines built  : {stats['timelines_built']}")
    print(f"  Processing time  : {stats['processing_time_seconds']:.3f}s")
    print(f"  Throughput       : {stats['events_per_second']:,.0f} events/sec")
    print()
    print("  Severity distribution:")
    for sev, count in stats["severity_distribution"].items():
        print(f"    {sev:<14} {count}")
    print()
    print("  MITRE ATT&CK techniques detected:")
    for tid, count in stats["technique_counts"].items():
        print(f"    {tid:<8} {count}")
    print(f"  Protocols observed: {', '.join(stats['protocol_counts'].keys())}")
    print()

    if result["narrative"]:
        print(result["narrative"])
        print()

    if args.export_dir:
        paths = sw.write_exports(args.export_dir)
        print("Exports written:")
        for name, path in paths.items():
            print(f"  {name:<16} {path}")

    if args.json:
        print(json.dumps(result, indent=2, default=str))

    print(f"Total wall time: {elapsed:.3f}s")
    return 0


def run_demo(args: argparse.Namespace) -> int:
    print()
    print("=" * 68)
    print("  SENTINELWALL DEMO — Simulated Multi-Stage Attack")
    print("=" * 68)
    print()
    scenario = args.scenario
    events, true_techniques = generate_attack_scenario(scenario)

    if not events:
        events, true_techniques = generate_benign_traffic(), []
        print(f"Unknown scenario '{scenario}', running benign traffic analysis.\n")

    print(f"Scenario: {scenario} ({len(events)} events, "
          f"{len(true_techniques)} hidden MITRE techniques)")
    print("Hiding ground-truth; analyzing as a clean observer...\n")

    sw = SentinelWall()
    hit_events = sw.ingest_events(events)
    result = sw.scan()

    stats = result["stats"]
    detected_techniques = set(stats["technique_counts"].keys())
    overlap = detected_techniques & set(true_techniques)
    recall = len(overlap) / len(true_techniques) if true_techniques else 0.0
    precision = len(overlap) / len(detected_techniques) if detected_techniques else 0.0

    print(f"Events processed      : {stats['events_processed']}")
    print(f"Threat clusters        : {stats['clusters_detected']}")
    print(f"Alerts generated       : {stats['alerts_generated']}")
    print(f"Throughput             : {stats['events_per_second']:,.0f} events/sec")
    print()
    if true_techniques:
        print(f"Ground-truth techniques: {', '.join(sorted(true_techniques))}")
        print(f"Detected techniques    : {', '.join(sorted(detected_techniques))}")
        print(f"Recall    : {recall:.1%}   ({len(overlap)}/{len(true_techniques)})")
        print(f"Precision : {precision:.1%}   ({len(overlap)}/{len(detected_techniques)})")
        print()

    if result["narrative"]:
        print(result["narrative"])
        print()

    sw.write_exports("sentinelwall_demo_exports")
    print("Demo exports written to ./sentinelwall_demo_exports/")
    return 0


def run_rules(args: argparse.Namespace, kwargs: dict[str, Any]) -> int:
    from sentinelwall.rules.engine import RuleEngine
    engine = RuleEngine()

    if args.rules_command == "list":
        rules = engine.get_builtin_rules()
        print(f"Built-in rules: {len(rules)}")
        print()
        for rule in rules:
            print(f"  [{rule.name}]")
            print(f"    severity : {rule.severity.name}")
            print(f"    desc     : {rule.description}")
            if rule.techniques:
                print(f"    mitre    : {', '.join(rule.techniques)}")
            if rule.tags:
                print(f"    tags     : {', '.join(rule.tags)}")
            print()
        return 0

    if args.rules_command == "validate":
        try:
            count = engine.load_rules_from_file(args.file)
        except Exception as exc:
            print(f"error: invalid rule file: {exc}", file=sys.stderr)
            return 1
        print(f"OK: parsed {count} rule(s) from {args.file}")
        return 0

    return 1


def run_mitre(args: argparse.Namespace) -> int:
    from sentinelwall.mitre.mapper import MitreMapper
    from sentinelwall.mitre.techniques import MITRE_TECHNIQUES

    mapper = MitreMapper()
    if args.technique:
        info = mapper.get_technique_info(args.technique)
        if not info:
            print(f"error: unknown technique {args.technique}", file=sys.stderr)
            return 1
        print(f"  {info.technique_id} - {info.name}")
        print(f"  Tactic   : {info.tactic}")
        print(f"  Severity : {info.severity.name}")
        print(f"  Desc     : {info.description}")
        print(f"  Patterns : {', '.join(info.detection_patterns)}")
        print(f"  Protocols: {', '.join(info.protocol_hints)}")
        print(f"  Ports    : {', '.join(str(p) for p in info.port_hints)}")
        if info.sub_techniques:
            print("  Sub-techniques:")
            for sub_id, sub_name in info.sub_techniques.items():
                print(f"    {sub_id} - {sub_name}")
        return 0

    print(f"MITRE ATT&CK coverage: {len(MITRE_TECHNIQUES)} techniques")
    print()
    print(f"{'TID':<8} {'Tactic':<22} {'Name':<40} {'Severity'}")
    print("-" * 90)
    for tid, info in sorted(MITRE_TECHNIQUES.items()):
        print(f"{tid:<8} {info.tactic:<22} {info.name:<40} {info.severity.name}")
    return 0


def run_dashboard(args: argparse.Namespace) -> int:
    try:
        from sentinelwall.dashboard.app import create_app
    except ImportError as exc:
        print(f"error: dashboard requires Flask (pip install sentinelwall[web]): {exc}",
              file=sys.stderr)
        return 1
    app = create_app()
    print(f"Serving SentinelWall dashboard at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def run_check(args: argparse.Namespace) -> int:
    from sentinelwall.ml.synthetic import generate_attack_scenario
    print("Running SentinelWall self-check...")
    events, techniques = generate_attack_scenario("multi-stage")
    sw = SentinelWall()
    sw.ingest_events(events)
    sw.scan()
    stats = sw.get_stats()
    ok = stats.clusters_detected > 0 and stats.technique_counts
    print(f"  events          : {stats.events_processed}")
    print(f"  clusters        : {stats.clusters_detected}")
    print(f"  techniques      : {len(stats.technique_counts)}")
    print(f"  throughput      : {stats.events_per_second:,.0f} events/sec")
    print(f"  status          : {'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    kwargs: dict[str, Any] = {
        "enable_ml": not args.no_ml,
        "enable_mitre": not args.no_mitre,
        "rules_path": args.rules or None,
    }

    commands = {
        "analyze": run_analyze,
    }
    if args.command == "analyze":
        return run_analyze(args, kwargs)
    if args.command == "demo":
        return run_demo(args)
    if args.command == "rules":
        return run_rules(args, kwargs)
    if args.command == "mitre":
        return run_mitre(args)
    if args.command == "dashboard":
        return run_dashboard(args)
    if args.command == "check":
        return run_check(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())