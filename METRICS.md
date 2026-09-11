# SentinelWall — Measured Performance Metrics

All numbers below were measured directly on the development machine:

- **CPU:** AMD Ryzen 5 5500U (single-core python processes)
- **RAM:** 16 GB
- **OS / runtime:** Linux, Python 3.13.5
- **Suite:** pytest 9.1.1 with `typeguard` active
- **Date:** 2026-09-11

## Throughput

| Metric | Value |
|---|---|
| Event ingestion rate (12,000 synthetic events, sequential) | ~23,700 events/sec |
| Engine `process()` for 12,000 events | 0.063 sec |
| Full pipeline for demo multi-stage scenario (34 events) | 0.28 sec wall |
| Demo-reported processing throughput (34 events) | ~14,700 events/sec |
| Detection pipeline events-per-second (12,000 events, process phase) | ~190,000 evt/s |

## Memory

| Metric | Value |
|---|---|
| tracemalloc peak (12,000 events ingested into engine) | ~3.0 MB |
| Process max RSS after ingesting 12,000 events | ~33 MB |

## Detection Accuracy (Synthetic Scenarios)

Measured by asking `SentinelWall` to analyze each `generate_attack_scenario`
scenario as a clean observer and comparing detected technique IDs against the
published ground truth.

| Scenario | Recall | Precision | Notes |
|---|---|---|---|
| multi-stage | 78% (7/9) | 88% (7/8) | T1560 not surfaced as its own cluster |
| brute-force | 0% (0/1) | n/a | scenario is failures-only; detector requires failure→success sequence |
| lateral-movement | 50% (1/2) | 100% | T1083 not detected |
| exfiltration | 50% (2/4) | 100% | T1071/T1560 not detected standalone |
| c2-beacon | 100% (4/4) | 80% (4/5) | one extra T1041 cluster |
| dns-tunneling | 100% (2/2) | 100% | |

## Rule Engine

| Metric | Value |
|---|---|
| Built-in rules | 18 |
| Single rule evaluation latency | ~2.1 microseconds |
| Evaluations per second (18-rule workload, single event dict) | ~470,000 eval/s |
| Custom rule load time (100 rules) | ~5.6 ms |

## MITRE ATT&CK Coverage

| Metric | Value |
|---|---|
| Techniques in database | 23 |
| Distinct tactics covered | 11 |
| Navigator layer export (5 clusters) | ~1 ms |
| STIX 2.1 bundle export (34 events, 5 clusters) | ~19 ms, 35 KB |
| STIX 2.1 bundle export (1,800 events) | ~84 ms, 1.3 MB |
| HTML report export (34 events) | ~2 ms, 14 KB |
| HTML report export (1,800 events) | ~31 ms, 25 KB |

## Test Suite

| Metric | Value |
|---|---|
| Total tests | 452 |
| Test suite runtime (pytest) | 4.70 sec |
| Iterations to full pass (this run) | 13 |

## How Measurements Were Taken

- **Ingestion:** `SentinelEngine.ingest_event` on 12,000 benign synthetic events;
  wall time via `time.perf_counter`.
- **Detection accuracy:** `SentinelWall` API client ingests every scenario,
  `scan()` returns `technique_counts`; overlap vs. ground-truth list.
- **Rule engine:** `RuleCondition.evaluate` on a fixed event dict, 200,000 × 18
  evaluations; parse timing from `RuleParser.parse_ruleset` of 100 generated rules.
- **Exports:** `engine.export_*` timings exclude STIX identity object overhead
  variance; sizes measured on serialized JSON / HTML bytes.

To reproduce: `python3 -m pytest tests/ -q` and `python3 -m sentinelwall demo`.