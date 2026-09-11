# SentinelWall

Autonomous AI-powered network threat detection, correlation and response engine.

SentinelWall ingests network traffic from pcaps, Suricata EVE logs, and Zeek
logs (or programmatically), then runs a multi-stage pipeline that detects
threats, maps them to MITRE ATT&CK techniques, builds attack-chain timelines,
and produces human-readable narratives plus machine-readable exports (STIX 2.1,
MITRE ATT&CK Navigator, HTML dashboard).

```
                ┌────────────┐      ┌──────────────┐      ┌──────────────┐
   pcap ───────►│            │      │  Correlator  │      │  MITRE Mapper│
   Zeek ───────►│ Ingestion  │─────►│  (clustering │─────►│  (ATT&CK     │
 Suricata ─────►│ + Enrich   │      │   & beacon   │      │  coverage)   │
   Programmatic►│            │      │   detection) │      │              │
                └────────────┘      └──────────────┘      └──────┬───────┘
                                                                 ▼
   narrative ◄── Narrative Gen ◄── Timeline Analyzer ◄── ML + Rules ◄──┘
                                                                 ▼
                        STIX 2.1 │ Navigator JSON │ HTML │ JSON
```

## Features

- **Multi-format ingestion** — pure-Python pcap reader (Ethernet/IPv4/IPv6/TCP/
  UDP/ICMP, HTTP/DNS/TLS/SSH application parsing), Zeek `*.log`, Suricata
  `eve.json`, and a direct event API.
- **Behavioral correlation** — port-scan detection, C2 beacon detection
  (regular-interval analysis with coefficient-of-variation), brute-force /
  credential stuffing sequences, lateral movement, DNS tunneling, large
  encrypted exfiltration, and multi-hop attack chains.
- **ML anomaly detection** — per-host baselines, port/protocol frequency
  models, and a nearest-neighbour isolation score; no external ML dependency
  required at runtime (`dependencies = []`).
- **Rule engine** — declarative SentinelWall DSL (see
  [Rule DSL](#rule-dsl)) with 18 built-in rules; arbitrary custom rules via
  `--rules rules.swl`.
- **MITRE ATT&CK mapping** — 23 techniques across 11 tactics, mapped from
  event type, protocol, port, behavioral pattern, and label signals.
- **Narrative generation** — automatic human-readable threat reports with
  phases, kill-chain and recommended remediations.
- **Exports** — STIX 2.1 bundle, MITRE ATT&CK Navigator layer, standalone HTML
  dashboard report, and JSON.
- **Web dashboard** — Flask-based local analytics dashboard.
- **CLI** — `analyze`, `demo`, `rules`, `mitre`, `dashboard`, `check`.

## Installation

Requires **Python 3.10+**. No third-party runtime dependencies.

```bash
git clone https://github.com/5h4d0wn1k/sentinelwall.git
cd sentinelwall
pip install -e .
```

Optional extras:

```bash
pip install -e ".[capture]"   # scapy-based packet capture
pip install -e ".[ml]"        # scikit-learn / numpy acceleration
pip install -e ".[web]"       # Flask dashboard
pip install -e ".[all]"       # everything
pip install -e ".[dev]"       # testing and lint tooling
```

You can also run without installing by invoking the module:

```bash
python3 -m sentinelwall --version
```

## Usage

### Quick demo

```bash
python3 -m sentinelwall demo
```

Runs a simulated multi-stage attack (recon → brute force → C2 → exfiltration →
lateral movement), analyzes it as a clean observer, prints the narrative and
writes exports to `./sentinelwall_demo_exports/`.

### Analyze traffic

```bash
python3 -m sentinelwall analyze capture.pcap
python3 -m sentinelwall analyze conn.log
python3 -m sentinelwall analyze eve.json
python3 -m sentinelwall analyze --export-dir ./reports *.pcap
python3 -m sentinelwall analyze --json capture.pcap
```

- `--export-dir DIR` — write STIX / Navigator / HTML / JSON exports.
- `--json` — print machine-readable JSON summary.

### Global options

| Option | Effect |
|---|---|
| `--no-ml` | disable ML anomaly detection |
| `--no-mitre` | disable MITRE ATT&CK mapping |
| `--rules FILE` | load custom rules (SentinelWall DSL) |

### Manage rules

```bash
python3 -m sentinelwall rules list       # built-in rule inventory
python3 -m sentinelwall rules validate rules.swl
```

### MITRE coverage

```bash
python3 -m sentinelwall mitre                       # coverage summary
python3 -m sentinelwall mitre --technique T1046     # technique details
```

### Dashboard

```bash
python3 -m sentinelwall dashboard --host 127.0.0.1 --port 8080
```

### Health check

```bash
python3 -m sentinelwall check
```

## MITRE ATT&CK Coverage

SentinelWall ships a curated database of 23 techniques across 11 tactics. The
mapper consumes events and threat clusters and reports the best-matching
techniques; the primary tactic is surfaced for each cluster.

| Technique | Name | Tactic |
|---|---|---|
| T1005 | Data from Local System | Collection |
| T1018 | Remote System Discovery | Discovery |
| T1021 | Remote Services | Lateral Movement |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1046 | Network Service Discovery | Discovery |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1053 | Scheduled Task/Job | Persistence |
| T1059 | Command and Scripting Interpreter | Execution |
| T1071 | Application Layer Protocol | Command and Control |
| T1078 | Valid Accounts | Persistence |
| T1082 | System Information Discovery | Discovery |
| T1083 | File and Directory Discovery | Discovery |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1110 | Brute Force | Credential Access |
| T1133 | External Remote Services | Persistence |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1486 | Data Encrypted for Impact | Impact |
| T1560 | Archive Collected Data | Collection |
| T1562 | Impair Defenses | Defense Evasion |
| T1566 | Phishing | Initial Access |
| T1572 | Protocol Tunneling | Command and Control |

Tactics covered: Collection, Command and Control, Credential Access, Defense
Evasion, Discovery, Execution, Exfiltration, Impact, Initial Access, Lateral
Movement, Persistence (11 of 14).

## Rule DSL

Rules are stored in `.swl` files using the SentinelWall DSL. Each rule has a
name, optional `meta:` block, and a `condition:` section. Conditions use
symbolic or word operators, and lines may be joined with `AND` / `OR`. A
condition block may be prefixed with `or condition:` / `and condition:` to set
the combine logic.

```rule
rule ssh_monitor:
    meta:
        description = "Detect SSH access"
        severity = HIGH
        techniques = ["T1021", "T1133"]
        tags = ["ssh", "remote"]
    condition:
        protocol == ssh
        AND destination_port eq 22

rule large_exfil:
    meta:
        severity = HIGH
    condition:
        payload_size > 100000

rule web_or_dns:
    or condition:
        protocol == http
        OR protocol == https
```

### Operators

| Symbolic | Word | Meaning |
|---|---|---|
| `==` | `eq` | equal (case-insensitive for strings) |
| `!=` | `neq` | not equal |
| `>` | `gt` | greater than (numeric) |
| `>=` | `gte` | greater than or equal |
| `<` | `lt` | less than |
| `<=` | `lte` | less than or equal |
| — | `contains` | substring, case-insensitive |
| — | `not_contains` | substring absent |
| — | `matches` | regex search |
| — | `in` | value in list, e.g. `destination_port in [22, 443]` |
| — | `between` | range, e.g. `payload_size between [1000, 5000]` |

Prefix a condition with `NOT ` to negate it. Fields available: `event_type`,
`protocol`, `severity`, `source_ip`, `destination_ip`, `source_port`,
`destination_port`, `payload_size`, `payload_preview`, `direction`, `tags`.

Example field values: `event_type == PORT_SCAN`, `protocol == ssh`,
`severity == HIGH`, `destination_port in [22, 443, 3389]`.

See `docs/rule-dsl.md` for the full reference.

## API

SentinelWall exposes a programmatic API for embedding:

```python
from sentinelwall.api.client import SentinelWall
from sentinelwall.core.events import EventType, Protocol, Severity, NetworkEvent
from datetime import datetime, timezone

sw = SentinelWall()

event = NetworkEvent(
    timestamp=datetime.now(timezone.utc),
    source_ip="185.220.101.34",
    destination_ip="10.0.1.5",
    source_port=51234,
    destination_port=22,
    protocol=Protocol.SSH,
    event_type=EventType.AUTH_FAILURE,
    severity=Severity.MEDIUM,
    payload_size=80,
    payload_preview="SSH-2.0 authentication failure",
)

sw.ingest_event(event)
report = sw.scan()

print(report["stats"])
print(report["narrative"])
```

### Reference

| Method | Description |
|---|---|
| `SentinelWall(enable_ml, enable_mitre, enable_narrative, rules_path)` | construct engine |
| `ingest_event(event)` / `ingest_events(events)` | ingest event(s), return alerts |
| `load_pcap(path)` / `load_zeek_log(path)` / `load_suricata_eve(path)` | load traffic files |
| `scan()` | run full pipeline; return `{stats, clusters, timelines, narrative}` |
| `export_stix()` | STIX 2.1 bundle (dict) |
| `export_mitre_navigator()` | Navigator layer (dict) |
| `export_html_report(path=None)` | HTML dashboard report (str) |
| `write_exports(dir)` | write STIX + Navigator + HTML to a directory |
| `get_events()` / `get_clusters()` / `get_timelines()` / `get_stats()` | access results |
| `reset()` | clear engine state |
| `from_pcap(path, ...)` / `from_zeek_dir(dir, ...)` / `from_suricata_eve(path, ...)` | factory constructors |

`NetworkEvent` fields: `timestamp`, `source_ip`, `destination_ip`,
`source_port`, `destination_port`, `protocol`, `event_type`, `severity`,
`payload_size`, `payload_preview`, `tags`, `metadata`, `raw_data`,
`confidence`. Event types include `PORT_SCAN`, `TLS_HANDSHAKE`,
`SSH_HANDSHAKE`, `AUTH_FAILURE`, `AUTH_SUCCESS`, `C2_BEACON`,
`ENCRYPTED_TRANSFER`, `DNS_QUERY`, `DNS_RESPONSE`, `HTTP_REQUEST`, `CONNECTION`
and more. Protocols include `TCP`, `UDP`, `HTTP`, `HTTPS`, `SSH`, `DNS`,
`SMB`, `RDP`, `VNC`, `ICMP`, `SMTP`, `FTP`, `LDAP`, `KERBEROS`, `NTP`, `DHCP`.

## Testing

```bash
python3 -m pytest tests/ -q
```

The suite contains **452 tests** covering the parser, correlator, engine,
events, rules, MITRE mapper, ML detector, exports (STIX / Navigator / HTML),
integrations (pcap / Zeek / Suricata), narrative generator, CLI, API and
dashboard.

- `python3 -m pytest tests/core/ -q` — core engine
- `python3 -m pytest tests/integrations/ -q` — pcap / Zeek / Suricata
- `python3 -m pytest tests/ml/ -q` — detector and synthetic scenarios
- `python3 -m pytest tests/rules/ -q` — DSL parser and engine

Linting and typing (dev extra):

```bash
ruff check .
mypy sentinelwall
```

## Live Lab Test Plan

To validate SentinelWall against live network traffic:

1. **Capture live traffic** with tcpdump/scapy on a monitored host:
   `tcpdump -i eth0 -w lab.pcap` (leave running 30–60 min).
2. **Generate benign baseline** while capture runs: browse, SSH, `git clone`,
   and normal DNS resolution.
3. **Inject an attack scenario** with a second host running legitimate
   tooling (e.g. `nmap -sS -T4 target`, an SSH brute-forcer for 2–3 minutes,
   a beaconing C2 simulation on port 443, and an `scp`/`nc` exfil transfer).
4. **Analyze**:
   ```bash
   python3 -m sentinelwall analyze --export-dir ./lab-reports lab.pcap
   ```
5. **Validate output**:
   - `report.html` identifies the attack phases in the right order;
   - `_report.json` lists the injected MITRE techniques
     (`T1046` scan, `T1110` brute force, `T1071`/`T1572` C2, `T1048` exfil);
   - the STIX bundle (`stix_report.json`) contains attack-pattern objects for
     the detected techniques and observed-data objects for the traffic.
6. **Tune**: raise/lower thresholds via `EngineConfig(correlation_window=...)`
   and custom rules until the injected behaviour is detected with no false
   positives on the benign baseline.
7. **Regression**: re-run `pytest tests/ -q` after any threshold changes.

## Roadmap

- [x] Pure-Python pcap reader (no scapy required by default)
- [x] Zeek and Suricata EVE ingestion
- [x] Behavioral correlator (scan, beacon, brute force, lateral, exfil)
- [x] MITRE ATT&CK mapping and Navigator export
- [x] Rule DSL engine with built-in rules
- [x] STIX 2.1 export
- [x] HTML narrative report + dashboard
- [x] File capture (`--capture`) with scapy extra
- [ ] Threat-intelligence enrichment (MISP / OTX / VirusTotal lookups)
- [ ] GeoIP enrichment module
- [ ] Real-time capture daemon with alerting
- [ ] PostgreSQL/ClickHouse event sink for long-term analysis
- [ ] ATT&CK Navigator sub-technique scorecards
- [ ] Windows Event Log and Sysmon ingestion
- [ ] Plugin architecture for custom parsers and detectors

## Documentation

- `docs/rule-dsl.md` — full rule DSL reference
- `METRICS.md` — measured performance, detection accuracy and coverage numbers
- `CONTRIBUTING.md` — how to contribute
- `SECURITY.md` — reporting vulnerabilities
- `AUTHORS.md` — maintainers
- `NOTICE.md` — third-party notices and licenses

## License

SentinelWall is released under the MIT License. See [LICENSE](LICENSE).