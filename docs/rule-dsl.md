# SentinelWall Rule DSL Reference

Rules use the SentinelWall DSL and live in `.swl` files. A rule file may
contain multiple rules. Load custom rules with `--rules rules.swl` or via
`SentinelWall(rules_path="rules.swl")`.

## File Structure

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
```

## Meta Keys

| Key | Type | Default | Example |
|---|---|---|---|
| `description` | string | `""` | `"Detect SSH access"` |
| `severity` | enum | `MEDIUM` | `HIGH` / `CRITICAL` / `LOW` |
| `techniques` | list | `[]` | `["T1021", "T1133"]` |
| `tags` | list | `[]` | `["ssh", "remote"]` |
| `mitre_tactics` | list | `[]` | `["lateral-movement"]` |
| `author` | string | `""` | `"5h4d0wn1k"` |
| `version` | string | `"1.0"` | `"2.1"` |

Unknown keys are stored verbatim. An invalid `severity` falls back to `MEDIUM`.

## Conditions

Conditions are one per line. Lines are AND-combined by default. Prefix a line
with `OR`/`AND`, or use `or condition:` / `and condition:` to switch the
combine logic for the whole block.

```rule
rule port_scan_or_smb:
    or condition:
        event_type == PORT_SCAN
        OR destination_port == 445
```

### Operators

| Symbolic | Word | Behavior |
|---|---|---|
| `==` / `eq` | equal | strings compared case-insensitively; coercion for int/float/bool |
| `!=` / `neq` | not equal | negation of `eq` |
| `>` / `gt` | greater than | numeric comparison |
| `>=` / `gte` | greater than or equal | numeric comparison |
| `<` / `lt` | less than | numeric comparison |
| `<=` / `lte` | less than or equal | numeric comparison |
| `contains` | substring (case-insensitive) | string search |
| `not_contains` | substring absent | string search |
| `matches` | regex search | `re.search(..., re.IGNORECASE)` |
| `in` | membership in list | `destination_port in [22, 443, 3389]` |
| `between` | inclusive numeric range | `payload_size between [1000, 5000]` |

### Negation

Prefix any condition with `NOT `:

```rule
rule non_standard_ssh:
    condition:
        protocol == ssh
        AND NOT destination_port == 22
```

### Fields

| Field | Type |
|---|---|
| `event_type` | string (`PORT_SCAN`, `AUTH_FAILURE`, `C2_BEACON`, …) |
| `protocol` | string (`tcp`, `udp`, `ssh`, `http`, `https`, `dns`, `smb`, …) |
| `severity` | `INFORMATIONAL` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `source_ip` | string |
| `destination_ip` | string |
| `source_port` | int |
| `destination_port` | int |
| `payload_size` | int |
| `payload_preview` | string |
| `direction` | `inbound` / `outbound` |
| `tags` | list of strings |

Multiple field/operator combinations may be mixed freely; conditions are
evaluated as `RuleCondition` objects with the semantics above.

## Example Rules

```rule
rule brute_force_auth_failure:
    meta:
        description = "Authentication failure detected — potential brute force attempt"
        severity = HIGH
        techniques = ["T1110"]
        tags = ["brute-force", "credential-access"]
    condition:
        event_type == AUTH_FAILURE

rule large_exfil:
    meta:
        description = "Large encrypted transfer — possible data exfiltration"
        severity = HIGH
        techniques = ["T1048"]
        tags = ["exfiltration"]
    condition:
        event_type == ENCRYPTED_TRANSFER
        AND payload_size > 100000

rule c2_beacon:
    meta:
        description = "Regular outbound beacon detected"
        severity = CRITICAL
        techniques = ["T1071", "T1572"]
        tags = ["c2", "command-and-control"]
    condition:
        event_type == C2_BEACON
```

## CLI

```bash
python3 -m sentinelwall rules  list                         # list built-ins
python3 -m sentinelwall rules  validate rules.swl           # validate a file
python3 -m sentinelwall analyze --rules rules.swl capture.pcap
```

## Parsing Rules

- `RuleParser().parse(text)` — parse a single rule
- `RuleParser().parse_ruleset(text)` — parse many rules
- `RuleParser().parse_file(path)` — parse a `.swl` file

Rules are `Rule` dataclasses with `conditions: list[RuleCondition]`, each
`RuleCondition(field, operator, value, negated)`. Evaluation is done with
`rule.evaluate(event_dict)`.