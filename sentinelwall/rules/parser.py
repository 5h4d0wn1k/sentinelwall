"""Rule DSL parser — parses sentinelwall detection rules into executable form."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from sentinelwall.core.events import EventType, Protocol, Severity


@dataclass
class RuleCondition:
    """A single condition in a rule."""
    field: str
    operator: str
    value: Any
    negated: bool = False

    def evaluate(self, event_dict: dict[str, Any]) -> bool:
        actual = event_dict.get(self.field)
        if actual is None:
            return False
        result = self._compare(actual, self.value)
        return not result if self.negated else result

    def _compare(self, actual: Any, expected: Any) -> bool:
        if self.operator == "eq":
            if isinstance(expected, str) and isinstance(actual, str):
                return actual.lower() == expected.lower()
            return actual == expected
        if self.operator == "neq":
            return not self._compare(actual, expected)
        if self.operator == "gt":
            return float(actual) > float(expected)
        if self.operator == "gte":
            return float(actual) >= float(expected)
        if self.operator == "lt":
            return float(actual) < float(expected)
        if self.operator == "lte":
            return float(actual) <= float(expected)
        if self.operator == "contains":
            return str(expected).lower() in str(actual).lower()
        if self.operator == "not_contains":
            return str(expected).lower() not in str(actual).lower()
        if self.operator == "matches":
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        if self.operator == "in":
            if isinstance(expected, (list, tuple, set)):
                return actual in expected
            return False
        if self.operator == "between":
            if isinstance(expected, (list, tuple)) and len(expected) == 2:
                return float(expected[0]) <= float(actual) <= float(expected[1])
            return False
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "negated": self.negated,
        }


@dataclass
class Rule:
    """A complete detection rule."""
    name: str
    description: str
    severity: Severity
    conditions: list[RuleCondition] = field(default_factory=list)
    condition_logic: str = "and"
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    enabled: bool = True
    author: str = ""
    version: str = "1.0"
    false_positive_hints: list[str] = field(default_factory=list)

    def evaluate(self, event_dict: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if not self.conditions:
            return False
        if self.condition_logic == "and":
            return all(c.evaluate(event_dict) for c in self.conditions)
        if self.condition_logic == "or":
            return any(c.evaluate(event_dict) for c in self.conditions)
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.name,
            "conditions": [c.to_dict() for c in self.conditions],
            "condition_logic": self.condition_logic,
            "tags": self.tags,
            "techniques": self.techniques,
            "mitre_tactics": self.mitre_tactics,
            "enabled": self.enabled,
            "author": self.author,
            "version": self.version,
        }


class RuleParser:
    """Parses sentinelwall rule DSL syntax.

    Rule syntax:
        rule <name> {
            meta:
                description = "..."
                severity = HIGH
                techniques = ["T1046", "T1018"]
                tags = ["port-scan", "recon"]

            condition:
                event_type == PORT_SCAN
                AND destination_port > 1024
                AND payload_size < 100

            or condition:
                protocol == ssh
                AND source_port neq 22
        }

    Operators: ==, !=, >, >=, <, <=, contains, matches, in, between
    Logic: AND, OR
    Fields: protocol, event_type, severity, source_ip, destination_ip,
            source_port, destination_port, payload_size, payload_preview,
            direction, tags
    """

    VALID_OPERATORS = {
        "==", "!=", ">", ">=", "<", "<=",
        "eq", "neq", "gt", "gte", "lt", "lte",
        "contains", "not_contains", "matches", "in", "between",
    }

    OPERATOR_MAP = {
        "==": "eq", "!=": "neq", ">": "gt", ">=": "gte",
        "<": "lt", "<=": "lte",
    }

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def parse(self, rule_text: str) -> Rule:
        """Parse a single rule from text."""
        rule_text = rule_text.strip()
        name = self._extract_name(rule_text)
        meta = self._extract_meta(rule_text)
        conditions, logic = self._extract_conditions(rule_text)
        severity_str = meta.get("severity", "MEDIUM").upper()
        try:
            severity = Severity[severity_str]
        except KeyError:
            severity = Severity.MEDIUM
        techniques = meta.get("techniques", [])
        if isinstance(techniques, str):
            techniques = [t.strip() for t in techniques.strip("[]").split(",") if t.strip()]
        tags = meta.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.strip("[]").split(",") if t.strip()]
        rule = Rule(
            name=name,
            description=meta.get("description", ""),
            severity=severity,
            conditions=conditions,
            condition_logic=logic,
            tags=tags,
            techniques=techniques,
            mitre_tactics=meta.get("mitre_tactics", []),
            author=meta.get("author", ""),
            version=meta.get("version", "1.0"),
        )
        self._rules.append(rule)
        return rule

    def parse_file(self, path: str) -> list[Rule]:
        """Parse a file containing multiple rules."""
        import pathlib
        content = pathlib.Path(path).read_text()
        return self.parse_ruleset(content)

    def parse_ruleset(self, text: str) -> list[Rule]:
        """Parse multiple rules from text."""
        rules = []
        parts = re.split(r'\brule\s+', text)
        for part in parts:
            part = part.strip()
            if not part:
                continue
            rule_text = f"rule {part}"
            try:
                rule = self.parse(rule_text)
                rules.append(rule)
            except (ValueError, KeyError):
                continue
        return rules

    def get_rules(self) -> list[Rule]:
        return list(self._rules)

    def _extract_name(self, text: str) -> str:
        match = re.search(r'rule\s+(\w+)', text)
        return match.group(1) if match else "unnamed_rule"

    def _extract_meta(self, text: str) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        meta_match = re.search(r'meta:\s*(.*?)(?:condition:|$)', text, re.DOTALL)
        if not meta_match:
            return meta
        meta_block = meta_match.group(1)
        for line in meta_block.split("\n"):
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key in ("severity",):
                meta[key] = value
            elif key in ("techniques", "tags", "mitre_tactics", "false_positive_hints"):
                if value.startswith("["):
                    items = [v.strip().strip('"').strip("'") for v in value.strip("[]").split(",")]
                    meta[key] = [i for i in items if i]
                else:
                    meta[key] = [value]
            else:
                meta[key] = value
        return meta

    def _extract_conditions(self, text: str) -> tuple[list[RuleCondition], str]:
        conditions: list[RuleCondition] = []
        logic = "and"
        cond_match = re.search(r'condition:\s*(.*?)(?:}$|$)', text, re.DOTALL)
        if not cond_match:
            return conditions, logic
        cond_block = cond_match.group(1).strip()
        logic_match = re.match(r'(or|and)\s+condition:', cond_block, re.IGNORECASE)
        if logic_match:
            logic = logic_match.group(1).lower()
            cond_block = cond_block[logic_match.end():].strip()
        lines = [l.strip() for l in cond_block.split("\n") if l.strip() and l.strip() != "}"]
        for line in lines:
            line = re.sub(r'^(AND|OR)\s+', '', line, flags=re.IGNORECASE).strip()
            cond = self._parse_condition(line)
            if cond:
                conditions.append(cond)
        return conditions, logic

    def _parse_condition(self, text: str) -> RuleCondition | None:
        text = text.strip()
        if not text:
            return None
        negated = False
        if text.upper().startswith("NOT "):
            negated = True
            text = text[4:].strip()
        for op_sym, op_name in sorted(self.OPERATOR_MAP.items(), key=lambda x: -len(x[0])):
            if op_sym in text:
                parts = text.split(op_sym, 1)
                if len(parts) == 2:
                    field_name = parts[0].strip()
                    value_str = parts[1].strip()
                    return RuleCondition(
                        field=field_name,
                        operator=op_name,
                        value=self._coerce_value(value_str),
                        negated=negated,
                    )
        for op_name in ("contains", "not_contains", "matches", "in", "between"):
            pattern = rf'(\w+)\s+{op_name}\s+(.+)'
            match = re.match(pattern, text, re.IGNORECASE)
            if match:
                field_name = match.group(1)
                value_str = match.group(2).strip()
                return RuleCondition(
                    field=field_name,
                    operator=op_name,
                    value=self._coerce_value(value_str),
                    negated=negated,
                )
        return None

    def _coerce_value(self, value_str: str) -> Any:
        value_str = value_str.strip().strip('"').strip("'")
        if value_str.upper() in ("TRUE", "FALSE"):
            return value_str.upper() == "TRUE"
        try:
            return int(value_str)
        except ValueError:
            pass
        try:
            return float(value_str)
        except ValueError:
            pass
        if value_str.startswith("["):
            items = [v.strip().strip('"').strip("'") for v in value_str.strip("[]").split(",")]
            return [self._coerce_value(v) for v in items if v]
        return value_str
