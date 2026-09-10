"""Rule engine — evaluates events against detection rules."""

from __future__ import annotations

from typing import Any

from sentinelwall.core.events import NetworkEvent
from sentinelwall.rules.builtin import BUILTIN_RULES
from sentinelwall.rules.parser import Rule, RuleParser


class RuleEngine:
    """Evaluates network events against detection rules.

    Supports both built-in rules and custom rules loaded from files.
    Rules use a YARA-like DSL with field matching, pattern detection,
    and boolean logic.
    """

    def __init__(self) -> None:
        self._parser = RuleParser()
        self._rules: list[Rule] = list(BUILTIN_RULES)
        self._custom_rules: list[Rule] = []

    def load_rules_from_file(self, path: str) -> int:
        """Load rules from a file. Returns number of rules loaded."""
        rules = self._parser.parse_file(path)
        self._custom_rules.extend(rules)
        return len(rules)

    def load_rules_from_string(self, text: str) -> int:
        """Load rules from a string. Returns number of rules loaded."""
        rules = self._parser.parse_ruleset(text)
        self._custom_rules.extend(rules)
        return len(rules)

    def add_rule(self, rule: Rule) -> None:
        """Add a single rule programmatically."""
        self._custom_rules.append(rule)

    def evaluate(self, event: NetworkEvent) -> list[dict[str, Any]]:
        """Evaluate an event against all rules. Returns list of matches."""
        matches = []
        event_dict = self._event_to_dict(event)
        all_rules = self._rules + self._custom_rules
        for rule in all_rules:
            if rule.evaluate(event_dict):
                matches.append({
                    "rule_name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity.name,
                    "techniques": rule.techniques,
                    "tags": rule.tags,
                    "mitre_tactics": rule.mitre_tactics,
                    "false_positive_hints": rule.false_positive_hints,
                })
        return matches

    def get_rules(self) -> list[Rule]:
        return list(self._rules) + list(self._custom_rules)

    def get_builtin_rules(self) -> list[Rule]:
        return list(self._rules)

    def get_custom_rules(self) -> list[Rule]:
        return list(self._custom_rules)

    def _event_to_dict(self, event: NetworkEvent) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "protocol": event.protocol.value,
            "event_type": event.event_type.name,
            "severity": event.severity.name,
            "payload_size": event.payload_size,
            "payload_preview": event.payload_preview,
            "direction": event.direction,
            "tags": event.tags,
            "confidence": event.confidence,
            "is_encrypted": event.is_encrypted,
            "lateral_movement_candidate": event.lateral_movement_candidate,
            "metadata": event.metadata,
        }
