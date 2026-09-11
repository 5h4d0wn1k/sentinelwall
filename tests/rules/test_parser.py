"""Tests for the rule DSL parser."""

import pytest

from sentinelwall.core.events import Severity
from sentinelwall.rules.parser import Rule, RuleCondition, RuleParser


RULE_TEXT = """
rule ssh_monitor:
    meta:
        description = "Detect SSH access"
        severity = HIGH
        techniques = ["T1021", "T1133"]
        tags = ["ssh", "remote"]
    condition:
        protocol == ssh
        AND destination_port eq 22
"""


SAMPLE_RULESET = """
rule port_scan:
    meta:
        severity = MEDIUM
        techniques = ["T1046"]
    condition:
        event_type == PORT_SCAN

rule large_exfil:
    meta:
        severity = HIGH
    condition:
        payload_size > 100000
"""


class TestRuleParserBasics:
    def test_parses_single_rule(self):
        parser = RuleParser()
        rule = parser.parse(RULE_TEXT)
        assert rule.name == "ssh_monitor"
        assert rule.description == "Detect SSH access"
        assert rule.severity == Severity.HIGH
        assert rule.techniques == ["T1021", "T1133"]

    def test_rules_tracked_in_parser(self):
        parser = RuleParser()
        parser.parse(RULE_TEXT)
        assert len(parser.get_rules()) == 1

    def test_conditions_extracted(self):
        parser = RuleParser()
        rule = parser.parse(RULE_TEXT)
        assert len(rule.conditions) == 2
        assert rule.condition_logic == "and"

    def test_parse_ruleset(self):
        parser = RuleParser()
        rules = parser.parse_ruleset(SAMPLE_RULESET)
        assert len(rules) == 2

    def test_parse_file(self, tmp_path):
        path = tmp_path / "rules.swl"
        path.write_text(SAMPLE_RULESET)
        parser = RuleParser()
        rules = parser.parse_file(str(path))
        assert len(rules) == 2

    def test_parse_missing_file_raises(self, tmp_path):
        parser = RuleParser()
        with pytest.raises(OSError):
            parser.parse_file(str(tmp_path / "missing.swl"))

    def test_invalid_severity_defaults_medium(self):
        parser = RuleParser()
        rule = parser.parse(RULE_TEXT.replace("severity = HIGH", "severity = BLAH"))
        assert rule.severity == Severity.MEDIUM

    def test_unnamed_rule(self):
        parser = RuleParser()
        rule = parser.parse("condition:\n    protocol == tcp")
        assert rule.name == "unnamed_rule"


class TestOperatorParsing:
    @pytest.mark.parametrize("op", [
        ("event_type == PORT_SCAN", "event_type", "eq", "PORT_SCAN"),
        ("protocol != tcp", "protocol", "neq", "tcp"),
        ("payload_size > 100", "payload_size", "gt", 100),
        ("payload_size >= 100", "payload_size", "gte", 100),
        ("payload_size < 100", "payload_size", "lt", 100),
        ("payload_size <= 100", "payload_size", "lte", 100),
    ])
    def test_symbolic_operators(self, op):
        line, field, operator, value = op
        parser = RuleParser()
        cond = parser._parse_condition(line)
        assert cond.field == field
        assert cond.operator == operator
        assert cond.value == value

    @pytest.mark.parametrize("op", [
        ("payload_size gt 100", "gt"),
        ("payload_size eq 100", "eq"),
        ("destination_port neq 22", "neq"),
        ("payload_preview contains exe", "contains"),
        ("payload_preview not_contains virus", "not_contains"),
        ("payload_preview matches GET", "matches"),
        ("destination_port between 100 and 200", None),
    ])
    def test_word_operators(self, op):
        line, expected = op
        parser = RuleParser()
        cond = parser._parse_condition(line)
        if expected is None:
            assert cond is None
        else:
            assert cond.operator == expected

    def test_in_operator(self):
        parser = RuleParser()
        cond = parser._parse_condition("destination_port in [22, 443]")
        assert cond.operator == "in"
        assert cond.value == [22, 443]

    def test_between_operator(self):
        parser = RuleParser()
        cond = parser._parse_condition("payload_size between [1, 5]")
        assert cond.operator == "between"
        assert cond.value == [1, 5]

    def test_not_negation(self):
        parser = RuleParser()
        cond = parser._parse_condition("NOT protocol == tcp")
        assert cond.negated is True

    def test_or_condition_logic(self):
        text = """
rule r:
    or condition:
        protocol == http
        OR protocol == https
"""
        parser = RuleParser()
        rule = parser.parse(text)
        assert rule.condition_logic == "or"
        assert len(rule.conditions) == 2

    def test_condition_coercion(self):
        parser = RuleParser()
        assert parser._coerce_value('42') == 42
        assert parser._coerce_value('3.14') == 3.14
        assert parser._coerce_value('"abc"') == "abc"
        assert parser._coerce_value('TRUE') is True


class TestRuleConditionEvaluate:
    def test_eq_string_case_insensitive(self):
        cond = RuleCondition("protocol", "eq", "SSH")
        assert cond.evaluate({"protocol": "ssh"})

    def test_neq(self):
        cond = RuleCondition("destination_port", "neq", "22")
        assert cond.evaluate({"destination_port": 2222})
        assert not cond.evaluate({"destination_port": 22})

    def test_gt(self):
        cond = RuleCondition("payload_size", "gt", 1000)
        assert cond.evaluate({"payload_size": 2000})
        assert not cond.evaluate({"payload_size": 500})

    def test_contains_case_insensitive(self):
        cond = RuleCondition("payload_preview", "contains", "SELF-signed")
        assert cond.evaluate({"payload_preview": "cert self-signed"})

    def test_not_contains(self):
        cond = RuleCondition("payload_preview", "not_contains", "malware")
        assert cond.evaluate({"payload_preview": "clean"})

    def test_in_list(self):
        cond = RuleCondition("destination_port", "in", [22, 443, 3389])
        assert cond.evaluate({"destination_port": 3389})
        assert not cond.evaluate({"destination_port": 80})

    def test_between(self):
        cond = RuleCondition("payload_size", "between", [100, 500])
        assert cond.evaluate({"payload_size": 250})
        assert not cond.evaluate({"payload_size": 900})

    def test_matches_regex(self):
        cond = RuleCondition("payload_preview", "matches", r"GET /admin")
        assert cond.evaluate({"payload_preview": "GET /admin HTTP/1.1"})

    def test_missing_field_false(self):
        cond = RuleCondition("destination_port", "eq", 22)
        assert not cond.evaluate({})

    def test_negated_flips(self):
        cond = RuleCondition("protocol", "eq", "ssh", negated=True)
        assert cond.evaluate({"protocol": "tcp"})
        assert not cond.evaluate({"protocol": "ssh"})

    def test_to_dict(self):
        cond = RuleCondition("port", "eq", 22, negated=True)
        d = cond.to_dict()
        assert d == {"field": "port", "operator": "eq", "value": 22, "negated": True}


class TestRuleEvaluate:
    def test_and_logic(self):
        rule = Rule(
            name="r", description="", severity=Severity.HIGH,
            conditions=[
                RuleCondition("protocol", "eq", "ssh"),
                RuleCondition("destination_port", "eq", 22),
            ],
            condition_logic="and",
        )
        assert rule.evaluate({"protocol": "ssh", "destination_port": 22})
        assert not rule.evaluate({"protocol": "ssh", "destination_port": 80})

    def test_or_logic(self):
        rule = Rule(
            name="r", description="", severity=Severity.HIGH,
            conditions=[
                RuleCondition("protocol", "eq", "http"),
                RuleCondition("protocol", "eq", "https"),
            ],
            condition_logic="or",
        )
        assert rule.evaluate({"protocol": "http"})
        assert rule.evaluate({"protocol": "https"})
        assert not rule.evaluate({"protocol": "dns"})

    def test_disabled_rule_never_fires(self):
        rule = Rule(
            name="r", description="", severity=Severity.HIGH,
            conditions=[RuleCondition("protocol", "eq", "http")],
            enabled=False,
        )
        assert not rule.evaluate({"protocol": "http"})

    def test_no_conditions_never_fires(self):
        rule = Rule(name="r", description="", severity=Severity.HIGH)
        assert not rule.evaluate({"protocol": "http"})

    def test_unknown_logic_never_fires(self):
        rule = Rule(
            name="r", description="", severity=Severity.HIGH,
            conditions=[RuleCondition("protocol", "eq", "http")],
            condition_logic="xor",
        )
        assert not rule.evaluate({"protocol": "http"})

    def test_to_dict_complete(self):
        rule = Rule(
            name="r", description="d", severity=Severity.MEDIUM,
            conditions=[RuleCondition("p", "eq", 1)],
            tags=["a"], techniques=["T1046"],
        )
        d = rule.to_dict()
        assert d["name"] == "r"
        assert d["severity"] == "MEDIUM"
        assert d["condition_logic"] == "and"