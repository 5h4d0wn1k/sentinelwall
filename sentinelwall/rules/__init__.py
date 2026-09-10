"""Custom detection rule engine with YARA-like DSL."""

from sentinelwall.rules.engine import RuleEngine
from sentinelwall.rules.parser import RuleParser, Rule
from sentinelwall.rules.builtin import BUILTIN_RULES

__all__ = ["RuleEngine", "RuleParser", "Rule", "BUILTIN_RULES"]
