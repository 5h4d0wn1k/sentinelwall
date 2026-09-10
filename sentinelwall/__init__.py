"""SentinelWall — Autonomous AI-powered network threat detection engine."""

__version__ = "1.0.0"
__author__ = "5h4d0wn1k"
__license__ = "MIT"

from sentinelwall.core.engine import SentinelEngine
from sentinelwall.core.events import NetworkEvent, EventType, Severity

__all__ = ["SentinelEngine", "NetworkEvent", "EventType", "Severity", "__version__"]
