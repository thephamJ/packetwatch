"""Data models shared across PacketWatch."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

SEVERITIES = ("low", "medium", "high")


@dataclass
class Alert:
    """A single detection produced by a detector."""

    timestamp: float  # packet time (Unix seconds) that triggered the alert
    detector: str  # e.g. "port_scan"
    severity: str  # one of SEVERITIES
    src: str  # offending IP or MAC address
    description: str  # short human-readable summary
    dst: Optional[str] = None  # target, when there is one
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
