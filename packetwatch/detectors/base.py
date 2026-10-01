"""Base class for all detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from packetwatch.models import Alert


class Detector(ABC):
    """A detector inspects packets one at a time and may emit alerts.

    Detectors are stateful: they keep whatever per-host history they need
    (sliding windows, address tables, ...) between calls to ``process``.
    Packets are expected in capture order (non-decreasing timestamps).
    """

    name = "base"

    @abstractmethod
    def process(self, pkt) -> List[Alert]:
        """Inspect one scapy packet and return zero or more alerts."""
