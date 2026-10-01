"""SYN flood detection.

A SYN flood sends a large number of connection requests to one target while
(almost) never completing the handshake. For each target we track, inside a
sliding window:

* how many bare SYN packets arrived, and
* how many SYN-ACK replies the target sent back.

An alert fires when the SYN count is high *and* the target answered only a
small fraction of them (an overwhelmed or unresponsive server). A busy but
healthy server answers nearly every SYN, so it does not trigger this rule.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Deque, Dict, List, Tuple

from scapy.layers.inet import IP, TCP

from packetwatch.detectors.base import Detector
from packetwatch.models import Alert

SYN_MASK = 0x12
SYN_ONLY = 0x02
SYN_ACK = 0x12


class SynFloodDetector(Detector):
    name = "syn_flood"

    def __init__(
        self,
        threshold: int = 100,
        window: float = 5.0,
        max_synack_ratio: float = 0.5,
        cooldown: float = 60.0,
    ):
        self.threshold = threshold
        self.window = window
        self.max_synack_ratio = max_synack_ratio
        self.cooldown = cooldown
        self._syns: Dict[str, Deque[Tuple[float, str]]] = {}  # victim -> (ts, src)
        self._sources: Dict[str, Counter] = {}  # victim -> source counter
        self._synacks: Dict[str, Deque[float]] = {}  # victim -> reply timestamps
        self._last_alert: Dict[str, float] = {}

    def _expire(self, victim: str, now: float) -> None:
        syns = self._syns.get(victim)
        sources = self._sources.get(victim)
        while syns and now - syns[0][0] > self.window:
            _, old_src = syns.popleft()
            sources[old_src] -= 1
            if sources[old_src] <= 0:
                del sources[old_src]
        synacks = self._synacks.get(victim)
        while synacks and now - synacks[0] > self.window:
            synacks.popleft()

    def process(self, pkt) -> List[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        flags = int(pkt[TCP].flags)
        ts = float(pkt.time)
        ip = pkt[IP]

        if flags & SYN_MASK == SYN_ACK:
            # The *source* of a SYN-ACK is the server answering a connection request.
            self._synacks.setdefault(ip.src, deque()).append(ts)
            self._expire(ip.src, ts)
            return []

        if flags & SYN_MASK != SYN_ONLY:
            return []

        victim = ip.dst
        self._syns.setdefault(victim, deque()).append((ts, ip.src))
        self._sources.setdefault(victim, Counter())[ip.src] += 1
        self._expire(victim, ts)

        syn_count = len(self._syns[victim])
        if syn_count < self.threshold:
            return []

        synack_count = len(self._synacks.get(victim, ()))
        ratio = synack_count / syn_count
        if ratio >= self.max_synack_ratio:
            return []

        last = self._last_alert.get(victim)
        if last is not None and ts - last < self.cooldown:
            return []
        self._last_alert[victim] = ts

        sources = self._sources[victim]
        src = next(iter(sources)) if len(sources) == 1 else "multiple"
        return [
            Alert(
                timestamp=ts,
                detector=self.name,
                severity="high",
                src=src,
                dst=victim,
                description=(
                    f"Possible SYN flood: {syn_count} SYNs to {victim} in "
                    f"{self.window:g}s, only {synack_count} SYN-ACK replies"
                ),
                details={
                    "syn_count": syn_count,
                    "synack_count": synack_count,
                    "synack_ratio": round(ratio, 3),
                    "distinct_sources": len(sources),
                    "window_seconds": self.window,
                },
            )
        ]
