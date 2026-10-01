"""Port scan detection.

Flags a source that sends TCP SYN packets to many *distinct* ports on the
same target inside a short sliding window. This catches the classic
"vertical" scan produced by tools such as ``nmap -sS``.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Deque, Dict, List, Tuple

from scapy.layers.inet import IP, TCP

from packetwatch.detectors.base import Detector
from packetwatch.models import Alert

SYN_MASK = 0x12  # SYN + ACK bits
SYN_ONLY = 0x02


class PortScanDetector(Detector):
    name = "port_scan"

    def __init__(self, threshold: int = 20, window: float = 10.0, cooldown: float = 60.0):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        # (src, dst) -> sliding window of (timestamp, dport) plus a port counter
        self._events: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = {}
        self._ports: Dict[Tuple[str, str], Counter] = {}
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def process(self, pkt) -> List[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        tcp = pkt[TCP]
        if int(tcp.flags) & SYN_MASK != SYN_ONLY:  # only bare SYNs (connection attempts)
            return []

        ts = float(pkt.time)
        key = (pkt[IP].src, pkt[IP].dst)
        events = self._events.setdefault(key, deque())
        ports = self._ports.setdefault(key, Counter())

        events.append((ts, tcp.dport))
        ports[tcp.dport] += 1

        # Drop events that fell out of the sliding window.
        while events and ts - events[0][0] > self.window:
            _, old_port = events.popleft()
            ports[old_port] -= 1
            if ports[old_port] <= 0:
                del ports[old_port]

        distinct = len(ports)
        if distinct < self.threshold:
            return []

        last = self._last_alert.get(key)
        if last is not None and ts - last < self.cooldown:
            return []
        self._last_alert[key] = ts

        return [
            Alert(
                timestamp=ts,
                detector=self.name,
                severity="medium",
                src=key[0],
                dst=key[1],
                description=(
                    f"Port scan: {distinct} distinct ports probed on {key[1]} "
                    f"within {self.window:g}s"
                ),
                details={
                    "distinct_ports": distinct,
                    "window_seconds": self.window,
                    "sample_ports": sorted(ports)[:10],
                },
            )
        ]
