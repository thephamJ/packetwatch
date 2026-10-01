"""DNS anomaly detection (possible DNS tunneling / data exfiltration).

DNS tunneling tools smuggle data inside query names, which tends to produce
very long names or long, random-looking labels such as
``mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpi.evil.example``.

Two heuristics are applied to each outbound query:

1. the whole query name is unusually long, or
2. the longest label is long *and* has high Shannon entropy (random-looking).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Tuple

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP

from packetwatch.detectors.base import Detector
from packetwatch.models import Alert


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class DnsAnomalyDetector(Detector):
    name = "dns_anomaly"

    def __init__(
        self,
        max_name_length: int = 100,
        min_label_length: int = 30,
        entropy_threshold: float = 3.5,
        cooldown: float = 60.0,
    ):
        self.max_name_length = max_name_length
        self.min_label_length = min_label_length
        self.entropy_threshold = entropy_threshold
        self.cooldown = cooldown
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def process(self, pkt) -> List[Alert]:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return []
        if pkt[DNS].qr != 0:  # only look at queries, not responses
            return []

        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="ignore")
        qname = qname.rstrip(".").lower()
        if not qname:
            return []

        labels = qname.split(".")
        longest = max(labels, key=len)
        entropy = shannon_entropy(longest)

        reasons = []
        if len(qname) >= self.max_name_length:
            reasons.append(f"query name is {len(qname)} characters long")
        if len(longest) >= self.min_label_length and entropy >= self.entropy_threshold:
            reasons.append(
                f"{len(longest)}-char label with high entropy ({entropy:.2f} bits/char)"
            )
        if not reasons:
            return []

        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        base_domain = ".".join(labels[-2:])
        ts = float(pkt.time)

        key = (src, base_domain)
        last = self._last_alert.get(key)
        if last is not None and ts - last < self.cooldown:
            return []
        self._last_alert[key] = ts

        return [
            Alert(
                timestamp=ts,
                detector=self.name,
                severity="medium",
                src=src,
                dst=base_domain,
                description=f"Suspicious DNS query to {base_domain}: " + "; ".join(reasons),
                details={
                    "query_name": qname[:200],
                    "name_length": len(qname),
                    "longest_label_length": len(longest),
                    "label_entropy": round(entropy, 3),
                },
            )
        ]
