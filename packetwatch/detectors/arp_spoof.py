"""ARP spoofing detection.

Builds an IP -> MAC table from ARP traffic. If an IP address that was
previously seen with one MAC suddenly appears with a different MAC, an
attacker may be poisoning ARP caches to sit in the middle of a conversation.

Known false positives: legitimate failover (VRRP/HSRP), NIC replacement, and
DHCP re-assignment can also change an IP's MAC. Treat alerts as leads to
investigate, not proof.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from scapy.layers.l2 import ARP

from packetwatch.detectors.base import Detector
from packetwatch.models import Alert


class ArpSpoofDetector(Detector):
    name = "arp_spoof"

    def __init__(self):
        self._table: Dict[str, str] = {}  # ip -> last known mac
        self._reported: Set[Tuple[str, str]] = set()  # (ip, new_mac) already alerted

    def process(self, pkt) -> List[Alert]:
        if not pkt.haslayer(ARP):
            return []
        arp = pkt[ARP]
        ip = str(arp.psrc)
        mac = str(arp.hwsrc).lower()

        if ip in ("", "0.0.0.0"):  # ARP probes carry no sender IP
            return []

        known = self._table.get(ip)
        if known is None:
            self._table[ip] = mac
            return []
        if known == mac:
            return []

        self._table[ip] = mac
        if (ip, mac) in self._reported:
            return []
        self._reported.add((ip, mac))

        return [
            Alert(
                timestamp=float(pkt.time),
                detector=self.name,
                severity="high",
                src=mac,
                dst=ip,
                description=f"ARP spoofing: {ip} changed from {known} to {mac}",
                details={"ip": ip, "previous_mac": known, "new_mac": mac, "arp_op": int(arp.op)},
            )
        ]
