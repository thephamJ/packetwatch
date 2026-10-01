"""Glue between packet sources and detectors."""

from __future__ import annotations

from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from scapy.utils import PcapReader

from packetwatch.detectors import (
    ArpSpoofDetector,
    Detector,
    DnsAnomalyDetector,
    PortScanDetector,
    SynFloodDetector,
)
from packetwatch.models import Alert


def default_detectors(**overrides) -> List[Detector]:
    """Build the standard detector set.

    ``overrides`` may contain any of: port_scan_threshold, port_scan_window,
    syn_flood_threshold, syn_flood_window.
    """
    ps_kwargs, sf_kwargs = {}, {}
    if "port_scan_threshold" in overrides:
        ps_kwargs["threshold"] = overrides["port_scan_threshold"]
    if "port_scan_window" in overrides:
        ps_kwargs["window"] = overrides["port_scan_window"]
    if "syn_flood_threshold" in overrides:
        sf_kwargs["threshold"] = overrides["syn_flood_threshold"]
    if "syn_flood_window" in overrides:
        sf_kwargs["window"] = overrides["syn_flood_window"]
    return [
        PortScanDetector(**ps_kwargs),
        SynFloodDetector(**sf_kwargs),
        ArpSpoofDetector(),
        DnsAnomalyDetector(),
    ]


def run_detectors(pkt, detectors: Sequence[Detector]) -> List[Alert]:
    """Feed one packet to every detector. A failing detector never stops the others."""
    alerts: List[Alert] = []
    for detector in detectors:
        try:
            alerts.extend(detector.process(pkt))
        except Exception:  # malformed packets should not crash a long capture
            continue
    return alerts


def analyze_packets(packets: Iterable, detectors: Sequence[Detector]) -> Tuple[List[Alert], int]:
    alerts: List[Alert] = []
    count = 0
    for pkt in packets:
        count += 1
        alerts.extend(run_detectors(pkt, detectors))
    return alerts, count


def analyze_pcap(path: str, detectors: Optional[Sequence[Detector]] = None) -> Tuple[List[Alert], int]:
    """Stream a .pcap/.pcapng file through the detectors.

    Returns ``(alerts, packet_count)``. The file is read packet by packet, so
    large captures do not need to fit in memory.
    """
    detectors = detectors if detectors is not None else default_detectors()
    with PcapReader(path) as reader:
        return analyze_packets(reader, detectors)


def analyze_live(
    iface: Optional[str],
    detectors: Sequence[Detector],
    on_alert: Callable[[Alert], None],
    timeout: Optional[int] = None,
    bpf_filter: Optional[str] = None,
) -> int:
    """Sniff live traffic (requires root/administrator privileges)."""
    from scapy.sendrecv import sniff

    seen = {"packets": 0}

    def handle(pkt):
        seen["packets"] += 1
        for alert in run_detectors(pkt, detectors):
            on_alert(alert)

    sniff(iface=iface, prn=handle, store=False, timeout=timeout, filter=bpf_filter)
    return seen["packets"]
