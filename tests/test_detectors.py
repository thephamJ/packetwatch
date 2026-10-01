from packetwatch.detectors import (
    ArpSpoofDetector,
    DnsAnomalyDetector,
    PortScanDetector,
    SynFloodDetector,
)
from packetwatch.detectors.dns_anomaly import shannon_entropy
from tests.helpers import ack, arp_reply, dns_query, syn, synack

ATTACKER, VICTIM = "192.168.1.66", "192.168.1.20"


def feed(detector, packets):
    alerts = []
    for pkt in packets:
        alerts.extend(detector.process(pkt))
    return alerts


# ---------------------------------------------------------------- port scan --
def test_port_scan_detected():
    pkts = [syn(ATTACKER, VICTIM, 1000 + i, 100 + i * 0.1) for i in range(25)]
    alerts = feed(PortScanDetector(threshold=20, window=10), pkts)
    assert len(alerts) == 1
    assert alerts[0].detector == "port_scan"
    assert alerts[0].src == ATTACKER and alerts[0].dst == VICTIM
    assert alerts[0].details["distinct_ports"] >= 20


def test_few_ports_not_flagged():
    pkts = [syn(ATTACKER, VICTIM, 1000 + i, 100 + i) for i in range(5)]
    assert feed(PortScanDetector(threshold=20), pkts) == []


def test_slow_scan_outside_window_not_flagged():
    # 25 ports, but one every 5 seconds: never 20 inside a 10 second window.
    pkts = [syn(ATTACKER, VICTIM, 1000 + i, 100 + i * 5) for i in range(25)]
    assert feed(PortScanDetector(threshold=20, window=10), pkts) == []


def test_repeated_same_port_is_not_a_scan():
    pkts = [syn(ATTACKER, VICTIM, 443, 100 + i * 0.01) for i in range(200)]
    assert feed(PortScanDetector(threshold=20), pkts) == []


def test_port_scan_cooldown_prevents_alert_spam():
    pkts = [syn(ATTACKER, VICTIM, 1000 + i, 100 + i * 0.01) for i in range(200)]
    alerts = feed(PortScanDetector(threshold=20, window=10, cooldown=60), pkts)
    assert len(alerts) == 1


def test_established_traffic_ignored_by_port_scan():
    pkts = [ack(ATTACKER, VICTIM, 1000 + i, 100 + i * 0.01) for i in range(50)]
    assert feed(PortScanDetector(threshold=20), pkts) == []


# --------------------------------------------------------------- SYN flood ---
def test_syn_flood_detected():
    pkts = [syn(f"10.0.{i // 250}.{i % 250 + 1}", "192.168.1.50", 80, 100 + i * 0.01) for i in range(150)]
    alerts = feed(SynFloodDetector(threshold=100, window=5), pkts)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.detector == "syn_flood" and a.severity == "high"
    assert a.dst == "192.168.1.50"
    assert a.src == "multiple"
    assert a.details["synack_count"] == 0


def test_busy_but_healthy_server_not_flagged():
    pkts = []
    for i in range(150):
        ts = 100 + i * 0.01
        pkts.append(syn("10.0.0.5", "192.168.1.50", 80, ts, sport=40000 + i))
        pkts.append(synack("192.168.1.50", "10.0.0.5", 80, ts + 0.001, dport=40000 + i))
    assert feed(SynFloodDetector(threshold=100, window=5), pkts) == []


def test_syn_flood_below_threshold_not_flagged():
    pkts = [syn("10.0.0.5", "192.168.1.50", 80, 100 + i * 0.01) for i in range(50)]
    assert feed(SynFloodDetector(threshold=100), pkts) == []


def test_single_source_flood_reports_that_source():
    pkts = [syn(ATTACKER, "192.168.1.50", 80, 100 + i * 0.01) for i in range(120)]
    alerts = feed(SynFloodDetector(threshold=100), pkts)
    assert len(alerts) == 1 and alerts[0].src == ATTACKER


# ------------------------------------------------------------ ARP spoofing ---
def test_arp_spoof_detected():
    pkts = [
        arp_reply("192.168.1.1", "aa:bb:cc:00:00:01", 100),
        arp_reply("192.168.1.1", "de:ad:be:ef:00:66", 101),
    ]
    alerts = feed(ArpSpoofDetector(), pkts)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.detector == "arp_spoof" and a.severity == "high"
    assert a.details["previous_mac"] == "aa:bb:cc:00:00:01"
    assert a.details["new_mac"] == "de:ad:be:ef:00:66"


def test_consistent_arp_not_flagged():
    pkts = [arp_reply("192.168.1.1", "aa:bb:cc:00:00:01", 100 + i) for i in range(5)]
    assert feed(ArpSpoofDetector(), pkts) == []


def test_arp_probe_with_zero_sender_ignored():
    pkts = [
        arp_reply("0.0.0.0", "aa:bb:cc:00:00:01", 100),
        arp_reply("0.0.0.0", "de:ad:be:ef:00:66", 101),
    ]
    assert feed(ArpSpoofDetector(), pkts) == []


def test_arp_mac_case_insensitive():
    pkts = [
        arp_reply("192.168.1.1", "AA:BB:CC:00:00:01", 100),
        arp_reply("192.168.1.1", "aa:bb:cc:00:00:01", 101),
    ]
    assert feed(ArpSpoofDetector(), pkts) == []


def test_arp_repeated_spoof_alerts_once_per_pair():
    pkts = [arp_reply("192.168.1.1", "aa:bb:cc:00:00:01", 100)]
    pkts += [arp_reply("192.168.1.1", "de:ad:be:ef:00:66", 101 + i) for i in range(10)]
    assert len(feed(ArpSpoofDetector(), pkts)) == 1


# ------------------------------------------------------------- DNS anomaly ---
def test_normal_dns_not_flagged():
    pkts = [dns_query(n, 100 + i) for i, n in enumerate(
        ["www.example.com", "github.com", "docs.python.org", "login.microsoftonline.com"])]
    assert feed(DnsAnomalyDetector(), pkts) == []


def test_high_entropy_long_label_flagged():
    label = "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpi"
    alerts = feed(DnsAnomalyDetector(), [dns_query(f"{label}.tunnel.example.net", 100)])
    assert len(alerts) == 1
    assert alerts[0].detector == "dns_anomaly"
    assert alerts[0].dst == "example.net"


def test_very_long_name_flagged():
    name = ".".join(["a" * 20] * 6) + ".example.com"  # low entropy but 130+ chars
    alerts = feed(DnsAnomalyDetector(), [dns_query(name, 100)])
    assert len(alerts) == 1
    assert "characters long" in alerts[0].description


def test_long_but_low_entropy_label_not_flagged():
    name = "a" * 35 + ".example.com"  # long label, but repetitive (entropy 0)
    assert feed(DnsAnomalyDetector(), [dns_query(name, 100)]) == []


def test_dns_tunnel_cooldown_dedupes_per_domain():
    pkts = [dns_query(f"mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6d{i:02d}.tunnel.example.net", 100 + i)
            for i in range(20)]
    assert len(feed(DnsAnomalyDetector(cooldown=60), pkts)) == 1


def test_dns_responses_ignored():
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.20") / UDP(sport=53, dport=50000) / DNS(
        qr=1, qd=DNSQR(qname="mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpi.tunnel.example.net"))
    pkt.time = 100
    assert DnsAnomalyDetector().process(pkt) == []


def test_shannon_entropy_basics():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9
