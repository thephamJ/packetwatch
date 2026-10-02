import pytest
from scapy.all import IP, TCP, Ether, wrpcap
from src.db import AlertDB
from src.detector import PacketWatchDetector

@pytest.fixture
def temp_detector(tmp_path):
    db_file = tmp_path / "test_alerts.db"
    db = AlertDB(str(db_file))
    return PacketWatchDetector(db), db

def test_port_scan_detection(temp_detector, tmp_path):
    detector, db = temp_detector
    pcap_path = tmp_path / "scan.pcap"

    packets = [
        Ether() / IP(src="192.168.56.102", dst="192.168.56.101") / TCP(dport=p, flags="S")
        for p in range(1, 26)
    ]
    wrpcap(str(pcap_path), packets)

    detector.analyze_pcap(str(pcap_path))
    summary = db.get_summary()

    assert any(row[1] == "PORT_SCAN" for row in summary)
