import json

import pytest

from packetwatch import db
from packetwatch.models import Alert


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    alerts = [
        Alert(100.0, "port_scan", "medium", "10.0.0.1", "scan", dst="10.0.0.9", details={"distinct_ports": 30}),
        Alert(200.0, "syn_flood", "high", "10.0.0.1", "flood", dst="10.0.0.9"),
        Alert(300.0, "dns_anomaly", "medium", "10.0.0.2", "dns", dst="evil.net"),
        Alert(400.0, "arp_spoof", "high", "aa:bb:cc:dd:ee:ff", "arp"),
    ]
    db.insert_alerts(c, alerts, source="test.pcap")
    yield c
    c.close()


def test_insert_and_roundtrip(conn):
    rows = db.query_alerts(conn)
    assert len(rows) == 4
    assert rows[0]["detector"] == "arp_spoof"  # newest first
    scan = [r for r in rows if r["detector"] == "port_scan"][0]
    assert json.loads(scan["details"]) == {"distinct_ports": 30}
    assert scan["source"] == "test.pcap"


def test_filters(conn):
    assert len(db.query_alerts(conn, detector="port_scan")) == 1
    assert len(db.query_alerts(conn, severity="high")) == 2
    assert len(db.query_alerts(conn, src="10.0.0.1")) == 2
    assert len(db.query_alerts(conn, since=250)) == 2
    assert len(db.query_alerts(conn, until=150)) == 1
    assert len(db.query_alerts(conn, severity="high", src="10.0.0.1")) == 1
    assert len(db.query_alerts(conn, limit=2)) == 2


def test_sql_injection_attempt_is_treated_as_data(conn):
    assert db.query_alerts(conn, src="' OR '1'='1") == []
    assert db.query_alerts(conn, detector="x'; DROP TABLE alerts;--") == []
    assert len(db.query_alerts(conn)) == 4  # table still intact


def test_top_sources(conn):
    top = db.top_sources(conn, limit=2)
    assert top[0] == {"src": "10.0.0.1", "alert_count": 2, "worst_severity": "high"}
    assert len(top) == 2


def test_counts_by_detector(conn):
    counts = {r["detector"]: r["alert_count"] for r in db.counts_by_detector(conn)}
    assert counts == {"port_scan": 1, "syn_flood": 1, "dns_anomaly": 1, "arp_spoof": 1}


def test_invalid_severity_rejected():
    c = db.connect(":memory:")
    with pytest.raises(Exception):
        db.insert_alerts(c, [Alert(1.0, "x", "catastrophic", "a", "b")])
