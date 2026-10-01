import json
from pathlib import Path

from scapy.utils import wrpcap

from packetwatch import db
from packetwatch.analyzer import analyze_pcap
from packetwatch.cli import main
from tests.helpers import arp_reply, dns_query, syn

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "demo_attack.pcap"


def test_demo_capture_triggers_all_four_detectors():
    alerts, packets = analyze_pcap(str(SAMPLE))
    assert packets > 500
    kinds = {a.detector for a in alerts}
    assert kinds == {"port_scan", "syn_flood", "arp_spoof", "dns_anomaly"}


def test_demo_capture_has_no_false_positives_on_benign_traffic():
    alerts, _ = analyze_pcap(str(SAMPLE))
    # Exactly one alert per injected attack (the DNS tunnel is deduped per domain).
    assert len(alerts) == 4
    assert {a.src for a in alerts if a.detector == "port_scan"} == {"192.168.1.66"}
    arp = [a for a in alerts if a.detector == "arp_spoof"][0]
    assert arp.details["ip"] == "192.168.1.1"


def test_analyze_small_pcap_from_disk(tmp_path):
    pcap = tmp_path / "t.pcap"
    pkts = [syn("1.1.1.1", "2.2.2.2", 1000 + i, 100 + i * 0.1) for i in range(30)]
    wrpcap(str(pcap), pkts)
    alerts, packets = analyze_pcap(str(pcap))
    assert packets == 30
    assert [a.detector for a in alerts] == ["port_scan"]


def test_cli_analyze_writes_database_and_report_reads_it(tmp_path, capsys):
    dbfile = str(tmp_path / "alerts.db")
    assert main(["analyze", str(SAMPLE), "--db", dbfile]) == 0
    out = capsys.readouterr().out
    assert "4 alert(s) raised" in out

    conn = db.connect(dbfile)
    assert len(db.query_alerts(conn)) == 4
    conn.close()

    assert main(["report", "--db", dbfile, "--severity", "high", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert {r["detector"] for r in rows} == {"syn_flood", "arp_spoof"}

    assert main(["summary", "--db", dbfile]) == 0
    assert "Top 10 sources" in capsys.readouterr().out


def test_cli_missing_file_returns_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.pcap"), "--no-db"]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_rejects_non_capture_file(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_text("this is not a pcap")
    assert main(["analyze", str(bad), "--no-db"]) == 2


def test_cli_threshold_tuning(tmp_path, capsys):
    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), [syn("1.1.1.1", "2.2.2.2", 1000 + i, 100 + i * 0.1) for i in range(10)])
    main(["analyze", str(pcap), "--no-db"])
    assert "0 alert(s)" in capsys.readouterr().out
    main(["analyze", str(pcap), "--no-db", "--port-scan-threshold", "5"])
    assert "1 alert(s)" in capsys.readouterr().out
