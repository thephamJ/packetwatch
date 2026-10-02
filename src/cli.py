import argparse
from src.db import AlertDB
from src.detector import PacketWatchDetector

def main():
    parser = argparse.ArgumentParser(description="PacketWatch Network Intrusion Detector")
    parser.add_argument("pcap", help="Path to PCAP capture file")
    parser.add_argument("--db", default="alerts.db", help="Path to SQLite DB output")
    args = parser.parse_args()

    db = AlertDB(args.db)
    detector = PacketWatchDetector(db)

    print(f"[*] Parsing capture: {args.pcap}...")
    detector.analyze_pcap(args.pcap)

    print("\n" + "=" * 55)
    print(f"{'Source IP':<18} | {'Attack':<12} | {'Severity':<8} | {'Count'}")
    print("=" * 55)

    rows = db.get_summary()
    if not rows:
        print("No suspicious behavior detected.")
    else:
        for src, atk, sev, count in rows:
            print(f"{src:<18} | {atk:<12} | {sev:<8} | {count}")
    print("=" * 55)

if __name__ == "__main__":
    main()
