"""Command-line interface for PacketWatch."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import List, Optional

from packetwatch import __version__, db
from packetwatch.analyzer import analyze_live, analyze_pcap, default_detectors
from packetwatch.models import Alert

SEVERITY_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}
RESET = "\033[0m"


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def colorize(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_alert(alert: Alert) -> None:
    sev = colorize(f"[{alert.severity.upper():6}]", alert.severity)
    print(f"{fmt_time(alert.timestamp)} {sev} {alert.detector:<11} {alert.src:<18} {alert.description}")


def parse_when(value: str) -> float:
    """Accept a Unix timestamp or an ISO date/time (interpreted as UTC)."""
    try:
        return float(value)
    except ValueError:
        pass
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def detector_options(args) -> dict:
    opts = {}
    for name in ("port_scan_threshold", "port_scan_window", "syn_flood_threshold", "syn_flood_window"):
        value = getattr(args, name, None)
        if value is not None:
            opts[name] = value
    return opts


def cmd_analyze(args) -> int:
    detectors = default_detectors(**detector_options(args))
    try:
        alerts, packets = analyze_pcap(args.pcap, detectors)
    except FileNotFoundError:
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        return 2
    except Exception as exc:  # unreadable / not a capture file
        print(f"error: could not read {args.pcap}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        print(f"Analyzed {packets} packets from {args.pcap}")
        for alert in alerts:
            print_alert(alert)
        print(f"{len(alerts)} alert(s) raised.")

    if not args.no_db:
        conn = db.connect(args.db)
        db.insert_alerts(conn, alerts, source=args.pcap)
        conn.close()
        if not args.json:
            print(f"Saved to {args.db}")
    return 0


def cmd_live(args) -> int:
    detectors = default_detectors(**detector_options(args))
    conn = db.connect(args.db)

    def on_alert(alert: Alert) -> None:
        print_alert(alert)
        db.insert_alerts(conn, [alert], source=f"live:{args.iface or 'default'}")

    print("Sniffing... press Ctrl+C to stop. (Only monitor networks you own or are authorized to test.)")
    try:
        packets = analyze_live(args.iface, detectors, on_alert, timeout=args.timeout, bpf_filter=args.filter)
    except PermissionError:
        print("error: live capture needs root/administrator privileges.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        packets = None
    finally:
        conn.close()
    if packets is not None:
        print(f"Capture finished after {packets} packets.")
    return 0


def cmd_report(args) -> int:
    conn = db.connect(args.db)
    since = parse_when(args.since) if args.since else None
    until = parse_when(args.until) if args.until else None
    rows = db.query_alerts(
        conn, detector=args.detector, severity=args.severity, src=args.src,
        since=since, until=until, limit=args.limit,
    )
    if args.json:
        for row in rows:
            row["details"] = json.loads(row["details"])
        print(json.dumps(rows, indent=2))
    else:
        if not rows:
            print("No alerts match those filters.")
        for row in rows:
            alert = Alert(row["ts"], row["detector"], row["severity"], row["src"],
                          row["description"], row["dst"])
            print_alert(alert)
    conn.close()
    return 0


def cmd_summary(args) -> int:
    conn = db.connect(args.db)
    print("Alerts by detector")
    for row in db.counts_by_detector(conn):
        print(f"  {row['detector']:<12} {row['alert_count']}")
    print(f"\nTop {args.top} sources")
    for row in db.top_sources(conn, args.top):
        print(f"  {row['src']:<20} {row['alert_count']:>3} alert(s), worst: {row['worst_severity']}")
    conn.close()
    return 0


def add_detector_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("detector tuning")
    group.add_argument("--port-scan-threshold", type=int, dest="port_scan_threshold",
                       help="distinct ports within the window that count as a scan (default 20)")
    group.add_argument("--port-scan-window", type=float, dest="port_scan_window",
                       help="port scan window in seconds (default 10)")
    group.add_argument("--syn-flood-threshold", type=int, dest="syn_flood_threshold",
                       help="SYNs to one host within the window that count as a flood (default 100)")
    group.add_argument("--syn-flood-window", type=float, dest="syn_flood_window",
                       help="SYN flood window in seconds (default 5)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packetwatch",
        description="Lightweight network intrusion detection for packet captures and live traffic.",
    )
    parser.add_argument("--version", action="version", version=f"packetwatch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="analyze a .pcap/.pcapng file")
    p.add_argument("pcap")
    p.add_argument("--db", default="packetwatch.db", help="SQLite database path (default packetwatch.db)")
    p.add_argument("--no-db", action="store_true", help="do not write alerts to the database")
    p.add_argument("--json", action="store_true", help="print alerts as JSON")
    add_detector_args(p)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("live", help="analyze live traffic (needs root)")
    p.add_argument("--iface", help="network interface (default: scapy's default)")
    p.add_argument("--timeout", type=int, help="stop after N seconds")
    p.add_argument("--filter", help="BPF capture filter, e.g. 'tcp or arp or udp port 53'")
    p.add_argument("--db", default="packetwatch.db")
    add_detector_args(p)
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("report", help="query saved alerts")
    p.add_argument("--db", default="packetwatch.db")
    p.add_argument("--detector", choices=["port_scan", "syn_flood", "arp_spoof", "dns_anomaly"])
    p.add_argument("--severity", choices=["low", "medium", "high"])
    p.add_argument("--src", help="exact source address to filter on")
    p.add_argument("--since", help="Unix time or ISO date/time (UTC)")
    p.add_argument("--until", help="Unix time or ISO date/time (UTC)")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("summary", help="alert counts and top offending sources")
    p.add_argument("--db", default="packetwatch.db")
    p.add_argument("--top", type=int, default=10)
    p.set_defaults(func=cmd_summary)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
