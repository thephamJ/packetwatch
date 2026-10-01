# PacketWatch

A lightweight network intrusion detection tool written in Python. PacketWatch reads packet
captures (or sniffs live traffic on a network you own), flags common attack patterns, and
stores every alert in a SQLite database you can query.

![tests](https://github.com/thephamJ/packetwatch/actions/workflows/ci.yml/badge.svg)

## What it detects

| Detector | Severity | Signal |
|---|---|---|
| **Port scan** | medium | One source sends bare TCP SYNs to many *distinct* ports on one target inside a sliding window (default: 20 ports / 10 s). |
| **SYN flood** | high | Many SYNs hit one target in a short window (default: 100 / 5 s) while the target answers fewer than half of them with SYN-ACK. |
| **ARP spoofing** | high | An IP address that was seen with one MAC address suddenly appears with a different MAC. |
| **DNS anomaly** (possible tunneling) | medium | A query name is very long (100+ chars), or its longest label is long (30+ chars) *and* random-looking (Shannon entropy of 3.5+ bits/char). |

Thresholds for port scans and SYN floods are tunable from the command line.

## Quick start

```bash
git clone https://github.com/thephamJ/packetwatch.git
cd packetwatch
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Analyze the bundled demo capture (a synthetic file with benign traffic plus one of each attack):

```console
$ packetwatch analyze samples/demo_attack.pcap
Analyzed 563 packets from samples/demo_attack.pcap
2025-10-09 08:54:00 [MEDIUM] port_scan   192.168.1.66       Port scan: 20 distinct ports probed on 192.168.1.20 within 10s
2025-10-09 08:54:20 [HIGH  ] syn_flood   multiple           Possible SYN flood: 100 SYNs to 192.168.1.50 in 5s, only 0 SYN-ACK replies
2025-10-09 08:54:41 [HIGH  ] arp_spoof   de:ad:be:ef:00:66  ARP spoofing: 192.168.1.1 changed from aa:bb:cc:00:00:01 to de:ad:be:ef:00:66
2025-10-09 08:55:00 [MEDIUM] dns_anomaly 192.168.1.20       Suspicious DNS query to example.net: 48-char label with high entropy (4.53 bits/char)
4 alert(s) raised.
Saved to packetwatch.db
```

(You can also run it without installing: `python -m packetwatch analyze samples/demo_attack.pcap`.)

## Usage

```bash
# Analyze a capture file (.pcap or .pcapng) and save alerts to SQLite
packetwatch analyze capture.pcap --db alerts.db

# Tune sensitivity
packetwatch analyze capture.pcap --port-scan-threshold 10 --syn-flood-threshold 50

# Machine-readable output
packetwatch analyze capture.pcap --json --no-db

# Query saved alerts
packetwatch report --db alerts.db --severity high
packetwatch report --db alerts.db --detector port_scan --src 192.168.1.66
packetwatch report --db alerts.db --since 2026-10-01 --until 2026-10-02T12:00:00

# Counts per detector and the noisiest sources
packetwatch summary --db alerts.db --top 5

# Live monitoring (needs root/administrator; only on networks you own or are authorized to test)
sudo packetwatch live --iface eth0 --filter "tcp or arp or udp port 53"
```

Because alerts live in plain SQLite, you can also query them directly:

```sql
-- Top 10 sources by alert count
SELECT src, COUNT(*) AS alerts
FROM alerts
GROUP BY src
ORDER BY alerts DESC
LIMIT 10;

-- High-severity alerts against one target
SELECT datetime(ts, 'unixepoch') AS time, detector, src, description
FROM alerts
WHERE severity = 'high' AND dst = '192.168.1.50'
ORDER BY ts;
```

## Project layout

```
packetwatch/
├── packetwatch/
│   ├── cli.py             # argparse CLI: analyze / live / report / summary
│   ├── analyzer.py        # streams packets through the detectors
│   ├── db.py              # SQLite schema + parameterized queries
│   ├── models.py          # Alert dataclass
│   └── detectors/
│       ├── port_scan.py
│       ├── syn_flood.py
│       ├── arp_spoof.py
│       └── dns_anomaly.py
├── tests/                 # pytest suite (detectors, database, end-to-end CLI)
├── scripts/generate_sample_pcap.py   # rebuilds samples/demo_attack.pcap
└── samples/demo_attack.pcap
```

## How it works

Each detector is a small stateful class with a single method, `process(packet)`, that returns
zero or more `Alert` objects. Detectors keep sliding windows (a `deque` of timestamps plus a
`Counter`) so memory use per host stays proportional to the window rather than the whole
capture. Captures are read packet by packet with Scapy's `PcapReader`, so large files do not
have to fit in memory. A detector that errors on a malformed packet is skipped for that
packet instead of crashing the run.

To add a detector, subclass `Detector`, implement `process`, and register it in
`analyzer.default_detectors`.

## Testing

```bash
pytest -q
```

The suite covers each detector's positive case, negative cases (slow scans, healthy servers,
repeated ports, ARP probes, benign DNS), alert de-duplication, the database layer
(including a SQL-injection check on the filters), and the CLI end to end against the demo
capture.

Regenerate the demo capture with:

```bash
python scripts/generate_sample_pcap.py samples/demo_attack.pcap
```

## Validation

- **Unit tests:** 35 automated tests (pytest) cover each detector's positive case, negative cases
  (slow scans, healthy servers, repeated ports, ARP probes, benign DNS), alert de-duplication,
  the SQLite layer, and the CLI end to end. They run on every push via GitHub Actions.
- **Synthetic attack capture:** `samples/demo_attack.pcap` contains 563 packets of normal
  traffic plus one port scan, SYN flood, ARP spoofing attempt, and DNS tunneling burst.
  PacketWatch raises exactly four alerts, one per attack, with no alerts on the normal traffic.

## Limitations

This is a learning project, not a replacement for Snort, Suricata, or Zeek.

- **IPv4 only.** IPv6 traffic is not analyzed yet.
- **Heuristics, not signatures.** Thresholds are simple and global; busy networks will need tuning, and a slow "low and slow" scan stays under the window.
- **SYN flood rule assumes visibility of replies.** It compares SYNs to SYN-ACKs, so captures taken on a segment that sees only one direction of traffic can mislead it.
- **ARP alerts can be false positives** on networks with legitimate failover (VRRP/HSRP) or hardware swaps.
- **DNS heuristics** can flag some legitimate long, machine-generated names (certain CDNs and security products).
- State is kept in memory per run; very long live sessions with huge numbers of distinct hosts will grow it.

## Roadmap

- IPv6 support
- Horizontal scan detection (one port across many hosts)
- Configurable thresholds via a config file
- Port the packet-parsing hot path to C++ or Rust for throughput

## Responsible use

PacketWatch only *reads* traffic. Use live mode and any lab testing on networks and systems
you own or have written authorization to monitor. The bundled sample capture is entirely
synthetic.

## License

MIT. See [LICENSE](LICENSE).
