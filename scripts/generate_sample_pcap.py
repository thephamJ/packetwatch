#!/usr/bin/env python3
"""Generate a synthetic demo capture containing benign traffic plus four attacks.

Everything here is fabricated with Scapy and written to a file; nothing is
sent on the network. Run:

    python scripts/generate_sample_pcap.py samples/demo_attack.pcap
"""

import random
import sys

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

random.seed(1337)  # reproducible output

GATEWAY_IP, GATEWAY_MAC = "192.168.1.1", "aa:bb:cc:00:00:01"
VICTIM_IP, VICTIM_MAC = "192.168.1.20", "aa:bb:cc:00:00:20"
ATTACKER_IP, ATTACKER_MAC = "192.168.1.66", "de:ad:be:ef:00:66"
WEB_SERVER = "192.168.1.50"
T0 = 1_760_000_000.0  # fixed start time (Unix seconds)

packets = []


def add(pkt, ts):
    pkt.time = ts
    packets.append(pkt)


def tcp(src, dst, dport, flags, sport=None):
    return (Ether() / IP(src=src, dst=dst) /
            TCP(sport=sport or random.randint(1025, 65000), dport=dport, flags=flags))


def dns_query(src, name):
    return (Ether() / IP(src=src, dst="8.8.8.8") /
            UDP(sport=random.randint(1025, 65000), dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))


# --- Benign traffic: normal handshakes, ARP, and everyday DNS lookups ----------
t = T0
for i in range(30):
    t += random.uniform(0.2, 1.0)
    sport = 40000 + i
    add(tcp(VICTIM_IP, WEB_SERVER, 443, "S", sport), t)
    add(tcp(WEB_SERVER, VICTIM_IP, sport, "SA", 443), t + 0.01)
    add(tcp(VICTIM_IP, WEB_SERVER, 443, "A", sport), t + 0.02)
for name in ("www.example.com", "github.com", "docs.python.org", "login.microsoftonline.com"):
    t += 0.5
    add(dns_query(VICTIM_IP, name), t)
add(Ether(src=GATEWAY_MAC, dst=VICTIM_MAC) / ARP(op=2, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC, hwdst=VICTIM_MAC, pdst=VICTIM_IP), t + 1)

# --- Attack 1: port scan (attacker probes 60 ports on the victim in ~3 s) -------
t = T0 + 40
for port in random.sample(range(1, 1024), 60):
    t += 0.05
    add(tcp(ATTACKER_IP, VICTIM_IP, port, "S"), t)

# --- Attack 2: SYN flood (spoofed sources hammer the web server, no replies) ----
t = T0 + 60
for _ in range(400):
    t += 0.005
    spoofed = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    add(tcp(spoofed, WEB_SERVER, 80, "S"), t)

# --- Attack 3: ARP spoofing (attacker claims to be the gateway) -----------------
t = T0 + 80
for _ in range(3):
    t += 1.0
    add(Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / ARP(op=2, psrc=GATEWAY_IP, hwsrc=ATTACKER_MAC, hwdst=VICTIM_MAC, pdst=VICTIM_IP), t)

# --- Attack 4: DNS tunneling (data encoded into long random-looking labels) -----
t = T0 + 100
alphabet = "abcdefghijklmnopqrstuvwxyz234567"
for _ in range(5):
    t += 0.4
    label = "".join(random.choice(alphabet) for _ in range(48))
    add(dns_query(VICTIM_IP, f"{label}.tunnel.example.net"), t)

packets.sort(key=lambda p: p.time)

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/demo_attack.pcap"
    wrpcap(out, packets)
    print(f"Wrote {len(packets)} packets to {out}")
