"""Packet builders shared by the tests."""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether


def stamp(pkt, ts):
    pkt.time = ts
    return pkt


def syn(src, dst, dport, ts, sport=40000):
    return stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"), ts)


def synack(src, dst, sport, ts, dport=40000):
    return stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA"), ts)


def ack(src, dst, dport, ts):
    return stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="A"), ts)


def arp_reply(ip, mac, ts, target="192.168.1.20"):
    return stamp(Ether(src=mac, dst="aa:bb:cc:00:00:20") / ARP(op=2, psrc=ip, hwsrc=mac, hwdst="aa:bb:cc:00:00:20", pdst=target), ts)


def dns_query(name, ts, src="192.168.1.20"):
    return stamp(
        Ether() / IP(src=src, dst="8.8.8.8") / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)),
        ts,
    )
