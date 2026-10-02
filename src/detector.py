from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, ARP
from src.db import AlertDB

class PacketWatchDetector:
    def __init__(self, db: AlertDB):
        self.db = db
        self.port_scan_threshold = 20
        self.syn_ack_ratio_threshold = 5.0

    def analyze_pcap(self, pcap_path: str):
        packets = rdpcap(pcap_path)

        ports_per_ip = defaultdict(set)
        syn_count = defaultdict(int)
        ack_count = defaultdict(int)
        arp_table = {}

        for pkt in packets:
            # 1. ARP Poisoning / Spoofing
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                proto_ip = pkt[ARP].psrc
                hw_mac = pkt[ARP].hwsrc
                if proto_ip in arp_table and arp_table[proto_ip] != hw_mac:
                    self.db.insert_alert(
                        proto_ip,
                        "ARP_SPOOF",
                        "HIGH",
                        f"MAC conflict: was {arp_table[proto_ip]}, now claiming {hw_mac}"
                    )
                else:
                    arp_table[proto_ip] = hw_mac

            # 2. Port Scans & SYN Floods
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                src_ip = pkt[IP].src
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags

                # Only count initial connection probes (SYN only, not RST or ACK)
                if flags == "S" or flags == 0x02:
                    ports_per_ip[src_ip].add(dst_port)
                    syn_count[src_ip] += 1
                elif flags == "SA" or flags == 0x12:
                    ack_count[pkt[IP].dst] += 1

        # Check port scan threshold
        for src, ports in ports_per_ip.items():
            if len(ports) >= self.port_scan_threshold:
                self.db.insert_alert(
                    src,
                    "PORT_SCAN",
                    "MEDIUM",
                    f"Scanned {len(ports)} unique ports"
                )

        # Check SYN flood threshold
        for src, syns in syn_count.items():
            acks = ack_count.get(src, 1)
            ratio = syns / acks
            if syns > 50 and ratio > self.syn_ack_ratio_threshold:
                self.db.insert_alert(
                    src,
                    "SYN_FLOOD",
                    "HIGH",
                    f"SYN/ACK ratio {ratio:.2f} ({syns} SYNs vs {acks} ACKs)"
                )

