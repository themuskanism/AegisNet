"""Scapy capture, evolved from the original prototype. No import-time capture."""
import csv
import math
from pathlib import Path
from scapy.all import IP, IPv6, TCP, UDP, sniff
from backend.flows import Packet


def packet_metadata(packet):
    """Return transport metadata only. IP bytes exclude Ethernet and other L2 headers."""
    try:
        ip = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        transport = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        if ip is None or transport is None:
            return None
        if IP in packet and (packet[IP].frag or int(packet[IP].flags) & 1):
            return None
        from scapy.layers.inet6 import IPv6ExtHdrFragment
        if IPv6ExtHdrFragment in packet:
            return None
        timestamp = float(packet.time)
        if not math.isfinite(timestamp) or timestamp < 0:
            return None
        return Packet(timestamp, ip.src, ip.dst, int(transport.sport), int(transport.dport),
                      6 if TCP in packet else 17, len(ip), int(transport.flags) if TCP in packet else 0,
                      4 if IP in packet else 6)
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None


def main():
    """Preserve the prototype's explicit 20-packet CSV capture command."""
    path = Path(__file__).resolve().parents[1] / 'data/network_traffic.csv'
    path.parent.mkdir(exist_ok=True)
    with path.open('a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(['source_ip','destination_ip','protocol','source_port','destination_port','packet_length'])
        def process_packet(packet):
            p = packet_metadata(packet)
            if p:
                writer.writerow([p.src,p.dst,'TCP' if p.protocol==6 else 'UDP',p.sport,p.dport,p.ip_bytes])
        sniff(prn=process_packet,count=20,store=False)


if __name__ == '__main__':
    main()
