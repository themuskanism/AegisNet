"""Scapy capture, evolved from the original prototype. No import-time capture."""
import csv
import math
from pathlib import Path
from scapy.all import IP, IPv6, TCP, UDP, sniff
from backend.flows import Packet


def packet_metadata(packet):
    """Return transport metadata only. IP bytes exclude Ethernet and other L2 headers."""
    try:
        ip = packet
        while ip and not isinstance(ip, (IP, IPv6)):
            ip = ip.payload
        if not ip:
            return None
        transport = ip.payload
        from scapy.layers.inet6 import IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt
        while isinstance(transport,(IPv6ExtHdrHopByHop,IPv6ExtHdrRouting,IPv6ExtHdrDestOpt)):
            transport=transport.payload
        if not isinstance(transport,(TCP,UDP)):
            return None
        if isinstance(ip, IP) and (ip.frag or int(ip.flags) & 1):
            return None
        from scapy.layers.inet6 import IPv6ExtHdrFragment
        if IPv6ExtHdrFragment in packet:
            return None
        timestamp = float(packet.time)
        if not math.isfinite(timestamp) or timestamp < 0:
            return None
        return Packet(timestamp, ip.src, ip.dst, int(transport.sport), int(transport.dport),
                      6 if isinstance(transport,TCP) else 17, len(ip), int(transport.flags) if isinstance(transport,TCP) else 0,
                      4 if isinstance(ip, IP) else 6)
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
