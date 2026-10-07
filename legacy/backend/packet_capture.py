from scapy.all import sniff, IP, IPv6, TCP, UDP
import csv
import os


CSV_FILE = "data/network_traffic.csv"


def process_packet(packet):
    source_ip = ""
    destination_ip = ""
    protocol = ""
    source_port = ""
    destination_port = ""
    packet_length = len(packet)

    # IPv4
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    # IPv6
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    # TCP
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    # UDP
    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    else:
        protocol = packet.name

    print(
        f"{source_ip} -> {destination_ip} | "
        f"{protocol} | {source_port} -> {destination_port} | "
        f"Length: {packet_length}"
    )

    # Save packet features
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_length
        ])


# Create data folder if it doesn't exist
os.makedirs("data", exist_ok=True)

# Create CSV with headers
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "packet_length"
        ])


print("=================================")
print(" AegisNet Network Traffic Capture")
print("=================================")
print("Capturing 20 packets...\n")


sniff(prn=process_packet, count=20)

print("\nPacket capture completed.")
print(f"Data saved to: {CSV_FILE}")