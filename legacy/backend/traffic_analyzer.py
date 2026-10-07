import csv
from collections import Counter

CSV_FILE = "data/network_traffic.csv"


def analyze_traffic():
    packets = []

    with open(CSV_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            packets.append(row)

    print("\n=================================")
    print(" AegisNet Traffic Analysis")
    print("=================================")

    print(f"Total packets analyzed: {len(packets)}")

    # Protocol analysis
    protocols = Counter(packet["protocol"] for packet in packets)

    print("\nProtocol Statistics:")
    for protocol, count in protocols.items():
        print(f"{protocol}: {count}")

    # Source IP analysis
    source_ips = Counter(packet["source_ip"] for packet in packets)

    print("\nTop Source IPs:")
    for ip, count in source_ips.most_common(5):
        print(f"{ip}: {count} packets")

    # Basic suspicious traffic rule
    print("\nThreat Analysis:")

    suspicious = False

    for ip, count in source_ips.items():
        if count >= 10:
            print(f"🚨 Suspicious traffic detected from {ip}")
            print(f"   Reason: {count} packets from the same source")
            suspicious = True

    if not suspicious:
        print("✅ No obvious suspicious traffic detected.")

    print("\nAnalysis completed.")


if __name__ == "__main__":
    analyze_traffic()