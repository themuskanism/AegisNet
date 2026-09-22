from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import csv
from collections import Counter

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

CSV_FILE = "data/network_traffic.csv"
@app.route("/dashboard")
def dashboard():
    return send_from_directory("../frontend", "index.html")

@app.route("/")
def home():
    return jsonify({
        "project": "AegisNet",
        "status": "Backend is running",
        "message": "AegisNet prototype started successfully"
    })


@app.route("/api/status")
def status():
    return jsonify({
        "status": "online",
        "service": "AegisNet Backend"
    })


@app.route("/api/traffic")
def traffic():

    packets = []

    try:
        with open(CSV_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for row in reader:
                packets.append(row)

        protocols = Counter(
            packet["protocol"] for packet in packets
        )

        source_ips = Counter(
            packet["source_ip"] for packet in packets
        )

        suspicious_sources = []

        for ip, count in source_ips.items():

            if count >= 10:
                suspicious_sources.append({
                    "ip": ip,
                    "packets": count,
                    "reason": "High packet count from same source"
                })

        return jsonify({
            "total_packets": len(packets),
            "protocols": dict(protocols),
            "top_source_ips": dict(source_ips.most_common(5)),
            "suspicious_sources": suspicious_sources
        })

    except FileNotFoundError:

        return jsonify({
            "error": "Network traffic CSV not found"
        }), 404


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )