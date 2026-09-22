const API_URL = "http://127.0.0.1:5000/api/traffic";

async function loadDashboard() {
    try {
        const response = await fetch(API_URL);

        if (!response.ok) {
            throw new Error("Could not fetch traffic data");
        }

        const data = await response.json();

        console.log("AegisNet traffic data:", data);

        const total = Number(data.total_packets || 0);

        const tcp = Number(data.protocols?.TCP || 0);
        const udp = Number(data.protocols?.UDP || 0);

        // Main statistics
        document.getElementById("totalPackets").textContent = total;
        document.getElementById("tcpPackets").textContent = tcp;
        document.getElementById("udpPackets").textContent = udp;

        // Threat count
        const threats = Array.isArray(data.suspicious_sources)
            ? data.suspicious_sources.length
            : 0;

        document.getElementById("threats").textContent = threats;

        // Protocol percentages
        if (total > 0) {
            const tcpPercent = ((tcp / total) * 100).toFixed(1);
            const udpPercent = ((udp / total) * 100).toFixed(1);

            document.getElementById("tcpPercent").textContent =
                tcpPercent + "%";

            document.getElementById("udpPercent").textContent =
                udpPercent + "%";

            document.getElementById("tcpBar").style.width =
                tcpPercent + "%";

            document.getElementById("udpBar").style.width =
                udpPercent + "%";
        }

        // Source IP table
        updateIPTable(data.top_source_ips || {});

        // Security status
        updateSecurityStatus(threats);

    } catch (error) {
        console.error("Dashboard error:", error);

        document.getElementById("totalPackets").textContent = "Error";
        document.getElementById("tcpPackets").textContent = "--";
        document.getElementById("udpPackets").textContent = "--";
    }
}


function updateIPTable(sourceIPs) {

    const table = document.getElementById("ipTable");

    table.innerHTML = "";

    const entries = Object.entries(sourceIPs);

    if (entries.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="4" class="loading">
                    No network data available
                </td>
            </tr>
        `;

        return;
    }

    entries.forEach(([ip, packets], index) => {

        const row = document.createElement("tr");

        const status =
            Number(packets) >= 10
                ? '<span style="color:#f59e0b;">● Suspicious</span>'
                : '<span style="color:#4ade80;">● Normal</span>';

        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${ip}</td>
            <td>${packets}</td>
            <td>${status}</td>
        `;

        table.appendChild(row);
    });
}


function updateSecurityStatus(threats) {

    const heading = document.querySelector(".security-status h2");
    const message = document.querySelector(".security-status p");

    if (threats > 0) {
        heading.textContent = "Threats Detected";
        heading.style.color = "#f59e0b";

        message.textContent =
            `${threats} suspicious source(s) detected`;
    } else {
        heading.textContent = "Protected";
        heading.style.color = "#4ade80";

        message.textContent =
            "No active threats detected";
    }
}


// Initial load
loadDashboard();


// Refresh every 10 seconds
setInterval(loadDashboard, 10000);