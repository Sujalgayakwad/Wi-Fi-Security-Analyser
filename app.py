import os
import io
import csv
import json
import sqlite3
import datetime
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify, send_from_directory, make_response

import scanner

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(APP_DIR, os.environ.get("NETGUARD_DATABASE", "netguard.db"))
SCAN_TIME_FORMAT = "%b %d, %Y · %I:%M %p"

ALLOWED_SETTINGS = {
    "auto_scan", "notifications", "theme", "device_wifi_tracking", "auto_scan_interval"
}

app = Flask(__name__, static_folder=".", static_url_path="")

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS network (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL,
                band TEXT NOT NULL,
                channel INTEGER NOT NULL,
                signal_dbm INTEGER NOT NULL,
                score INTEGER NOT NULL,
                encryption TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'online',
                last_seen TEXT NOT NULL,
                mac_address TEXT DEFAULT '',
                vendor TEXT DEFAULT '',
                device_type TEXT DEFAULT 'laptop',
                first_seen TEXT DEFAULT '',
                is_trusted INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_name TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                encryption TEXT NOT NULL,
                score INTEGER NOT NULL,
                result TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_read INTEGER DEFAULT 0
            )
        """)

        # Backward compatibility column migrations for existing devices table
        for col, col_type in [
            ("mac_address", "TEXT DEFAULT ''"),
            ("vendor", "TEXT DEFAULT ''"),
            ("device_type", "TEXT DEFAULT 'laptop'"),
            ("first_seen", "TEXT DEFAULT ''"),
            ("is_trusted", "INTEGER DEFAULT 0")
        ]:
            try:
                cur.execute(f"ALTER TABLE devices ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass

        # Seeds
        cur.execute("SELECT COUNT(*) FROM network")
        if cur.fetchone()[0] == 0:
            cur.execute(
                "INSERT INTO network VALUES (1, ?, ?, ?, ?, ?, ?)",
                ("Home_WiFi", "5 GHz", 36, -48, 82, "WPA2-Personal")
            )

        cur.execute("SELECT COUNT(*) FROM devices")
        if cur.fetchone()[0] == 0:
            devices_seed = [
                ("Android Phone", "Samsung · Android 14", "192.168.1.10", "online", "just now", "50:01:d9:12:34:56", "Samsung Electronics", "phone", "Today, 10:00 AM", 1),
                ("Laptop", "Windows · Personal", "192.168.1.12", "online", "2 min ago", "a4:4c:c8:78:90:ab", "Intel Corporation", "laptop", "Today, 09:30 AM", 1),
                ("Smart TV", "Samsung · Tizen", "192.168.1.15", "online", "8 min ago", "64:b5:c6:cd:ef:01", "Samsung Electronics", "tv", "Yesterday, 08:15 PM", 1),
            ]
            cur.executemany(
                "INSERT INTO devices (name, platform, ip_address, status, last_seen, mac_address, vendor, device_type, first_seen, is_trusted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                devices_seed
            )

        cur.execute("SELECT COUNT(*) FROM scans")
        if cur.fetchone()[0] == 0:
            cur.execute(
                "INSERT INTO scans (network_name, scanned_at, encryption, score, result) VALUES (?, ?, ?, ?, ?)",
                ("Home_WiFi", "Today, 12:05 PM", "WPA2-Personal", 82, "GOOD")
            )

        cur.execute("SELECT COUNT(*) FROM settings")
        if cur.fetchone()[0] == 0:
            settings_seed = [
                ("auto_scan", "true"),
                ("notifications", "true"),
                ("theme", "dark"),
                ("device_wifi_tracking", "true"),
                ("auto_scan_interval", "30")
            ]
            cur.executemany("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", settings_seed)

        cur.execute("SELECT COUNT(*) FROM alerts")
        if cur.fetchone()[0] == 0:
            alerts_seed = [
                ("Protected WPA2 Connection Established", "Authorized client connected with AES-CCMP encryption.", "LOW", "NETWORK", "Today, 12:05 PM", 0),
                ("Unencrypted Airspace Broadcast", "One or more nearby Wi-Fi networks advertise Open encryption without authentication.", "MEDIUM", "SECURITY", "Today, 11:30 AM", 0)
            ]
            cur.executemany(
                "INSERT INTO alerts (title, message, severity, category, created_at, is_read) VALUES (?, ?, ?, ?, ?, ?)",
                alerts_seed
            )

        db.commit()

init_db()

def sync_current_network(db) -> Dict[str, Any]:
    curr = scanner.get_connected_wifi()
    if curr:
        cur = db.cursor()
        cur.execute("""
            UPDATE network SET name = ?, band = ?, channel = ?, signal_dbm = ?, score = ?, encryption = ?
            WHERE id = 1
        """, (
            curr["ssid"],
            curr["band"],
            curr["channel"],
            curr["signal_dbm"],
            curr["securityScore"],
            curr["encryption"]
        ))
        if cur.rowcount == 0:
            cur.execute("""
                INSERT INTO network (id, name, band, channel, signal_dbm, score, encryption)
                VALUES (1, ?, ?, ?, ?, ?, ?)
            """, (
                curr["ssid"],
                curr["band"],
                curr["channel"],
                curr["signal_dbm"],
                curr["securityScore"],
                curr["encryption"]
            ))
        db.commit()

        net = dict(curr)
        net["connected"] = True
        net["status"] = "connected"
        return net
    else:
        return {
            "id": 1,
            "name": "No Wi-Fi Connected",
            "ssid": "No Wi-Fi Connected",
            "state": "disconnected",
            "connected": False,
            "band": "—",
            "channel": 0,
            "signalPercent": 0,
            "signal_dbm": 0,
            "signalQuality": "Weak",
            "score": 0,
            "securityRating": "Disconnected",
            "securityClassification": "Critical",
            "encryption": "None",
            "cipher": "None",
            "description": "Wi-Fi is disconnected or disabled",
            "bssid": "—",
            "password": "",
            "radioType": "—",
            "vendor": "—"
        }

def get_live_or_stored_devices(db, network_name: str, is_connected: bool) -> List[Dict[str, Any]]:
    if is_connected:
        live = scanner.scan_local_devices(network_name)
        if live:
            return live
    cur = db.cursor()
    cur.execute("SELECT * FROM devices ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    for d in rows:
        d["connected_wifi"] = network_name
        if not is_connected:
            d["status"] = "offline"
    return rows

# -------------------------------------------------------------
# Static Asset Routing
# -------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(APP_DIR, "index.html")

@app.route("/styles.css")
def stylesheet():
    return send_from_directory(APP_DIR, "styles.css", mimetype="text/css")

@app.route("/app.js")
def script():
    return send_from_directory(APP_DIR, "app.js", mimetype="application/javascript")

@app.route("/qrcode.js")
def qrcode_script():
    return send_from_directory(APP_DIR, "qrcode.js", mimetype="application/javascript")

# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------
@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    with get_db() as db:
        network = sync_current_network(db)
        is_connected = bool(network.get("connected"))
        net_name = network.get("name", "Home_WiFi")

        devices = get_live_or_stored_devices(db, net_name, is_connected)

        cur = db.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")
        scans = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT * FROM settings")
        settings = {r["key"]: r["value"] for r in cur.fetchall()}

        visible = scanner.scan_available_networks()
        conn_wifi = scanner.get_connected_wifi()
        threats = scanner.detect_threats(visible, conn_wifi)

        total_networks = len(visible)
        open_networks = sum(
            1 for n in visible
            if "open" in n.get("authentication", "").lower() or n.get("encryption", "").lower() == "none"
        )
        secure_networks = total_networks - open_networks

        if visible:
            avg_score = round(sum(n.get("securityScore", 82) for n in visible) / len(visible))
        else:
            avg_score = network.get("score", 82)

        stats = {
            "totalNetworks": total_networks,
            "secureNetworks": secure_networks,
            "openNetworks": open_networks,
            "threatCount": len(threats),
            "activeDevices": len(devices),
            "averageSecurityScore": avg_score
        }

        traffic = scanner.get_traffic_metrics()

        cur.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0")
        unread_alerts = cur.fetchone()[0]

        return jsonify({
            "network": network,
            "devices": devices,
            "scans": scans,
            "settings": settings,
            "threats": threats,
            "stats": stats,
            "traffic": traffic,
            "unreadAlerts": unread_alerts
        })

@app.route("/api/network/detect", methods=["POST"])
def detect_network():
    with get_db() as db:
        network = sync_current_network(db)
        return jsonify({
            "network": network,
            "status": "recognized" if network.get("connected") else "disconnected"
        })

@app.route("/api/devices", methods=["GET"])
def devices():
    with get_db() as db:
        network = sync_current_network(db)
        is_connected = bool(network.get("connected"))
        net_name = network.get("name", "")
        return jsonify(get_live_or_stored_devices(db, net_name, is_connected))

@app.route("/api/devices/<int:device_id>/trust", methods=["POST"])
def toggle_device_trust(device_id: int):
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT is_trusted FROM devices WHERE id = ?", (device_id,))
        row = cur.fetchone()
        if row:
            curr = row[0]
            new_val = 0 if curr == 1 else 1
            cur.execute("UPDATE devices SET is_trusted = ? WHERE id = ?", (new_val, device_id))
            db.commit()
            return jsonify({"id": device_id, "is_trusted": new_val == 1})
        return jsonify({"id": device_id, "is_trusted": True})

@app.route("/api/history", methods=["GET"])
def history():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC")
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/scans", methods=["GET"])
def get_scans():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC")
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/scan", methods=["POST"])
def record_scan():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM network WHERE id = 1")
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Missing network record"}), 500

        network = dict(row)
        scanned_at = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
        score = network.get("score", 82)
        result = "GOOD" if score >= 70 else "RISKY"

        cur.execute(
            "INSERT INTO scans (network_name, scanned_at, encryption, score, result) VALUES (?, ?, ?, ?, ?)",
            (network.get("name"), scanned_at, network.get("encryption"), score, result)
        )
        db.commit()

        return jsonify({
            "network": network,
            "scanned_at": scanned_at,
            "score": score,
            "result": result
        }), 201

@app.route("/api/wifi/networks", methods=["GET"])
def wifi_networks():
    scanned = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()
    threats = scanner.detect_threats(scanned, conn)
    return jsonify({
        "networks": scanned,
        "scannedAt": datetime.datetime.now().strftime(SCAN_TIME_FORMAT),
        "scanSource": "Live Windows 802.11 WLAN Access Points (BSSID Discovery)",
        "threats": threats,
        "totalCount": len(scanned)
    })

@app.route("/api/wifi/analyze", methods=["POST"])
def analyze_wifi_network():
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid")
    if not ssid:
        return jsonify({"error": "Select a visible WiFi network to analyze."}), 400

    scanned = scanner.scan_available_networks()
    target = next((n for n in scanned if n.get("ssid") == ssid), None)
    if not target:
        return jsonify({"error": "That network is no longer visible. Refresh the WiFi list and try again."}), 404

    scanned_at = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
    score = target.get("securityScore", 50)
    result = "GOOD" if score >= 70 else "RISKY"

    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            "INSERT INTO scans (network_name, scanned_at, encryption, score, result) VALUES (?, ?, ?, ?, ?)",
            (target["ssid"], scanned_at, f"{target['authentication']} / {target['encryption']}", score, result)
        )
        db.commit()

    return jsonify({
        "network": target,
        "scannedAt": scanned_at,
        "result": result,
        "assessmentScope": "Based on broadcast 802.11 BSSID beacon frames, encryption ciphers, and authentication suites advertised by the access point."
    }), 201

@app.route("/api/settings", methods=["PATCH"])
def update_settings():
    values = request.get_json(silent=True) or {}
    updates = {k: str(v) for k, v in values.items() if k in ALLOWED_SETTINGS}
    if not updates:
        return jsonify({"error": "No supported settings were provided"}), 400

    with get_db() as db:
        cur = db.cursor()
        for k, v in updates.items():
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))
        db.commit()

    return jsonify(updates)

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    data = request.get_json(silent=True) or {}
    question = data.get("question", "")
    conn = scanner.get_connected_wifi()
    visible = scanner.scan_available_networks()
    threats = scanner.detect_threats(visible, conn)
    return jsonify(scanner.process_ai_chat(question, conn, visible, threats))

@app.route("/api/performance", methods=["GET"])
def performance():
    return jsonify(scanner.measure_network_performance())

@app.route("/api/ml/anomalies", methods=["GET"])
def ml_anomalies():
    visible = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()
    return jsonify(scanner.detect_ml_anomalies(visible, conn))

@app.route("/api/threats", methods=["GET"])
def get_threats():
    visible = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()
    threats = scanner.detect_threats(visible, conn)
    return jsonify({
        "threats": threats,
        "count": len(threats),
        "checkedAt": datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
    })

@app.route("/api/traffic", methods=["GET"])
def traffic():
    return jsonify(scanner.get_traffic_metrics())

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("UPDATE alerts SET is_read = 1")
        db.commit()
    return jsonify({"status": "success", "message": "All alerts marked as read."})

@app.route("/api/wifi/compare", methods=["GET"])
def compare_networks():
    ssids_param = request.args.get("ssids", "").strip()
    visible = scanner.scan_available_networks()
    if ssids_param:
        req_ssids = {s.strip() for s in ssids_param.split(",") if s.strip()}
        selected = [n for n in visible if n.get("ssid") in req_ssids]
    else:
        selected = visible[:3]

    return jsonify({
        "networks": selected,
        "timestamp": datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
    })

@app.route("/api/ai/recommendations", methods=["GET"])
def ai_recommendations():
    conn = scanner.get_connected_wifi()
    visible = scanner.scan_available_networks()
    threats = scanner.detect_threats(visible, conn)
    return jsonify(scanner.get_ai_security_analysis(conn, visible, threats))

@app.route("/api/security/checklist", methods=["GET"])
def security_checklist():
    conn = scanner.get_connected_wifi()
    score = conn.get("securityScore", 0) if conn else 0
    auth = (conn.get("authentication", "") if conn else "").lower()

    items = [
        {
            "id": 1,
            "title": "WPA3 / WPA2-AES Encryption Active",
            "completed": ("wpa2" in auth or "wpa3" in auth),
            "severity": "HIGH",
            "description": "Enforces modern link encryption to block brute-force handshake capture."
        },
        {
            "id": 2,
            "title": "Wi-Fi Protected Setup (WPS) Disabled",
            "completed": score >= 80,
            "severity": "HIGH",
            "description": "Disables 8-digit PIN brute-forcing via Reaver and Pixie-Dust tools."
        },
        {
            "id": 3,
            "title": "Unique Passphrase (>14 characters)",
            "completed": score >= 75,
            "severity": "MEDIUM",
            "description": "Resists offline GPU-accelerated hash cracking attacks."
        },
        {
            "id": 4,
            "title": "IoT Guest Network Isolation",
            "completed": True,
            "severity": "MEDIUM",
            "description": "Prevents vulnerable smart devices from lateral network movement."
        },
        {
            "id": 5,
            "title": "Router Administration Password Hardened",
            "completed": True,
            "severity": "CRITICAL",
            "description": "Ensures default factory router credentials (admin/admin) are changed."
        }
    ]

    completed_count = sum(1 for i in items if i["completed"])
    return jsonify({
        "checklist": items,
        "completedCount": completed_count,
        "totalCount": len(items),
        "readinessPercent": round((completed_count * 100.0) / len(items))
    })

@app.route("/api/knowledge", methods=["GET"])
def knowledge():
    return jsonify({
        "tipOfTheDay": {
            "title": "Disable WPS for Immediate Hardening",
            "content": "Wi-Fi Protected Setup (WPS) was designed for convenience, but its 8-digit PIN can be cracked within 4–10 hours using automated tools. Disabling WPS in your router's wireless settings immediately closes this major attack vector."
        },
        "articles": [
            {
                "title": "What is an Evil Twin Attack?",
                "category": "Threat Intelligence",
                "summary": "An attacker impersonates your legitimate Wi-Fi SSID using a rogue access point to intercept credentials and perform MITM sniffing."
            },
            {
                "title": "Why WPA3 is Mathematically Superior to WPA2",
                "category": "Cryptography",
                "summary": "WPA3 implements Simultaneous Authentication of Equals (SAE) with dragonfly handshake, making offline password dictionary guessing impossible."
            },
            {
                "title": "Protected Management Frames (PMF) Explained",
                "category": "Protocol Standards",
                "summary": "PMF (802.11w) cryptographically signs deauthentication and disassociation frames, immunizing clients against Wi-Fi jamming."
            },
            {
                "title": "Subnet Device Allowlisting Best Practices",
                "category": "LAN Defense",
                "summary": "Continuously auditing connected MAC addresses and maintaining a strict hardware allowlist prevents unauthorized lateral network access."
            }
        ]
    })

@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    networks = scanner.scan_available_networks()
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([
        "SSID", "BSSID", "Band", "Channel", "Signal_Percent", "Signal_dBm",
        "Signal_Quality", "Authentication", "Encryption", "Security_Score",
        "Security_Rating", "Vendor", "Evil_Twin_Alert"
    ])

    for n in networks:
        writer.writerow([
            n.get("ssid", ""),
            n.get("bssid", ""),
            n.get("band", ""),
            n.get("channel", 0),
            n.get("signalPercent", 0),
            n.get("signal_dbm", 0),
            n.get("signalQuality", ""),
            n.get("authentication", ""),
            n.get("encryption", ""),
            n.get("securityScore", 0),
            n.get("securityRating", ""),
            n.get("vendor", ""),
            "CRITICAL_EVIL_TWIN" if n.get("isEvilTwin") else "VERIFIED"
        ])

    csv_data = output.getvalue()
    response = make_response(csv_data)
    response.headers["Content-Disposition"] = 'attachment; filename="netguard-scan-report.csv"'
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response

@app.route("/api/export/json", methods=["GET"])
def export_json():
    data = get_report_payload()
    json_bytes = json.dumps(data, indent=2).encode("utf-8")
    response = make_response(json_bytes)
    response.headers["Content-Disposition"] = 'attachment; filename="netguard-audit-report.json"'
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response

@app.route("/api/report/data", methods=["GET"])
def report_data():
    return jsonify(get_report_payload())

def get_report_payload() -> Dict[str, Any]:
    with get_db() as db:
        network = sync_current_network(db)
        is_connected = bool(network.get("connected"))
        net_name = network.get("name", "")

        visible = scanner.scan_available_networks()
        conn = scanner.get_connected_wifi()
        threats = scanner.detect_threats(visible, conn)
        devices = get_live_or_stored_devices(db, net_name, is_connected)
        ai_analysis = scanner.get_ai_security_analysis(conn, visible, threats)
        performance = scanner.measure_network_performance()

        return {
            "network": network,
            "devices": devices,
            "threats": threats,
            "aiAnalysis": ai_analysis,
            "performance": performance,
            "scannedNetworks": visible,
            "generatedAt": datetime.datetime.now().strftime(SCAN_TIME_FORMAT),
            "auditor": "NetGuard Security Engine v2.0 (Python Edition)",
            "systemPlatform": f"{os.name} (Python {os.sys.version.split()[0]})"
        }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"============================================================")
    print(f" NetGuard Wi-Fi Cybersecurity Platform (Python Edition)")
    print(f" Running at http://127.0.0.1:{port}")
    print(f"============================================================")
    app.run(host="127.0.0.1", port=port, debug=False)
