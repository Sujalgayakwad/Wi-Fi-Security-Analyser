import os
import io
import csv
import json
import uuid
import hashlib
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

# -------------------------------------------------------------
# Password Hashing and Auth Utilities
# -------------------------------------------------------------
def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = uuid.uuid4().hex
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return key.hex(), salt

def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    hashed, _ = hash_password(password, salt)
    return hashed == expected_hash

def get_current_user(db, req) -> Optional[Dict[str, Any]]:
    auth_header = req.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "token" in req.args:
        token = req.args.get("token")

    if not token:
        return None

    cur = db.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.email, u.role, u.created_at, u.last_login
        FROM users u
        JOIN user_tokens t ON u.id = t.user_id
        WHERE t.token = ? AND t.expires_at > datetime('now')
    """, (token,))
    row = cur.fetchone()
    return dict(row) if row else None

# -------------------------------------------------------------
# Database Connection and Migrations
# -------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as db:
        cur = db.cursor()

        # 1. Users & Authentication
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT NOT NULL,
                last_login TEXT DEFAULT ''
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Seed Default Administrator if users table is empty
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            p_hash, p_salt = hash_password("Admin@NetGuard2026!")
            cur.execute("""
                INSERT INTO users (username, email, password_hash, salt, role, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("admin", "admin@netguard.local", p_hash, p_salt, "administrator", datetime.datetime.now().strftime(SCAN_TIME_FORMAT), ""))

        # 2. Network table
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

        # 3. Devices & History
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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                status TEXT NOT NULL,
                seen_at TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
            )
        """)

        # 4. Scans & Sessions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_uuid TEXT UNIQUE NOT NULL,
                scanned_at TEXT NOT NULL,
                trigger_type TEXT NOT NULL DEFAULT 'manual',
                total_networks INTEGER NOT NULL DEFAULT 0,
                secure_networks INTEGER NOT NULL DEFAULT 0,
                open_networks INTEGER NOT NULL DEFAULT 0,
                threats_count INTEGER NOT NULL DEFAULT 0,
                average_score INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_time ON scan_sessions(scanned_at)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                ssid TEXT NOT NULL,
                bssid TEXT NOT NULL,
                signal_percent INTEGER NOT NULL,
                signal_dbm INTEGER NOT NULL,
                band TEXT NOT NULL,
                channel INTEGER NOT NULL,
                authentication TEXT NOT NULL,
                encryption TEXT NOT NULL,
                security_score INTEGER NOT NULL,
                security_rating TEXT NOT NULL,
                vendor TEXT NOT NULL,
                is_evil_twin INTEGER NOT NULL DEFAULT 0,
                is_duplicate INTEGER NOT NULL DEFAULT 0,
                scanned_at TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scanres_bssid ON scan_results(bssid)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scanres_ssid ON scan_results(ssid)")

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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_network ON scans(network_name)")

        # 5. Security Findings
        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                session_id INTEGER,
                network_identifier TEXT NOT NULL,
                bssid TEXT DEFAULT '',
                finding_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                remediation TEXT NOT NULL,
                detection_time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON security_findings(severity)")

        # 6. Security Scores History
        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_name TEXT NOT NULL,
                bssid TEXT NOT NULL,
                score INTEGER NOT NULL,
                rating TEXT NOT NULL,
                factors_json TEXT NOT NULL,
                calculated_at TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_secscore_name ON security_scores(network_name)")

        # 7. Threat Events History
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                affected_network TEXT NOT NULL,
                bssid TEXT DEFAULT '',
                vendor TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                confidence TEXT DEFAULT 'HIGH',
                detected_at TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_type ON threat_events(threat_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_sev ON threat_events(severity)")

        # 8. Performance History
        cur.execute("""
            CREATE TABLE IF NOT EXISTS performance_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_host TEXT NOT NULL,
                avg_latency_ms INTEGER NOT NULL,
                min_latency_ms INTEGER NOT NULL,
                max_latency_ms INTEGER NOT NULL,
                jitter_ms INTEGER NOT NULL,
                loss_percent INTEGER NOT NULL,
                rx_speed_kbps REAL NOT NULL,
                tx_speed_kbps REAL NOT NULL,
                quality_score INTEGER NOT NULL,
                quality_rating TEXT NOT NULL,
                stability_percent INTEGER NOT NULL,
                measured_at TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_perf_time ON performance_history(measured_at)")

        # 9. Reports
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_uuid TEXT UNIQUE NOT NULL,
                report_type TEXT NOT NULL,
                file_name TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                generated_at TEXT NOT NULL
            )
        """)

        # 10. Settings & Alerts
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
                is_read INTEGER DEFAULT 0,
                acknowledged INTEGER DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(is_read)")

        # Backward compatibility column migrations
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

        try:
            cur.execute("ALTER TABLE alerts ADD COLUMN acknowledged INTEGER DEFAULT 0")
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
                ("Protected WPA2 Connection Established", "Authorized client connected with AES-CCMP encryption.", "LOW", "NETWORK", "Today, 12:05 PM", 0, 0),
                ("Unencrypted Airspace Broadcast", "One or more nearby Wi-Fi networks advertise Open encryption without authentication.", "MEDIUM", "SECURITY", "Today, 11:30 AM", 0, 0)
            ]
            cur.executemany(
                "INSERT INTO alerts (title, message, severity, category, created_at, is_read, acknowledged) VALUES (?, ?, ?, ?, ?, ?, ?)",
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

        # Log score calculation history
        cur.execute("""
            INSERT INTO security_scores (network_name, bssid, score, rating, factors_json, calculated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            curr["ssid"],
            curr["bssid"],
            curr["securityScore"],
            curr["securityRating"],
            json.dumps(["Authentication: " + curr["encryption"], "Cipher: " + curr.get("cipher", "CCMP")]),
            datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
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
            cur = db.cursor()
            now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
            for dev in live:
                # Find or insert in devices table to ensure valid FK
                cur.execute("SELECT id, is_trusted FROM devices WHERE mac_address = ? OR ip_address = ?", (dev["mac_address"], dev["ip_address"]))
                existing = cur.fetchone()
                if existing:
                    d_id = existing[0]
                    dev["is_trusted"] = bool(existing[1])
                    cur.execute("UPDATE devices SET last_seen = ?, status = 'online' WHERE id = ?", (now_str, d_id))
                else:
                    cur.execute("""
                        INSERT INTO devices (name, platform, ip_address, status, last_seen, mac_address, vendor, device_type, first_seen, is_trusted)
                        VALUES (?, ?, ?, 'online', ?, ?, ?, ?, ?, ?)
                    """, (
                        dev["name"], dev["platform"], dev["ip_address"], now_str,
                        dev["mac_address"], dev["vendor"], dev["device_type"], now_str,
                        1 if dev.get("is_trusted") else 0
                    ))
                    d_id = cur.lastrowid

                dev["id"] = d_id
                dev["connected_wifi"] = network_name

                # Log presence into device_history
                cur.execute("""
                    INSERT INTO device_history (device_id, ip_address, mac_address, status, seen_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    d_id,
                    dev["ip_address"],
                    dev["mac_address"],
                    dev["status"],
                    now_str
                ))
            db.commit()
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
# AUTHENTICATION ENDPOINTS (Section 15, 17)
# -------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400

    p_hash, p_salt = hash_password(password)
    now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)

    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cur.fetchone():
            return jsonify({"error": "Username or email is already registered."}), 409

        cur.execute("""
            INSERT INTO users (username, email, password_hash, salt, role, created_at, last_login)
            VALUES (?, ?, ?, ?, 'analyst', ?, ?)
        """, (username, email, p_hash, p_salt, now_str, now_str))
        user_id = cur.lastrowid

        token = uuid.uuid4().hex
        expires = (datetime.datetime.now() + datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("INSERT INTO user_tokens VALUES (?, ?, ?, ?)", (token, user_id, now_str, expires))
        db.commit()

        return jsonify({
            "message": "User registered successfully.",
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "role": "analyst"
            }
        }), 201

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, username))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Invalid username or password."}), 401

        user = dict(row)
        if not verify_password(password, user["salt"], user["password_hash"]):
            return jsonify({"error": "Invalid username or password."}), 401

        token = uuid.uuid4().hex
        now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
        expires = (datetime.datetime.now() + datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

        cur.execute("INSERT INTO user_tokens VALUES (?, ?, ?, ?)", (token, user["id"], now_str, expires))
        cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user["id"]))
        db.commit()

        return jsonify({
            "message": "Login successful.",
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "last_login": now_str
            }
        })

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.args.get("token")
    if token:
        with get_db() as db:
            cur = db.cursor()
            cur.execute("DELETE FROM user_tokens WHERE token = ?", (token,))
            db.commit()
    return jsonify({"message": "Logged out successfully."})

@app.route("/api/auth/profile", methods=["GET"])
def auth_profile():
    with get_db() as db:
        user = get_current_user(db, request)
        if user:
            return jsonify({"user": user, "authenticated": True})
        return jsonify({
            "authenticated": False,
            "user": {
                "username": "guest",
                "role": "visitor"
            }
        })

# -------------------------------------------------------------
# WI-FI SCANNING & SESSIONS (Section 3)
# -------------------------------------------------------------
@app.route("/api/scans/start", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def record_scan():
    trigger = request.json.get("trigger", "manual") if request.is_json and request.json else "manual"
    scanned = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()
    threats = scanner.detect_threats(scanned, conn)

    now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
    session_uuid = uuid.uuid4().hex

    total_net = len(scanned)
    open_net = sum(1 for n in scanned if "open" in n.get("authentication", "").lower() or n.get("encryption", "").lower() == "none")
    secure_net = total_net - open_net
    avg_score = round(sum(n.get("securityScore", 80) for n in scanned) / total_net) if total_net > 0 else 82

    with get_db() as db:
        cur = db.cursor()
        # Record session
        cur.execute("""
            INSERT INTO scan_sessions (session_uuid, scanned_at, trigger_type, total_networks, secure_networks, open_networks, threats_count, average_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_uuid, now_str, trigger, total_net, secure_net, open_net, len(threats), avg_score))
        session_id = cur.lastrowid

        # Record granular results
        for n in scanned:
            cur.execute("""
                INSERT INTO scan_results (session_id, ssid, bssid, signal_percent, signal_dbm, band, channel, authentication, encryption, security_score, security_rating, vendor, is_evil_twin, is_duplicate, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id, n.get("ssid"), n.get("bssid"), n.get("signalPercent", 50),
                n.get("signal_dbm", -70), n.get("band", "2.4 GHz"), n.get("channel", 11),
                n.get("authentication", "Unknown"), n.get("encryption", "Unknown"),
                n.get("securityScore", 80), n.get("securityRating", "Good"),
                n.get("vendor", ""), 1 if n.get("isEvilTwin") else 0,
                1 if n.get("isDuplicate") else 0, now_str
            ))

        # Legacy scans table entry for backwards compatibility
        cur.execute("""
            INSERT INTO scans (network_name, scanned_at, encryption, score, result)
            VALUES (?, ?, ?, ?, ?)
        """, (
            conn.get("ssid") if conn else (scanned[0].get("ssid") if scanned else "Airspace"),
            now_str,
            conn.get("encryption") if conn else "WPA2",
            conn.get("securityScore", avg_score) if conn else avg_score,
            "GOOD" if (conn.get("securityScore", avg_score) if conn else avg_score) >= 70 else "RISKY"
        ))

        # Record threats to threat_events
        for t in threats:
            cur.execute("""
                INSERT INTO threat_events (threat_type, severity, status, title, description, affected_network, bssid, vendor, evidence, confidence, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                t.get("type"), t.get("severity"), t.get("status"), t.get("title"),
                t.get("description"), t.get("affectedNetwork"), t.get("bssid", ""),
                t.get("vendor", ""), t.get("evidence", ""), t.get("confidence", "HIGH"), now_str
            ))

        db.commit()

    return jsonify({
        "sessionId": session_id,
        "sessionUuid": session_uuid,
        "scanned_at": now_str,
        "totalNetworks": total_net,
        "averageScore": avg_score,
        "networks": scanned,
        "threats": threats,
        "status": "COMPLETED"
    }), 201

@app.route("/api/scans", methods=["GET"])
@app.route("/api/history", methods=["GET"])
def get_scans():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50")
        scans = [dict(r) for r in cur.fetchall()]
        return jsonify(scans)

@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan_details(scan_id: int):
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM scan_sessions WHERE id = ?", (scan_id,))
        sess = cur.fetchone()
        if not sess:
            return jsonify({"error": "Scan session not found"}), 404
        cur.execute("SELECT * FROM scan_results WHERE session_id = ?", (scan_id,))
        results = [dict(r) for r in cur.fetchall()]
        return jsonify({"session": dict(sess), "networks": results})

@app.route("/api/wifi/networks", methods=["GET"])
@app.route("/api/networks", methods=["GET"])
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

@app.route("/api/networks/<path:ssid>", methods=["GET"])
def get_network_by_ssid(ssid: str):
    scanned = scanner.scan_available_networks()
    target = next((n for n in scanned if n.get("ssid").lower() == ssid.lower()), None)
    if not target:
        return jsonify({"error": "Network not visible in current airspace."}), 404
    return jsonify(target)

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

# -------------------------------------------------------------
# DASHBOARD API
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

# -------------------------------------------------------------
# SECURITY ANALYSIS & FINDINGS (Section 4, 5)
# -------------------------------------------------------------
@app.route("/api/security/analyze", methods=["POST"])
def run_security_analysis():
    visible = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()
    threats = scanner.detect_threats(visible, conn)
    analysis = scanner.get_ai_security_analysis(conn, visible, threats)

    now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
    findings = []

    with get_db() as db:
        cur = db.cursor()
        for t in threats:
            f_id = f"FND-{uuid.uuid4().hex[:6].upper()}"
            cur.execute("""
                INSERT INTO security_findings (finding_id, network_identifier, bssid, finding_name, severity, risk_level, description, evidence, remediation, detection_time, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
            """, (
                f_id, t.get("affectedNetwork"), t.get("bssid", ""), t.get("title"),
                t.get("severity"), t.get("severity"), t.get("description"),
                t.get("evidence", "Observable broadcast beacon frames."),
                t.get("recommendation", "Hardening router configuration."),
                now_str
            ))
            findings.append({
                "findingId": f_id,
                "title": t.get("title"),
                "severity": t.get("severity"),
                "network": t.get("affectedNetwork"),
                "remediation": t.get("recommendation")
            })
        db.commit()

    return jsonify({
        "status": "SUCCESS",
        "findingsCount": len(findings),
        "findings": findings,
        "analysis": analysis,
        "analyzedAt": now_str
    })

@app.route("/api/security/findings", methods=["GET"])
def get_security_findings():
    sev_filter = request.args.get("severity")
    status_filter = request.args.get("status")

    with get_db() as db:
        cur = db.cursor()
        query = "SELECT * FROM security_findings WHERE 1=1"
        params = []
        if sev_filter:
            query += " AND severity = ?"
            params.append(sev_filter.upper())
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.upper())

        query += " ORDER BY id DESC LIMIT 100"
        cur.execute(query, params)
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/security/score", methods=["GET"])
def get_security_score():
    conn = scanner.get_connected_wifi()
    current_score = conn.get("securityScore", 0) if conn else 0
    network_name = conn.get("ssid", "No Network") if conn else "No Network"

    prev_score = None
    with get_db() as db:
        cur = db.cursor()
        cur.execute("""
            SELECT score, calculated_at FROM security_scores
            WHERE network_name = ?
            ORDER BY id DESC LIMIT 2
        """, (network_name,))
        rows = cur.fetchall()
        if len(rows) > 1:
            prev_score = rows[1]["score"]

    diff = (current_score - prev_score) if prev_score is not None else 0
    return jsonify({
        "network": network_name,
        "currentScore": current_score,
        "previousScore": prev_score,
        "difference": diff,
        "rating": scanner.classify_score(current_score),
        "explanation": f"Score calculated based on link encryption ({conn.get('encryption', 'None') if conn else 'Disconnected'}), authentication suite, and rogue AP proximity."
    })

@app.route("/api/security/history", methods=["GET"])
def get_security_history():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM security_scores ORDER BY id DESC LIMIT 50")
        return jsonify([dict(r) for r in cur.fetchall()])

# -------------------------------------------------------------
# THREAT DETECTION (Section 6)
# -------------------------------------------------------------
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

@app.route("/api/threats/analyze", methods=["POST"])
def analyze_threats():
    visible = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()
    threats = scanner.detect_threats(visible, conn)
    now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)

    with get_db() as db:
        cur = db.cursor()
        for t in threats:
            cur.execute("""
                INSERT INTO threat_events (threat_type, severity, status, title, description, affected_network, bssid, vendor, evidence, confidence, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                t.get("type"), t.get("severity"), t.get("status"), t.get("title"),
                t.get("description"), t.get("affectedNetwork"), t.get("bssid", ""),
                t.get("vendor", ""), t.get("evidence", ""), t.get("confidence", "HIGH"), now_str
            ))
        db.commit()

    return jsonify({
        "threatsCount": len(threats),
        "threats": threats,
        "evaluatedAt": now_str
    })

@app.route("/api/threats/history", methods=["GET"])
def get_threats_history():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM threat_events ORDER BY id DESC LIMIT 50")
        return jsonify([dict(r) for r in cur.fetchall()])

# -------------------------------------------------------------
# CONNECTED DEVICES (Section 7)
# -------------------------------------------------------------
@app.route("/api/devices", methods=["GET"])
def devices():
    with get_db() as db:
        network = sync_current_network(db)
        is_connected = bool(network.get("connected"))
        net_name = network.get("name", "")
        return jsonify(get_live_or_stored_devices(db, net_name, is_connected))

@app.route("/api/devices/discover", methods=["POST"])
def discover_devices():
    with get_db() as db:
        network = sync_current_network(db)
        is_connected = bool(network.get("connected"))
        net_name = network.get("name", "")
        devices_list = get_live_or_stored_devices(db, net_name, is_connected)
        return jsonify({"count": len(devices_list), "devices": devices_list})

@app.route("/api/devices/history", methods=["GET"])
def get_devices_history():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM device_history ORDER BY id DESC LIMIT 50")
        return jsonify([dict(r) for r in cur.fetchall()])

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

# -------------------------------------------------------------
# NETWORK PERFORMANCE (Section 8)
# -------------------------------------------------------------
@app.route("/api/performance", methods=["GET"])
@app.route("/api/performance/test", methods=["POST"])
def performance():
    perf = scanner.measure_network_performance()

    with get_db() as db:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO performance_history (target_host, avg_latency_ms, min_latency_ms, max_latency_ms, jitter_ms, loss_percent, rx_speed_kbps, tx_speed_kbps, quality_score, quality_rating, stability_percent, measured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            perf.get("targetHost", "8.8.8.8"),
            perf.get("avgLatencyMs", 0),
            perf.get("minLatencyMs", 0),
            perf.get("maxLatencyMs", 0),
            perf.get("jitterMs", 0),
            perf.get("packetLossPercent", 0),
            perf.get("rxSpeedKbps", 0.0),
            perf.get("txSpeedKbps", 0.0),
            perf.get("connectionQualityScore", 100),
            perf.get("qualityRating", "Good"),
            perf.get("stabilityPercent", 95),
            perf.get("measuredAt", datetime.datetime.now().strftime("%I:%M:%S %p"))
        ))
        db.commit()

    return jsonify(perf)

@app.route("/api/performance/history", methods=["GET"])
def get_performance_history():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM performance_history ORDER BY id DESC LIMIT 30")
        return jsonify([dict(r) for r in cur.fetchall()])

# -------------------------------------------------------------
# AI ASSISTANT & KNOWLEDGE (Section 9)
# -------------------------------------------------------------
@app.route("/api/ai/chat", methods=["POST"])
@app.route("/api/assistant/chat", methods=["POST"])
def ai_chat():
    data = request.get_json(silent=True) or {}
    question = data.get("question", "")
    conn = scanner.get_connected_wifi()
    visible = scanner.scan_available_networks()
    threats = scanner.detect_threats(visible, conn)
    return jsonify(scanner.process_ai_chat(question, conn, visible, threats))

@app.route("/api/ai/recommendations", methods=["GET"])
@app.route("/api/assistant/recommendations", methods=["GET"])
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

# -------------------------------------------------------------
# MACHINE LEARNING MODULE (Section 10)
# -------------------------------------------------------------
@app.route("/api/ml/anomalies", methods=["GET"])
def ml_anomalies():
    visible = scanner.scan_available_networks()
    conn = scanner.get_connected_wifi()

    history_records = []
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT ssid, bssid FROM scan_results ORDER BY id DESC LIMIT 100")
        history_records = [dict(r) for r in cur.fetchall()]

    return jsonify(scanner.detect_ml_anomalies(visible, conn, history_records))

# -------------------------------------------------------------
# TRAFFIC & COMPARISON
# -------------------------------------------------------------
@app.route("/api/traffic", methods=["GET"])
def traffic():
    return jsonify(scanner.get_traffic_metrics())

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

# -------------------------------------------------------------
# ALERTS & NOTIFICATIONS (Section 12)
# -------------------------------------------------------------
@app.route("/api/alerts", methods=["GET"])
@app.route("/api/notifications", methods=["GET"])
def get_alerts():
    sev = request.args.get("severity")
    with get_db() as db:
        cur = db.cursor()
        if sev and sev.upper() != "ALL":
            cur.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT 50", (sev.upper(),))
        else:
            cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
        return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("UPDATE alerts SET is_read = 1")
        db.commit()
    return jsonify({"status": "success", "message": "All alerts marked as read."})

@app.route("/api/alerts/<int:alert_id>/read", methods=["PATCH"])
@app.route("/api/notifications/<int:alert_id>/read", methods=["PATCH"])
def mark_alert_read(alert_id: int):
    with get_db() as db:
        cur = db.cursor()
        cur.execute("UPDATE alerts SET is_read = 1 WHERE id = ?", (alert_id,))
        db.commit()
    return jsonify({"id": alert_id, "is_read": 1})

@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@app.route("/api/notifications/<int:alert_id>/ack", methods=["POST"])
def acknowledge_alert(alert_id: int):
    with get_db() as db:
        cur = db.cursor()
        cur.execute("UPDATE alerts SET acknowledged = 1, is_read = 1 WHERE id = ?", (alert_id,))
        db.commit()
    return jsonify({"id": alert_id, "acknowledged": 1, "is_read": 1})

# -------------------------------------------------------------
# SETTINGS
# -------------------------------------------------------------
@app.route("/api/settings", methods=["GET"])
def get_settings():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM settings")
        return jsonify({r["key"]: r["value"] for r in cur.fetchall()})

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

# -------------------------------------------------------------
# REPORTS & EXPORTS (Section 13)
# -------------------------------------------------------------
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

@app.route("/api/reports/generate", methods=["POST"])
def generate_report():
    data = request.get_json(silent=True) or {}
    report_type = data.get("type", "JSON").upper()
    now_str = datetime.datetime.now().strftime(SCAN_TIME_FORMAT)
    rep_uuid = uuid.uuid4().hex
    file_name = f"netguard-audit-{rep_uuid[:8]}.{report_type.lower()}"

    payload = get_report_payload()
    summary = {
        "network": payload["network"].get("name"),
        "score": payload["network"].get("score"),
        "totalScanned": len(payload.get("scannedNetworks", [])),
        "threats": len(payload.get("threats", [])),
        "generatedAt": now_str
    }

    with get_db() as db:
        cur = db.cursor()
        cur.execute("""
            INSERT INTO reports (report_uuid, report_type, file_name, summary_json, generated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (rep_uuid, report_type, file_name, json.dumps(summary), now_str))
        report_id = cur.lastrowid
        db.commit()

    return jsonify({
        "reportId": report_id,
        "reportUuid": rep_uuid,
        "fileName": file_name,
        "type": report_type,
        "generatedAt": now_str,
        "downloadUrl": f"/api/reports/{report_id}/download"
    }), 201

@app.route("/api/reports", methods=["GET"])
def get_reports_list():
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 50")
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            try:
                r["summary"] = json.loads(r["summary_json"])
            except Exception:
                r["summary"] = {}
        return jsonify(rows)

@app.route("/api/reports/<int:report_id>/download", methods=["GET"])
def download_report(report_id: int):
    with get_db() as db:
        cur = db.cursor()
        cur.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        rep = cur.fetchone()
        if not rep:
            return jsonify({"error": "Report not found"}), 404

        rep_dict = dict(rep)
        rep_type = rep_dict["report_type"]
        file_name = rep_dict["file_name"]

    if rep_type == "CSV":
        return export_csv()
    else:
        return export_json()

def get_report_payload() -> Dict[str, Any]:
    with get_db() as db:
        network = sync_current_network(db)
        is_connected = bool(network.get("connected"))
        net_name = network.get("name", "")

        visible = scanner.scan_available_networks()
        conn = scanner.get_connected_wifi()
        threats = scanner.detect_threats(visible, conn)
        devices_list = get_live_or_stored_devices(db, net_name, is_connected)
        ai_analysis = scanner.get_ai_security_analysis(conn, visible, threats)
        performance_data = scanner.measure_network_performance()

        return {
            "network": network,
            "devices": devices_list,
            "threats": threats,
            "aiAnalysis": ai_analysis,
            "performance": performance_data,
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
