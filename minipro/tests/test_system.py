import urllib.request
import urllib.error
import json
import sys
import uuid

BASE_URL = "http://127.0.0.1:5001"

def request(method, path, data=None, token=None):
    url = BASE_URL + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            status = response.status
            content = response.read()
            try:
                res_json = json.loads(content.decode("utf-8"))
            except Exception:
                res_json = content
            return status, res_json, response.headers
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            res_json = json.loads(content.decode("utf-8"))
        except Exception:
            res_json = content.decode("utf-8", errors="ignore")
        return e.code, res_json, e.headers

print("=====================================================================")
print(" NETGUARD FULL CYBERSECURITY PLATFORM – AUTOMATED TEST SUITE")
print("=====================================================================")

passed_tests = 0
failed_tests = 0

def check(test_num, name, condition, details=""):
    global passed_tests, failed_tests
    if condition:
        passed_tests += 1
        print(f"[PASS] {test_num:02d}. {name} {('- ' + details) if details else ''}")
    else:
        failed_tests += 1
        print(f"[FAIL] {test_num:02d}. {name}: {details}")

# 1. Static Files & Web UI
status, content, _ = request("GET", "/")
check(1, "Web UI Dashboard Endpoint", status == 200 and len(content) > 1000, f"HTTP {status}, {len(content)} bytes")

status, content, _ = request("GET", "/app.js")
check(2, "Frontend Script Endpoint", status == 200 and len(content) > 5000, f"HTTP {status}, {len(content)} bytes")

status, content, _ = request("GET", "/styles.css")
check(3, "Frontend Stylesheet Endpoint", status == 200 and len(content) > 5000, f"HTTP {status}, {len(content)} bytes")

status, content, _ = request("GET", "/qrcode.js")
check(4, "QR Code Library Script", status == 200 and len(content) > 1000, f"HTTP {status}, {len(content)} bytes")

# 2. Authentication: Default Admin Login & Registration
status, res, _ = request("POST", "/api/auth/login", {"username": "admin", "password": "Admin@NetGuard2026!"})
check(5, "Default Admin Authentication", status == 200 and "token" in res, f"HTTP {status}, User: {res.get('user', {}).get('username') if isinstance(res, dict) else ''}")
admin_token = res.get("token") if isinstance(res, dict) else None

test_user = f"user_{uuid.uuid4().hex[:6]}"
status, res, _ = request("POST", "/api/auth/register", {
    "username": test_user,
    "email": f"{test_user}@security.org",
    "password": "Password@12345!"
})
check(6, "New User Registration", status == 201 and "token" in res, f"Registered '{test_user}'")
user_token = res.get("token") if isinstance(res, dict) else None

status, res, _ = request("GET", "/api/auth/profile", token=user_token)
check(7, "Token-Based Profile Retrieval", status == 200 and res.get("authenticated") is True, f"Username: {res.get('user', {}).get('username')}")

# 3. Wi-Fi Scanning & Sessions
status, res, _ = request("POST", "/api/scans/start", {"trigger": "manual_test"})
check(8, "Start Wi-Fi Scan & Session Logging", status == 201 and "sessionId" in res, f"SessionId={res.get('sessionId')}, Networks={res.get('totalNetworks')}")
session_id = res.get("sessionId")

status, res, _ = request("GET", "/api/wifi/networks")
check(9, "Scan Results Discovery (/api/wifi/networks)", status == 200 and "networks" in res, f"Found {res.get('totalCount')} networks")

if session_id:
    status, res, _ = request("GET", f"/api/scans/{session_id}")
    check(10, f"Retrieve Scan Session Details (#{session_id})", status == 200 and "session" in res, f"Session UUID: {res.get('session', {}).get('session_uuid')}")

# 4. Security Analysis & Findings Engine
status, res, _ = request("POST", "/api/security/analyze")
check(11, "Rule-Based Security Analysis Engine", status == 200 and "findings" in res, f"Findings generated: {res.get('findingsCount')}")

status, res, _ = request("GET", "/api/security/findings")
check(12, "Security Findings Log Retrieval", status == 200 and isinstance(res, list), f"Total active findings: {len(res)}")

status, res, _ = request("GET", "/api/security/score")
check(13, "Security Score & Delta Comparison", status == 200 and "currentScore" in res, f"Score: {res.get('currentScore')}/100, Rating: {res.get('rating')}")

# 5. Threat Detection
status, res, _ = request("GET", "/api/threats")
check(14, "Active Threat Detection & Radar", status == 200 and "threats" in res, f"Active Threats: {res.get('count')}")

status, res, _ = request("POST", "/api/threats/analyze")
check(15, "Threat Analysis & Event Logging", status == 200 and "threatsCount" in res, f"Recorded {res.get('threatsCount')} threat events")

status, res, _ = request("GET", "/api/threats/history")
check(16, "Threat Events History Log", status == 200 and isinstance(res, list), f"Historical Threat Records: {len(res)}")

# 6. Connected Device Monitoring & Allowlist
status, res, _ = request("GET", "/api/devices")
check(17, "Subnet Device Inventory", status == 200 and isinstance(res, list) and len(res) > 0, f"Discovered {len(res)} devices on subnet")

status, res, _ = request("POST", "/api/devices/discover")
check(18, "Subnet Device Discovery API", status == 200 and isinstance(res, dict) and "devices" in res, f"Devices count: {res.get('count') if isinstance(res, dict) else 0}")

status, res, _ = request("POST", "/api/devices/1/trust")
check(19, "Hardware Allowlist Toggle API", status == 200 and "is_trusted" in res, f"Device 1 trusted: {res.get('is_trusted')}")

status, res, _ = request("GET", "/api/devices/history")
check(20, "Device Presence History Log", status == 200 and isinstance(res, list), f"History logs count: {len(res)}")

# 7. Network Performance, Latency & Jitter
status, res, _ = request("GET", "/api/performance")
check(21, "Network Performance Telemetry", status == 200 and "avgLatencyMs" in res, f"Latency: {res.get('avgLatencyMs')}ms, Jitter: {res.get('jitterMs')}ms, Quality: {res.get('connectionQualityScore')}/100")

status, res, _ = request("POST", "/api/performance/test")
check(22, "Live Performance Test Execution", status == 200 and "connectionQualityScore" in res, f"Score: {res.get('connectionQualityScore')}/100 ({res.get('qualityRating')})")

status, res, _ = request("GET", "/api/performance/history")
check(23, "Performance Measurements History", status == 200 and isinstance(res, list), f"Logged performance tests: {len(res)}")

# 8. AI Cybersecurity Assistant & Recommendations
status, res, _ = request("POST", "/api/ai/chat", {"question": "How can I improve my router security?"})
check(24, "AI Cybersecurity Assistant Chat", status == 200 and "answer" in res and len(res["answer"]) > 20, f"Answer length: {len(res.get('answer', ''))} chars")

status, res, _ = request("GET", "/api/ai/recommendations")
check(25, "AI Security Recommendations Engine", status == 200 and "routerHardeningSteps" in res, f"Hardening steps count: {len(res.get('routerHardeningSteps', []))}")

# 9. Machine Learning Anomaly Detection
status, res, _ = request("GET", "/api/ml/anomalies")
check(26, "Statistical ML Anomaly Detector", status == 200 and "anomalyScore" in res, f"Score: {res.get('anomalyScore')}, Anomalous: {res.get('isAnomalous')}, Sample: {res.get('sampleSize')}")

# 10. Router Checklist & Knowledge Base
status, res, _ = request("GET", "/api/security/checklist")
check(27, "Router Hardening Checklist", status == 200 and "checklist" in res, f"Checklist items: {len(res.get('checklist', []))}, Readiness: {res.get('readinessPercent')}%")

status, res, _ = request("GET", "/api/knowledge")
check(28, "Cybersecurity Knowledge Base", status == 200 and "tipOfTheDay" in res and "articles" in res, f"Tip: {res.get('tipOfTheDay', {}).get('title')}")

# 11. Alerts & Notifications
status, res, _ = request("GET", "/api/alerts")
check(29, "Security Alerts Event Log", status == 200 and isinstance(res, list), f"Alerts: {len(res)}")

status, res, _ = request("POST", "/api/alerts/clear")
check(30, "Clear / Mark All Alerts As Read", status == 200 and res.get("status") == "success", "All alerts marked as read")

# 12. Reports & Data Exports
status, res, headers = request("GET", "/api/export/csv")
check(31, "RFC-4180 CSV Scan Report Export", status == 200 and "text/csv" in headers.get("Content-Type", ""), f"CSV size: {len(res)} bytes")

status, res, headers = request("GET", "/api/export/json")
check(32, "Structured JSON Security Audit Export", status == 200 and isinstance(res, dict) and "network" in res, f"Audit generated at: {res.get('generatedAt')}")

status, res, _ = request("POST", "/api/reports/generate", {"type": "PDF"})
check(33, "Report Generation Engine (/api/reports/generate)", status == 201 and "reportId" in res, f"Created Report #{res.get('reportId')} ({res.get('fileName')})")
report_id = res.get("reportId")

status, res, _ = request("GET", "/api/reports")
check(34, "Reports History Log Retrieval", status == 200 and isinstance(res, list), f"Total generated reports: {len(res)}")

if report_id:
    status, res, _ = request("GET", f"/api/reports/{report_id}/download")
    check(35, f"Report Download API (#{report_id})", status == 200, "Report payload downloaded successfully")

# 13. Settings Configuration
status, res, _ = request("GET", "/api/settings")
check(36, "Retrieve System Settings", status == 200 and "theme" in res, f"Theme: {res.get('theme')}, Auto-Scan: {res.get('auto_scan')}")

status, res, _ = request("PATCH", "/api/settings", {"theme": "dark", "auto_scan_interval": "30"})
check(37, "Update System Settings (PATCH)", status == 200 and res.get("theme") == "dark", "Settings persisted to SQLite")

# 14. Network Comparison
status, res, _ = request("GET", "/api/wifi/compare")
check(38, "Network Comparison Matrix", status == 200 and "networks" in res, f"Compared networks: {len(res.get('networks', []))}")

# 15. Dashboard Aggregator
status, res, _ = request("GET", "/api/dashboard")
check(39, "Complete Dashboard Data Aggregator", status == 200 and "stats" in res and "network" in res, f"SSID: {res.get('network', {}).get('ssid')}, Score: {res.get('stats', {}).get('averageSecurityScore')}")

# =====================================================================
# WIFI SECURITY ANALYZER PRO MODULE TESTS (Tests 40 - 51)
# =====================================================================

# 16. Firewall Management Module
status, res, _ = request("GET", "/api/firewall")
check(40, "Firewall Detection & Profiles API", status == 200 and "profiles" in res and res.get("status") == "SUCCESS", f"Profiles: {len(res.get('profiles', {}))}, Defense Score: {res.get('score')}/100")

status, res, _ = request("GET", "/api/firewall/connections")
check(41, "Firewall Inbound/Outbound Socket Telemetry", status == 200 and "connections" in res, f"Monitored sockets: {res.get('count', 0)}")

status, res, _ = request("POST", "/api/firewall/rules", {
    "rule_name": "Test_NetGuard_Block_Port_9999",
    "direction": "IN",
    "action": "BLOCK",
    "protocol": "TCP",
    "local_port": "9999"
})
check(42, "Firewall Rule Creation API (POST)", status in (200, 201) and "rule" in res, f"Created: {res.get('rule', {}).get('rule_name')}")

status, res, _ = request("GET", "/api/firewall/rules")
check(43, "Firewall Rules Access Control List (GET)", status == 200 and "rules" in res, f"Active rules: {res.get('count')}")

# Clean up created rule
status, res, _ = request("DELETE", "/api/firewall/rules/Test_NetGuard_Block_Port_9999")
check(44, "Firewall Rule Deletion API (DELETE)", status == 200, f"Deleted rule: {res.get('rule_name')}")

# 17. Virus & Malware Detection Module
status, res, _ = request("GET", "/api/malware/status")
check(45, "Antivirus & Microsoft Defender Status API", status == 200 and "defender" in res, f"Defender Engine: {res.get('defender', {}).get('engine_name')}")

status, res, _ = request("POST", "/api/malware/scan", {"target_path": "tests", "max_files": 20})
check(46, "Cryptographic Hash & Heuristic Malware Scanner", status == 200 and "filesScanned" in res, f"Scanned: {res.get('filesScanned')} files in {res.get('durationSeconds')}s, Threats: {res.get('threatsFound')}")

# 18. Intrusion Detection System (IDS)
status, res, _ = request("GET", "/api/ids/status")
check(47, "Intrusion Detection System (IDS) Telemetry", status == 200 and "threat_level" in res, f"Threat Level: {res.get('threat_level')}, Sockets Evaluated: {res.get('active_sockets_evaluated')}")

# 19. Vulnerability Scanner
status, res, _ = request("GET", "/api/vulnerabilities?target=127.0.0.1")
check(48, "Vulnerability Scanner & CVSS Posture Audit", status == 200 and "vulnerability_score" in res, f"Score: {res.get('vulnerability_score')}/100, Total Findings: {res.get('total_findings')}")

# 20. Threat Intelligence & IoC Lookup
status, res, _ = request("GET", "/api/threat-intel/feed")
check(49, "Cyber Threat Intelligence (CTI) Stream Feed", status == 200 and "malicious_ips" in res, f"Indexed IoCs: {res.get('total_iocs_indexed')}")

status, res, _ = request("GET", "/api/threat-intel/lookup?q=185.220.101.5")
check(50, "Instant Threat Intelligence IoC Lookup API", status == 200 and res.get("found") is True, f"Attribution: {res.get('threat_actor')}, Risk: {res.get('risk_score')}")

# 21. Unified Security Audit Logs
status, res, _ = request("GET", "/api/logs?module=ALL&limit=10")
check(51, "Unified Security Audit Logs Retrieval & Filter", status == 200 and "logs" in res, f"Retrieved log entries: {res.get('count')}")

print("\n=====================================================================")
print(f" TOTAL TESTS: {passed_tests + failed_tests} | PASSED: {passed_tests} | FAILED: {failed_tests}")
print("=====================================================================")

if failed_tests == 0:
    print(">>> 100% OF ALL SYSTEM & INTEGRATION TESTS PASSED! APPLICATION FULLY FUNCTIONAL. <<<")
    sys.exit(0)
else:
    print(f"FAILED {failed_tests} TESTS. INVESTIGATE LOGS.")
    sys.exit(1)
