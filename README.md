# 🛡️ WIFI SECURITY ANALYZER PRO — Next-Gen Cybersecurity Platform

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/SQLite-3.49-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/)
[![Tests](https://img.shields.io/badge/Tests-51%2F51%20Passing-10b981?style=for-the-badge&logo=pytest&logoColor=white)](tests/test_system.py)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

An enterprise-grade, high-performance **Wi-Fi Security Analysis, Host & Network Firewall Defense, Malware Detection, Intrusion Detection (IDS), and Threat Assessment Platform** built with **Python (Flask)**, native Windows security interfaces, and a next-generation responsive dark cybersecurity dashboard.

---

## 🌟 The 12 Core Cybersecurity Modules

1. **🛡️ Security Overview (Executive Dashboard)**
   - Algorithmic overall security score (0–100) reflecting multi-vector defense status.
   - Live telemetry: Airspace threat count, active connected devices, host firewall score, malware shield status, and real-time bandwidth graphs.
2. **🛰️ Wi-Fi Network Scanner**
   - Discovers nearby 802.11 access points, SSIDs, BSSIDs (MAC), signal strength (RSSI dBm & percentage), frequency band (2.4/5/6 GHz), and channels.
   - Audits cipher suites (WPA3-SAE, WPA2-AES, WPA-TKIP, WEP, Open) and resolves OUI vendor hardware.
3. **💻 Connected Device Intelligence**
   - Discovers subnet hosts with IP addresses, MAC addresses, hostnames, and manufacturer vendors.
   - Hardware allowlist management with 1-click authorization toggle (`/api/devices/{id}/trust`).
4. **⇄ Network Traffic Monitor**
   - Real-time bandwidth upload and download speed telemetry (`netstat -e` counters).
   - Live packet loss, ICMP round-trip latency, and jitter variance metrics.
5. **🧱 Firewall Management & Attack Surface Defense**
   - Deep inspection of Windows Defender Firewall across Domain, Private, and Public profiles via `netsh advfirewall`.
   - Inbound and outbound connection monitoring with mapped application names and PIDs.
   - Attack surface listening TCP port scanner and custom rule creation / deletion (`/api/firewall/rules`).
6. **☣️ Virus & Malware Detection Engine**
   - High-precision file and directory scanning with SHA-256 cryptographic hash verification.
   - Known threat signature database (EICAR, Ransomware, Trojans, Mirai Botnet, CoinMiners).
   - Behavioral heuristic detection for disguised double extensions (`.pdf.exe`) and obfuscated scripts.
   - Live integration with Microsoft Defender Antivirus (`powershell Get-MpComputerStatus`).
   - Safe isolation quarantine vault (`.quarantine/`) with user confirmation; never deletes files automatically.
7. **🔍 Vulnerability Scanner (CVSS v3.1)**
   - Audits local host and authorized subnet endpoints for risky services (Telnet 23, FTP 21, SMB 445, RDP 3389).
   - Maps vulnerabilities to CVE/CWE databases with CVSS v3.1 severity ratings and remediation guidance.
8. **⚡ Intrusion Detection System (IDS)**
   - Stateful network connection monitoring detecting port scans, rapid SYN floods, and connections to high-risk backdoor ports (4444, 1337, 31337).
   - MITRE ATT&CK tactic categorization and 1-click "Block Source IP in Firewall" defense.
9. **🌐 Cyber Threat Intelligence (CTI)**
   - Live IoC feed tracking known malicious IPs, command & control (C2) domains, and scanner nodes.
   - Wi-Fi protocol security advisories (KRACK, FragAttacks, Bluetooth/Wi-Fi bypass).
   - Instant IoC lookup search tool (`/api/threat-intel/lookup`).
10. **📋 Unified Security Audit Logs**
    - Centralized, immutable audit trail of firewall changes, malware scans, IDS events, and network transitions.
    - Multi-criteria filtering (by module, severity, and text search) with direct CSV and JSON export.
11. **📊 Reports & Analytics**
    - Executive Daily and Weekly cybersecurity audit summaries.
    - Automated PDF generation modal and RFC-4180 CSV telemetry exports.
12. **⚙️ Preferences & Configuration**
    - Configurable themes (Cyber Dark, Matrix Neon, Midnight Hacker, High Contrast, Cobalt Blue, OLED Pure Black).
    - Periodic auto-scan intervals (Off, 15s, 30s, 60s) and alert notification preferences.

---

## 🚀 Quick Start Guide

### Prerequisites
- Windows 10 or 11
- Python 3.8 or higher

### Installation & Execution
```powershell
# 1. Clone repository
git clone https://github.com/Sujalgayakwad/Wi-Fi-Security-Analyser.git
cd Wi-Fi-Security-Analyser

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the application
python app.py
```
Open **`http://127.0.0.1:5001`** in any modern web browser.

---

## 🧪 Automated Integration Test Suite
To verify all 51 security and platform modules:
```powershell
python tests/test_system.py
```
All 51 tests run and validate 100% pass rates across authentication, network scanning, firewall rules, malware hash matching, IDS events, and database integrity.


---

## 🌟 Key Features

### 1. 🛰️ Deep Wi-Fi Spectrum & Access Point Scanner
- **Real-Time Airspace Discovery**: Discovers all visible SSIDs, BSSIDs (hardware MACs), signal strengths (percentage and calculated dBm RSSI), frequency bands (2.4 GHz, 5 GHz, 6 GHz), and Wi-Fi channels.
- **Hardware Vendor Resolution (OUI)**: Resolves MAC prefixes to device manufacturers (Intel, Realtek, Cisco, Ubiquiti, TP-Link, Netgear, Apple, Samsung, etc.).
- **Cryptographic Suite Auditing**: Flags Open/Unencrypted networks, deprecated WEP RC4 ciphers, legacy WPA1/TKIP, standard WPA2-CCMP, and modern WPA3-SAE (Simultaneous Authentication of Equals).
- **Search, Filter & Sorting**: Dynamically sort networks by signal, score, channel, band, or SSID with instant search filtering.

### 2. 🚨 Threat Detection & Evil Twin Radar
- **Evil Twin Identification**: Flags duplicate SSIDs operating on disparate BSSIDs with conflicting security standards or suspicious RSSI variances.
- **Rogue AP Detection**: Detects unauthorized access points advertising network configurations identical to authorized infrastructure.
- **Spectral Anomaly Detection**: Statistical Z-score heuristic analysis across observable radio spectrum parameters.

### 3. 🛡️ Dynamic Wi-Fi Security Score (0–100)
- **Objective Grading**: Computes an airspace and network security score based on encryption strength, authentication ciphers, PMF compliance, and rogue presence.
- **Classification Categories**:
  - 🟢 **Excellent (90–100)**: WPA3-Personal/Enterprise with PMF
  - 🔵 **Good (75–89)**: Robust WPA2-AES/CCMP
  - 🟡 **Moderate (50–74)**: Weak signal, legacy settings, or channel congestion
  - 🟠 **Poor (30–49)**: WPA/TKIP or mixed legacy modes
  - 🔴 **Critical (<30)**: Open broadcast or deprecated WEP

### 4. 💻 Connected Device Intelligence & Allowlist
- **Subnet Device Discovery**: Probes authorized network subnets using ARP and ICMP table analysis.
- **Device Fingerprinting**: Displays IP address, MAC address, hostname, and manufacturer vendor.
- **Trusted Hardware Allowlist**: 1-click toggling (`/api/devices/{id}/trust`) to approve known hardware and highlight untrusted or rogue devices.

### 5. ⚡ Network Performance, Latency & Jitter
- **ICMP Ping Telemetry**: Active round-trip time (RTT) measurements yielding minimum, maximum, and average latency.
- **Jitter & Packet Loss**: Measures connection variance and packet loss percentage to calculate a **Connection Quality Score (0–100)**.
- **Live Bandwidth Telemetry**: Captures real-time RX/TX upload and download rates via system network interface counters (`netstat -e`).

### 6. 🤖 AI-Powered Cybersecurity Assistant & Chat
- **Interactive Security Chat**: Ask natural-language questions about your Wi-Fi environment, encryption types, or threat alerts.
- **Tailored Remediation**: Explains identified risks in simple terms and provides router hardening advice without external cloud dependencies.

### 7. 🔑 Wi-Fi Password Extraction & Offline QR Code
- **Connected Credential Recovery**: Direct retrieval of the connected Wi-Fi password with **Show / Hide** and **1-Click Copy** buttons.
- **QR Code Sharing**: Integrated offline QR code generator (`/qrcode.js`) for rapid mobile connection without revealing plaintext passwords.

### 8. 📋 Router Hardening Checklist & Knowledge Base
- **Hardening Checklist**: Step-by-step guidance on disabling WPS, updating firmware, changing default credentials, and isolating guest networks.
- **Threat Intelligence & Tip of the Day**: Curated cybersecurity articles covering Evil Twin attacks, PMF (802.11w), and WPA3 dragonfly handshakes.

### 9. 🎨 Multi-Theme Engine & Dynamic Real-Time Greeting
- **6 Professional Security Themes**:
  - 🌙 **Cyber Dark (Default)**: Deep midnight navy (`#061329`) with electric cyan radar highlights.
  - 🟢 **Matrix Terminal**: High-contrast terminal green hacker aesthetic (`#020d06` / `#00ff66`).
  - 🟣 **Midnight Synthwave**: Cyberpunk neon magenta (`#ff2a85`), electric violet (`#bd00ff`), and dark purple glass.
  - 🌑 **Stealth Obsidian**: Pure OLED deep obsidian (`#030712`) with titanium borders and ice-blue telemetry (`#38bdf8`).
  - 🌊 **Nordic Frost**: Arctic deep teal (`#03121a`) with aurora mint (`#14b8a6` / `#06b6d4`).
  - ☀️ **Tech Light**: Crisp enterprise daylight mode (`#f3f6fa`) with high-contrast text and sapphire accents.
- **Dynamic Clock-Based Greeting**: Automatically greets the active security officer based on client local time (*Good morning*, *Good afternoon*, *Good evening*, *Good night*).
- **1-Click Theme Switcher**: Dedicated switcher pill in topbar and selector in system preferences with instant `localStorage` persistence.
- **Live Airspace Sync & Refresh Engine**: Interactive topbar action button and sidebar system monitor widget to re-synchronize live WLAN telemetry and active screens on demand.

### 10. 📜 Persistent Scan History & Audit Trail Management
- **Full Historical Logging**: Every security scan session and granular AP observation is persisted in SQLite (`scans`, `scan_sessions`, `scan_results`).
- **Comprehensive Audit View**: Displays Network SSID, Scan Timestamp, Cipher Suite, and Color-Coded Security Score with quick airspace inspection.
- **1-Click Clear History**: Instant database purge endpoint (`POST /api/history/clear`) with confirmation prompt to safely reset historical logs and threat event records.

### 11. 📄 Multi-Format Export & Reporting
- **RFC-4180 CSV Export**: Complete scan table download for spreadsheet analysis.
- **Structured JSON Audit**: Full system audit state export for compliance and archival.
- **Printable PDF Security Report**: Dedicated `@media print` layout and modal preview for generating executive audit reports.

---

## 🏗️ Architecture & Project Structure

```
Wi-Fi-Security-Analyser/
├── app.py                                 # Flask REST API, SQLite Controller & Static Server
├── scanner.py                             # Native Windows Wi-Fi, Ping, Throughput & ML Engine
├── requirements.txt                       # Lightweight Python dependencies (Flask)
├── run.bat                                # 1-Click Windows launcher script
├── app.js                                 # Frontend state, multi-theme engine, charts & API bindings
├── index.html                             # Responsive cybersecurity single-page application
├── styles.css                             # Cyber Dark, Matrix, Synthwave & Light theme styles
├── qrcode.js                              # Offline QR code generator library
├── screenshots/
│   ├── dashboard.png.jpeg                 # Real-time dashboard & security health
│   ├── networks.png.jpeg                  # 802.11 spectrum & AP analysis table
│   └── history.jpeg                       # Scan history & audit trail interface
└── README.md                              # Comprehensive platform documentation
```

---

## 🚀 Getting Started

### Prerequisites
- **Operating System**: Windows 10 or 11
- **Python**: Python 3.8 or higher (Python 3.10–3.13 tested)
- **Wi-Fi Interface**: Enabled wireless adapter

### Installation & Launch

#### Option A: 1-Click Launcher (Windows)
Double-click `run.bat` in File Explorer or run:
```powershell
.\run.bat
```

#### Option B: Standard Python (Command Line)
```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the platform
python app.py
```

Once running, navigate to:
👉 **[http://127.0.0.1:5001](http://127.0.0.1:5001)**

---

## 📸 Screenshots

### 🛡️ 1. Real-Time Cybersecurity Dashboard & Spectrum Health
Live monitoring of connected Wi-Fi parameters, security grading (0–100), active rogue threat counts, and quick cybersecurity actions.
<p align="center">
  <img src="screenshots/dashboard.png" alt="NetGuard Dashboard" width="95%">
</p>

### 📡 2. 802.11 Airspace Access Point Audit Matrix
Complete discovery of nearby SSIDs, hardware BSSIDs, OUI manufacturer resolution, signal RSSI (dBm), encryption suites, and threat grade classifications.
<p align="center">
  <img src="screenshots/networks.png" alt="Network Analysis" width="95%">
</p>

### 📜 3. Scan History, Audit Trail & Database Management
Historical audit log of all network scans, timestamps, ciphers, ratings, with 1-click **Clear History** and export tools.
<p align="center">
  <img src="screenshots/history.jpeg" alt="Scan History" width="95%">
</p>

---

## 🔌 API Endpoints Reference

| Category | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **Auth** | `POST` | `/api/auth/register` | Register new analyst account |
| **Auth** | `POST` | `/api/auth/login` | Authenticate user & generate bearer session token |
| **Auth** | `POST` | `/api/auth/logout` | Terminate session & invalidate token |
| **Auth** | `GET` | `/api/auth/profile` | Current user profile & authentication status |
| **Dashboard** | `GET` | `/` | Web UI Dashboard |
| **Dashboard** | `GET` | `/api/dashboard` | Active Wi-Fi telemetry, stats, connected password, and threats |
| **Scanning** | `POST`| `/api/scans/start` | Trigger live Wi-Fi scan session with full DB logging |
| **Scanning** | `GET` | `/api/scans` | Historical scan sessions |
| **Scanning** | `POST`| `/api/history/clear` | Clear all saved historical scans and threat logs |
| **Scanning** | `GET` | `/api/scans/{id}` | Granular AP observations for specific scan session |
| **Scanning** | `GET` | `/api/wifi/networks` | Visible access points with channel, band, RSSI, and security score |
| **Analysis** | `POST`| `/api/security/analyze`| Runs rule-based security findings engine |
| **Analysis** | `GET` | `/api/security/findings`| Filterable security findings log (severity/status) |
| **Analysis** | `GET` | `/api/security/score` | Current network security score with delta comparison |
| **Threats** | `GET` | `/api/threats` | Active threat analysis, Evil Twin detection, and rogue AP alerts |
| **Threats** | `POST`| `/api/threats/analyze`| Record threat events with confidence levels to database |
| **Threats** | `GET` | `/api/threats/history`| Historical threat event logs |
| **Devices** | `GET` | `/api/devices` | Subnet device inventory with vendor resolution |
| **Devices** | `POST`| `/api/devices/discover`| Trigger active ARP discovery & track presence |
| **Devices** | `POST`| `/api/devices/{id}/trust`| Toggle device hardware allowlist trust status |
| **Devices** | `GET` | `/api/devices/history` | Historical device connection logs |
| **Performance**| `GET` | `/api/performance` | Live latency, jitter, packet loss %, and quality score |
| **Performance**| `POST`| `/api/performance/test` | Execute performance audit & store to history |
| **Performance**| `GET` | `/api/performance/history`| Time-series latency and quality score history |
| **AI Assistant**| `POST`| `/api/ai/chat` | AI cybersecurity assistant chat endpoint |
| **AI Assistant**| `GET` | `/api/ai/recommendations`| AI executive summary & router hardening guidance |
| **ML Module** | `GET` | `/api/ml/anomalies` | Statistical Z-score & spectral anomaly detection |
| **Traffic** | `GET` | `/api/traffic` | Real-time byte transfer rates (RX/TX KB/s) |
| **Alerts** | `GET` | `/api/alerts` | Security alert event log with severity filtering |
| **Alerts** | `POST`| `/api/alerts/clear` | Mark all alerts as read |
| **Alerts** | `PATCH`| `/api/alerts/{id}/read`| Mark specific alert as read |
| **Alerts** | `POST`| `/api/alerts/{id}/ack` | Acknowledge critical alert |
| **Reports** | `POST`| `/api/reports/generate`| Generate PDF/CSV/JSON audit report & save metadata |
| **Reports** | `GET` | `/api/reports` | List generated security reports |
| **Reports** | `GET` | `/api/reports/{id}/download`| Download generated report payload |
| **Export** | `GET` | `/api/export/csv` | RFC-4180 CSV export download |
| **Export** | `GET` | `/api/export/json` | Complete structured JSON audit export |
| **Checklist** | `GET` | `/api/security/checklist`| Router security hardening rules |
| **Knowledge** | `GET` | `/api/knowledge` | Tip of the Day & cybersecurity threat intelligence |

---

## 🧪 Automated Testing

NetGuard includes a complete automated test suite covering all 18 functional modules:

```powershell
python tests/test_system.py
```

Expected result:
```text
=====================================================================
 TOTAL TESTS: 39 | PASSED: 39 | FAILED: 0
=====================================================================
>>> 100% OF ALL SYSTEM & INTEGRATION TESTS PASSED! APPLICATION FULLY FUNCTIONAL. <<<
```

---

## 🔑 Default Administrator Credentials

For initial testing and role-based access:
- **Username**: `admin`
- **Password**: `Admin@NetGuard2026!`
- **Role**: `administrator`

---

## 🔒 Security & Privacy Notice

NetGuard runs strictly in user mode on your authorized local hardware:
- Passwords are recovered only for profiles already authorized and saved on the local Windows device.
- Subnet scans are restricted to the local network gateway subnet.
- No telemetry, keystrokes, or scan data are uploaded to third-party cloud services.

---

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.
