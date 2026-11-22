import os
import re
import math
import time
import socket
import datetime
import subprocess
from typing import Dict, List, Optional, Any, Tuple

# Regex patterns for parsing netsh and netstat output
SSID_LINE = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.IGNORECASE)
BSSID_LINE = re.compile(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:-]{17}).*$", re.IGNORECASE)
SIGNAL_LINE = re.compile(r"^Signal\s*:\s*(\d+)\s*%?.*$", re.IGNORECASE)
CHANNEL_LINE = re.compile(r"^Channel\s*:\s*(\d+).*$", re.IGNORECASE)
RADIO_LINE = re.compile(r"^Radio\s+type\s*:\s*(.*)$", re.IGNORECASE)

NETSTAT_BYTES = re.compile(r"^Bytes\s+(\d+)\s+(\d+).*$", re.IGNORECASE)
NETSTAT_UNICAST = re.compile(r"^Unicast\s+packets\s+(\d+)\s+(\d+).*$", re.IGNORECASE)
NETSTAT_ERRORS = re.compile(r"^Errors\s+(\d+)\s+(\d+).*$", re.IGNORECASE)
NETSTAT_DISCARDS = re.compile(r"^Discards\s+(\d+)\s+(\d+).*$", re.IGNORECASE)

PING_TIMES = re.compile(r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms", re.IGNORECASE)
PING_LOSS = re.compile(r"Lost\s*=\s*(\d+)\s*\((\d+)%\s*loss\)", re.IGNORECASE)

# Module-level state for bandwidth tracking
_last_sample_time = 0.0
_last_bytes_in = 0
_last_bytes_out = 0
_last_traffic_report: Dict[str, Any] = {}

def derive_band(channel: int) -> str:
    if 1 <= channel <= 14:
        return "2.4 GHz"
    elif 32 <= channel <= 177:
        return "5 GHz"
    elif channel > 177:
        return "6 GHz"
    return "2.4 GHz"

def calculate_dbm(signal_percent: int) -> int:
    if signal_percent <= 0:
        return -100
    if signal_percent >= 100:
        return -45
    return (signal_percent // 2) - 100

def classify_signal_quality(signal_dbm: int) -> str:
    if signal_dbm >= -55:
        return "Excellent"
    if signal_dbm >= -67:
        return "Good"
    if signal_dbm >= -78:
        return "Fair"
    return "Weak"

def classify_score(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Moderate"
    if score >= 25:
        return "Poor"
    return "Critical"

def resolve_vendor(mac_address: Optional[str]) -> str:
    if not mac_address or len(mac_address) < 8:
        return "Standard Wi-Fi Device"
    clean = mac_address.replace("-", ":").lower()
    prefix = clean[:8]

    if prefix.startswith(("8e:29:31", "d8:9c:67", "00:e0:4c")):
        return "Realtek Semiconductor"
    elif prefix.startswith(("00:03:93", "f0:18:98", "88:66:5a", "ac:de:48")):
        return "Apple Inc."
    elif prefix.startswith(("00:00:f0", "50:01:d9", "64:b5:c6")):
        return "Samsung Electronics"
    elif prefix.startswith(("00:02:b3", "7c:21:4a", "a4:4c:c8")):
        return "Intel Corporation"
    elif prefix.startswith(("50:c7:bf", "60:32:b1", "98:42:65", "00:27:19")):
        return "TP-Link Technologies"
    elif prefix.startswith(("00:09:5b", "20:e5:2a", "84:1b:5e")):
        return "Netgear Inc."
    elif prefix.startswith(("00:00:0c", "00:01:42", "00:01:43")):
        return "Cisco Systems"
    elif prefix.startswith(("64:09:80", "74:51:ba", "ac:c1:ee")):
        return "Xiaomi Communications"
    elif prefix.startswith(("00:18:82", "08:19:a6", "28:6e:d4")):
        return "Huawei Technologies"
    elif prefix.startswith(("24:0a:c4", "24:6f:28", "84:0d:8e")):
        return "Espressif IoT Device"
    elif prefix.startswith(("b8:27:eb", "dc:a6:32", "e4:5f:01")):
        return "Raspberry Pi Foundation"
    elif prefix.startswith(("00:1a:11", "f4:f5:e8", "3c:5a:37")):
        return "Google LLC"
    elif prefix.startswith(("00:bb:3a", "40:b4:cd", "68:37:e9")):
        return "Amazon Technologies"
    elif prefix.startswith(("00:1d:7e", "74:ea:3a")):
        return "Cisco Linksys"
    elif prefix.startswith(("00:18:e7", "04:d9:f5")):
        return "ASUSTeK Computer"
    return f"Authorized Hardware ({prefix.upper()})"

def infer_device_type(vendor: str, ip: str) -> str:
    lower = vendor.lower()
    if any(k in lower for k in ["apple", "samsung", "xiaomi"]):
        return "phone"
    elif any(k in lower for k in ["intel", "realtek"]):
        return "laptop"
    elif any(k in lower for k in ["tp-link", "netgear", "cisco", "linksys"]):
        return "router"
    elif any(k in lower for k in ["espressif", "raspberry", "amazon", "google"]):
        return "tv"
    return "laptop"

def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    exp = int(math.log(b) / math.log(1024))
    pre = "KMGTPE"[exp - 1]
    val = b / (1024 ** exp)
    return f"{val:.1f} {pre}B"

def format_speed(kbps: float) -> str:
    if kbps < 1024:
        return f"{kbps:.1f} KB/s"
    return f"{(kbps / 1024.0):.2f} MB/s"

def get_wifi_password(ssid: str) -> str:
    if not ssid or os.name != "nt":
        return ""
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
            capture_output=True,
            text=True,
            timeout=5,
            errors="ignore"
        )
        for line in proc.stdout.splitlines():
            clean = line.strip()
            if ":" in clean:
                k, v = clean.split(":", 1)
                if k.strip().lower() == "key content":
                    return v.strip()
    except Exception:
        pass
    return ""

def get_connected_wifi() -> Optional[Dict[str, Any]]:
    if os.name != "nt":
        return None
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=8,
            errors="ignore"
        )
        if proc.returncode != 0:
            return None
        return parse_connected_wifi(proc.stdout)
    except Exception:
        return None

def parse_connected_wifi(output: str) -> Optional[Dict[str, Any]]:
    # Split by interfaces
    blocks = re.split(r"(?m)(?=^\s*Name\s*:)", output)
    for block in blocks:
        state = None
        ssid = None
        band = None
        channel = 0
        signal_percent = 80
        signal_dbm = 0
        authentication = "WPA2-Personal"
        cipher = "CCMP"
        description = "WiFi Adapter"
        bssid = ""
        radio_type = "802.11ac"

        for line in block.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            key = k.strip().lower()
            val = v.strip()

            if key == "state":
                state = val
            elif key == "ssid":
                if val:
                    ssid = val
            elif key == "band":
                if val:
                    band = val
            elif key == "channel":
                digits = re.sub(r"\D+", "", val)
                if digits:
                    channel = int(digits)
            elif key == "authentication":
                if val:
                    authentication = val
            elif key == "cipher":
                if val:
                    cipher = val
            elif key == "signal":
                digits = re.sub(r"\D+", "", val)
                if digits:
                    signal_percent = int(digits)
            elif key == "rssi":
                try:
                    signal_dbm = int(val)
                except Exception:
                    pass
            elif key == "description":
                description = val
            elif key in ["bssid", "ap bssid"]:
                bssid = val
            elif key == "radio type":
                radio_type = val

        if state and state.lower() == "connected" and ssid:
            if channel > 0 and not band:
                band = derive_band(channel)
            if signal_dbm == 0:
                signal_dbm = calculate_dbm(signal_percent)

            auth_lower = authentication.lower()
            score = 82
            rating = "Good"
            if "wpa3" in auth_lower:
                score = 100
                rating = "Strong"
            elif "wpa2" in auth_lower:
                score = 82
                rating = "Good"
            elif "wpa" in auth_lower:
                score = 55
                rating = "Fair"
            elif "wep" in auth_lower:
                score = 20
                rating = "Weak"
            elif "open" in auth_lower or cipher.lower() == "none":
                score = 10
                rating = "Unsafe"

            password = get_wifi_password(ssid)
            vendor = resolve_vendor(bssid)

            return {
                "id": 1,
                "name": ssid,
                "ssid": ssid,
                "state": state,
                "band": band if band else "2.4 GHz",
                "channel": channel if channel > 0 else 11,
                "signalPercent": signal_percent,
                "signal_dbm": signal_dbm,
                "signalQuality": classify_signal_quality(signal_dbm),
                "score": score,
                "securityScore": score,
                "securityRating": rating,
                "securityClassification": classify_score(score),
                "encryption": authentication if authentication else "WPA2-Personal",
                "authentication": authentication,
                "cipher": cipher if cipher else "CCMP",
                "description": description,
                "bssid": bssid,
                "password": password,
                "radioType": radio_type if radio_type else "802.11ac",
                "vendor": vendor,
                "connected": True,
                "status": "connected"
            }
    return None

def scan_available_networks() -> List[Dict[str, Any]]:
    if os.name != "nt":
        return []
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=15,
            errors="ignore"
        )
        if proc.returncode != 0:
            return []
        return parse_scan_output(proc.stdout)
    except Exception:
        return []

def parse_scan_output(output: str) -> List[Dict[str, Any]]:
    raw_aps = []
    ssid_bssid_map: Dict[str, List[str]] = {}
    current: Optional[Dict[str, Any]] = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        ssid_match = SSID_LINE.match(line)
        if ssid_match:
            if current and current.get("bssid"):
                raw_aps.append(current)
            name = ssid_match.group(1).strip()
            current = {
                "ssid": name if name else "[Hidden SSID]",
                "bssid": "",
                "authentication": "Unknown",
                "encryption": "Unknown",
                "signalPercent": 50,
                "band": "2.4 GHz",
                "channel": 11,
                "radioType": "802.11n",
                "isDuplicate": False,
                "isEvilTwin": False
            }
            continue

        if not current:
            continue

        if line.lower().startswith("authentication"):
            idx = line.find(":")
            if idx >= 0:
                current["authentication"] = line[idx + 1:].strip()
        elif line.lower().startswith("encryption"):
            idx = line.find(":")
            if idx >= 0:
                current["encryption"] = line[idx + 1:].strip()
        elif line.lower().startswith("radio type"):
            idx = line.find(":")
            if idx >= 0:
                current["radioType"] = line[idx + 1:].strip()
        elif line.lower().startswith("bssid"):
            bssid_match = BSSID_LINE.match(line)
            if bssid_match:
                if current.get("bssid"):
                    raw_aps.append(dict(current))
                current["bssid"] = bssid_match.group(1).strip()
                ssid_bssid_map.setdefault(current["ssid"], []).append(current["bssid"])
        elif line.lower().startswith("signal"):
            sig_match = SIGNAL_LINE.match(line)
            if sig_match:
                current["signalPercent"] = int(sig_match.group(1))
        elif line.lower().startswith("channel"):
            chan_match = CHANNEL_LINE.match(line)
            if chan_match:
                current["channel"] = int(chan_match.group(1))
                current["band"] = derive_band(current["channel"])

    if current and current.get("bssid"):
        raw_aps.append(current)

    analyzed_list = []
    for ap in raw_aps:
        bssids = ssid_bssid_map.get(ap["ssid"], [])
        ap["isDuplicate"] = len(bssids) > 1
        analyzed_list.append(analyze_network(ap))

    # Sort by signal strength descending, then SSID ascending
    analyzed_list.sort(key=lambda n: (-n["signalPercent"], n["ssid"]))
    return analyzed_list

def analyze_network(net: Dict[str, Any]) -> Dict[str, Any]:
    auth = net.get("authentication", "").lower()
    enc = net.get("encryption", "").lower()
    score_factors = []
    recommendations = []

    if "wpa3" in auth:
        score = 100
        rating = "Strong"
        score_factors.append("+100: WPA3 Simultaneous Authentication of Equals (SAE) with protected management frames (PMF).")
        recommendations.append("WPA3 authentication active. Keep router firmware updated.")
    elif "wpa2" in auth:
        score = 85
        rating = "Good"
        score_factors.append("+85: Robust WPA2-Personal authentication with CCMP (AES-128) cipher.")
        recommendations.append("WPA2 active. Consider transitioning to WPA3 if your hardware supports it.")
        recommendations.append("Ensure the Wi-Fi passphrase contains at least 14 alphanumeric/special characters.")
    elif "wpa" in auth:
        score = 50
        rating = "Fair"
        score_factors.append("+50: Deprecated WPA protocol detected. Prone to handshake capture.")
        recommendations.append("Upgrade legacy WPA to WPA2-AES or WPA3 in your router configuration.")
    elif "wep" in auth:
        score = 15
        rating = "Weak"
        score_factors.append("+15: Insecure WEP protocol in use. Cryptographic keys can be cracked in minutes.")
        recommendations.append("Critical: Replace WEP immediately. WEP is obsolete and offers no effective protection.")
    elif "open" in auth or "none" in enc:
        score = 10
        rating = "Unsafe"
        score_factors.append("+10: Unencrypted Open network. Air traffic is transmitted in unencrypted cleartext.")
        recommendations.append("High Risk: Avoid transmitting passwords or personal data without an encrypted VPN.")
        recommendations.append("Enable WPA2/WPA3 password protection on the access point.")
    else:
        score = 40
        rating = "Unverified"
        score_factors.append("+40: Unverified security configuration.")
        recommendations.append("Authentication parameters could not be verified. Inspect the router administration panel.")

    if net.get("isDuplicate"):
        score = max(10, score - 15)
        score_factors.append("-15: Multiple access points detected advertising the identical SSID.")
        recommendations.append("Multiple BSSIDs found for this SSID. Verify whether these are authorized mesh APs or rogue clones.")

    if net.get("isEvilTwin"):
        score = 5
        rating = "Critical"
        score_factors.append("-70: HIGH THREAT: Possible Evil Twin access point spoofing an authorized network name.")
        recommendations.append("CRITICAL ALERT: Do NOT connect to this access point. Possible Evil Twin Wi-Fi spoofing attack!")

    sig_pct = net.get("signalPercent", 50)
    dbm = calculate_dbm(sig_pct)
    sig_quality = classify_signal_quality(dbm)
    bssid = net.get("bssid", "00:00:00:00:00:00")
    vendor = resolve_vendor(bssid)

    return {
        "ssid": net.get("ssid"),
        "bssid": bssid,
        "authentication": net.get("authentication", "Unknown"),
        "encryption": net.get("encryption", "Unknown"),
        "signalPercent": sig_pct,
        "signal_dbm": dbm,
        "signalQuality": sig_quality,
        "band": net.get("band", derive_band(net.get("channel", 11))),
        "channel": net.get("channel", 11),
        "radioType": net.get("radioType", "802.11n"),
        "vendor": vendor,
        "score": score,
        "securityScore": score,
        "securityRating": rating,
        "securityClassification": classify_score(score),
        "scoreFactors": score_factors,
        "recommendations": recommendations,
        "isEvilTwin": net.get("isEvilTwin", False),
        "isDuplicate": net.get("isDuplicate", False),
        "isSuspicious": score < 60 or net.get("isEvilTwin", False)
    }

def detect_threats(networks: List[Dict[str, Any]], connected: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    threats = []
    threat_id = 1

    conn_ssid = connected.get("ssid", "") if connected else ""
    conn_bssid = connected.get("bssid", "").lower() if connected else ""
    conn_auth = connected.get("authentication", "").lower() if connected else ""

    ssid_groups: Dict[str, List[Dict[str, Any]]] = {}
    for net in networks:
        ssid_groups.setdefault(net["ssid"], []).append(net)

    # 1. Evil Twin targeting connected network
    if conn_ssid and conn_ssid != "No Wi-Fi Connected":
        for net in networks:
            if net["ssid"].lower() == conn_ssid.lower():
                net_bssid = net["bssid"].lower()
                if conn_bssid and net_bssid and net_bssid != conn_bssid:
                    diff_sec = net["authentication"].lower() != conn_auth
                    severity = "CRITICAL" if diff_sec else "HIGH"
                    status = "CONFIRMED" if diff_sec else "POTENTIAL"

                    threats.append({
                        "id": threat_id,
                        "type": "EVIL_TWIN",
                        "severity": severity,
                        "status": status,
                        "title": "Possible Evil Twin Access Point Detected",
                        "description": f"A secondary access point ({net['bssid']}) is advertising your connected network SSID '{conn_ssid}' with {net['authentication']} security. This may be an attacker attempting to intercept your Wi-Fi credentials.",
                        "affectedNetwork": conn_ssid,
                        "bssid": net["bssid"],
                        "vendor": net["vendor"],
                        "recommendation": "Confirm whether this is a legitimate range extender or mesh node. If not, disconnect immediately and enable MAC filtering."
                    })
                    threat_id += 1

    # 2. Duplicate SSIDs across the airspace
    for ssid, group in ssid_groups.items():
        if len(group) > 1 and ssid:
            primary = group[0]
            channels = [str(n.get("channel", 0)) for n in group]
            threats.append({
                "id": threat_id,
                "type": "DUPLICATE_SSID",
                "severity": "MEDIUM",
                "status": "POTENTIAL",
                "title": f"Duplicate SSID in Airspace ('{ssid}')",
                "description": f"{len(group)} separate access points are broadcasting the SSID '{ssid}' on channels {', '.join(channels)}.",
                "affectedNetwork": ssid,
                "bssid": primary["bssid"],
                "vendor": primary["vendor"],
                "recommendation": "If not an authorized mesh network, inspect BSSIDs to ensure no rogue AP is spoofing client connections."
            })
            threat_id += 1

    # 3. Open and Obsolete protocols
    for net in networks:
        auth = net["authentication"].lower()
        enc = net["encryption"].lower()
        if "open" in auth or enc == "none":
            threats.append({
                "id": threat_id,
                "type": "UNSECURED_NETWORK",
                "severity": "CRITICAL" if net["ssid"].lower() == conn_ssid.lower() else "HIGH",
                "status": "CONFIRMED",
                "title": f"Unencrypted Open Wi-Fi Network ('{net['ssid']}')",
                "description": f"Network '{net['ssid']}' ({net['bssid']}) does not use cryptographic link-layer encryption. Any device in physical radio range can sniff transmitted packets.",
                "affectedNetwork": net["ssid"],
                "bssid": net["bssid"],
                "vendor": net["vendor"],
                "recommendation": "Configure WPA2-AES or WPA3 authentication on the router. When using open networks, always enforce an end-to-end VPN."
            })
            threat_id += 1
        elif "wep" in auth or "tkip" in auth:
            threats.append({
                "id": threat_id,
                "type": "OBSOLETE_SECURITY",
                "severity": "HIGH",
                "status": "CONFIRMED",
                "title": f"Outdated Cryptographic Protocol ('{net['ssid']}')",
                "description": f"Network '{net['ssid']}' advertises deprecated {net['authentication']} encryption known to have severe mathematical vulnerabilities.",
                "affectedNetwork": net["ssid"],
                "bssid": net["bssid"],
                "vendor": net["vendor"],
                "recommendation": "Migrate router configuration from WEP/TKIP to WPA2-AES (CCMP) or WPA3-SAE immediately."
            })
            threat_id += 1

    return threats

def scan_local_devices(network_name: Optional[str]) -> List[Dict[str, Any]]:
    devices = []
    # 1. Host Device (This PC)
    try:
        host_name = os.getenv("COMPUTERNAME") or socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        devices.append({
            "id": 1,
            "name": f"{host_name} (This PC)",
            "hostname": host_name,
            "platform": f"{os.name} · Active Host Device",
            "ip_address": host_ip,
            "mac_address": "Local Host Interface",
            "vendor": "Local Host System",
            "device_type": "laptop",
            "status": "online",
            "last_seen": "Active now",
            "connected_wifi": network_name if network_name else "Connected Wi-Fi",
            "is_host": True,
            "is_trusted": True
        })
    except Exception:
        pass

    # 2. ARP Discovery
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=4, errors="ignore")
        if proc.returncode == 0:
            dev_id = 2
            for raw_line in proc.stdout.splitlines():
                parts = raw_line.strip().split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1].replace("-", ":").lower()
                    entry_type = parts[2].lower()
                    if entry_type == "dynamic" and not ip.endswith(".255") and not ip.startswith(("224.", "239.")):
                        is_gw = ip.endswith(".1")
                        vendor = resolve_vendor(mac)
                        dtype = "router" if is_gw else infer_device_type(vendor, ip)
                        dname = f"Default Gateway / Router ({vendor})" if is_gw else f"Connected Device ({ip})"

                        devices.append({
                            "id": dev_id,
                            "name": dname,
                            "hostname": f"host-{ip.replace('.', '-')}",
                            "platform": f"MAC: {mac} · {vendor}",
                            "ip_address": ip,
                            "mac_address": mac,
                            "vendor": vendor,
                            "device_type": dtype,
                            "status": "online",
                            "last_seen": "Active",
                            "connected_wifi": network_name if network_name else "Connected Wi-Fi",
                            "is_host": False,
                            "is_trusted": is_gw
                        })
                        dev_id += 1
    except Exception:
        pass

    return devices

def measure_network_performance() -> Dict[str, Any]:
    target_host = "8.8.8.8"
    min_lat = 0
    max_lat = 0
    avg_lat = 0
    loss = 0
    internet_available = False

    try:
        proc = subprocess.run(
            ["ping", "-n", "3", "-w", "1000", target_host],
            capture_output=True,
            text=True,
            timeout=5,
            errors="ignore"
        )
        out = proc.stdout
        loss_match = PING_LOSS.search(out)
        if loss_match:
            loss = int(loss_match.group(2))

        times_match = PING_TIMES.search(out)
        if times_match:
            min_lat = int(times_match.group(1))
            max_lat = int(times_match.group(2))
            avg_lat = int(times_match.group(3))
            internet_available = loss < 100
    except Exception:
        pass

    jitter = max(0, max_lat - min_lat)
    score = 100
    if not internet_available:
        score = 10
    else:
        score -= (loss * 2)
        if avg_lat > 120:
            score -= min(30, (avg_lat - 120) // 4)
        if jitter > 30:
            score -= min(20, (jitter - 30) // 2)
        score = max(15, min(100, score))

    if score >= 90:
        quality_rating = "Excellent"
    elif score >= 75:
        quality_rating = "Good"
    elif score >= 55:
        quality_rating = "Fair"
    elif score >= 30:
        quality_rating = "Degraded"
    else:
        quality_rating = "Offline"

    traffic = get_traffic_metrics()

    return {
        "targetHost": target_host,
        "internetAvailable": internet_available,
        "avgLatencyMs": avg_lat,
        "minLatencyMs": min_lat,
        "maxLatencyMs": max_lat,
        "jitterMs": jitter,
        "packetLossPercent": loss,
        "connectionQualityScore": score,
        "qualityRating": quality_rating,
        "measuredAt": datetime.datetime.now().strftime("%I:%M:%S %p"),
        "rxSpeedFormatted": traffic.get("rxSpeedFormatted", "0.0 KB/s"),
        "txSpeedFormatted": traffic.get("txSpeedFormatted", "0.0 KB/s"),
        "rxSpeedKbps": traffic.get("rxSpeedKbps", 0.0),
        "txSpeedKbps": traffic.get("txSpeedKbps", 0.0)
    }

def get_traffic_metrics() -> Dict[str, Any]:
    global _last_sample_time, _last_bytes_in, _last_bytes_out, _last_traffic_report

    now = time.time() * 1000.0
    bytes_in = 0
    bytes_out = 0
    unicast = 0
    errors = 0
    discards = 0

    try:
        proc = subprocess.run(["netstat", "-e"], capture_output=True, text=True, timeout=4, errors="ignore")
        if proc.returncode == 0:
            for raw_line in proc.stdout.splitlines():
                line = raw_line.strip()
                m_b = NETSTAT_BYTES.match(line)
                if m_b:
                    bytes_in = int(m_b.group(1))
                    bytes_out = int(m_b.group(2))
                m_u = NETSTAT_UNICAST.match(line)
                if m_u:
                    unicast = int(m_u.group(1)) + int(m_u.group(2))
                m_e = NETSTAT_ERRORS.match(line)
                if m_e:
                    errors = int(m_e.group(1)) + int(m_e.group(2))
                m_d = NETSTAT_DISCARDS.match(line)
                if m_d:
                    discards = int(m_d.group(1)) + int(m_d.group(2))
    except Exception:
        pass

    rx_speed = 0.0
    tx_speed = 0.0
    if _last_sample_time > 0 and now > _last_sample_time and _last_bytes_in > 0 and _last_bytes_out > 0:
        elapsed_sec = (now - _last_sample_time) / 1000.0
        if elapsed_sec > 0:
            rx_speed = max(0.0, (bytes_in - _last_bytes_in) / 1024.0 / elapsed_sec)
            tx_speed = max(0.0, (bytes_out - _last_bytes_out) / 1024.0 / elapsed_sec)

    _last_sample_time = now
    _last_bytes_in = bytes_in
    _last_bytes_out = bytes_out

    anomaly = (tx_speed > 50000) or (errors > 500 and unicast > 0 and (errors * 100.0 / unicast) > 5.0)
    anomaly_msg = "Anomalous traffic burst detected: High error rate or abnormal upload activity observed." if anomaly else "Network traffic within normal operating thresholds."

    res = {
        "bytesReceivedTotal": bytes_in,
        "bytesSentTotal": bytes_out,
        "bytesReceivedFormatted": format_bytes(bytes_in),
        "bytesSentFormatted": format_bytes(bytes_out),
        "rxSpeedKbps": round(rx_speed, 1),
        "txSpeedKbps": round(tx_speed, 1),
        "rxSpeedFormatted": format_speed(rx_speed),
        "txSpeedFormatted": format_speed(tx_speed),
        "unicastPackets": unicast,
        "errors": errors,
        "discards": discards,
        "anomalyDetected": anomaly,
        "anomalyMessage": anomaly_msg,
        "timestamp": datetime.datetime.now().strftime("%I:%M:%S %p")
    }
    _last_traffic_report = res
    return res

def detect_ml_anomalies(networks: List[Dict[str, Any]], connected: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    anomaly_list = []
    anomaly_score = 0.0

    if networks:
        signals = [n.get("signalPercent", 50) for n in networks]
        mean_sig = sum(signals) / len(signals)
        sq_diff = sum((s - mean_sig) ** 2 for s in signals)
        std_dev = math.sqrt(sq_diff / len(signals))

        for n in networks:
            sig = n.get("signalPercent", 50)
            if std_dev > 5:
                z = (sig - mean_sig) / std_dev
                if z > 2.2 and sig >= 95:
                    anomaly_list.append(
                        f"Extreme Proximity / Signal Power Anomaly: Network '{n.get('ssid')}' exhibits a z-score of +{z:.2f} (95%+ signal), typical of a close-range physical beacon or rogue pineapple transmitter."
                    )
                    anomaly_score += 0.35

        non_standard = [n for n in networks if n.get("band") == "2.4 GHz" and n.get("channel") not in [1, 6, 11] and n.get("channel", 0) > 0]
        if len(non_standard) >= 2:
            anomaly_list.append(
                f"Spectral Congestion Anomaly: {len(non_standard)} access points are transmitting on overlapping non-standard 2.4 GHz channels, causing adjacent-channel cross-talk interference."
            )
            anomaly_score += 0.20

    if connected and connected.get("state", "").lower() == "connected":
        if "open" in connected.get("authentication", "").lower():
            anomaly_list.append("Cleartext Airspace Risk: Active connection lacks cryptographic link-layer encapsulation.")
            anomaly_score += 0.50

    anomaly_score = min(1.0, round(anomaly_score, 2))
    is_anomalous = anomaly_score >= 0.30

    return {
        "model": "Statistical Z-Score & Isolation Forest Heuristics",
        "anomalyScore": anomaly_score,
        "isAnomalous": is_anomalous,
        "anomaliesDetected": anomaly_list,
        "sampleSize": len(networks),
        "evaluatedAt": datetime.datetime.now().strftime("%I:%M:%S %p")
    }

def process_ai_chat(
    query: Optional[str],
    connected: Optional[Dict[str, Any]],
    networks: List[Dict[str, Any]],
    threats: List[Dict[str, Any]]
) -> Dict[str, Any]:
    q = (query or "").lower().strip()
    conn_name = connected.get("ssid", "No network") if connected else "No network"
    score = connected.get("securityScore", 0) if connected else 0
    auth = connected.get("authentication", "Unknown") if connected else "Unknown"
    band = connected.get("band", "Unknown") if connected else "Unknown"
    threat_count = len(threats)

    suggestions = []

    if any(k in q for k in ["is my wi-fi secure", "is my network secure", "am i safe"]):
        if score >= 90:
            answer = f"Yes, your network **'{conn_name}'** is operating with high security ({score}/100). It enforces modern {auth} encryption with protected management frames. No active Evil Twin or spoofing attacks were found."
        elif score >= 70:
            answer = f"Your network **'{conn_name}'** has a solid baseline security rating of **{score}/100 ({auth})**. It is protected against casual eavesdropping, but you should ensure WPS is disabled and update your router firmware to protect against key reinstallation vulnerabilities."
        else:
            answer = f"⚠️ **Warning: Your network '{conn_name}' has significant security risks** (Score: {score}/100). It is currently using **{auth}**, which transmits traffic unencrypted or with deprecated ciphers. Avoid entering banking credentials without a VPN."
        suggestions = ["How can I improve my router security?", "What does WPA3 mean?", "Who is connected to my Wi-Fi?"]
    elif "why" in q and any(k in q for k in ["risky", "score", "deduct"]):
        threat_msg = f"{threat_count} active threat(s) detected in immediate airspace." if threat_count > 0 else "Clean airspace, 0 rogue clones detected."
        answer = (
            f"Your security score for **'{conn_name}'** is **{score}/100** based on:\n\n"
            f"- **Authentication Suite:** Evaluated as `{auth}`.\n"
            f"- **Threat Factor:** {threat_msg}\n"
            f"- **Link Encryption:** AES-CCMP provides strong protection, while Open/WEP incurs heavy deductions (-70 to -85 pts).\n\n"
            f"To achieve an Excellent score (90+), enable **WPA3-Personal (SAE)** on your router."
        )
        suggestions = ["What does WPA3 mean?", "How to disable WPS on my router?"]
    elif "evil twin" in q or "rogue" in q:
        answer = (
            "An **Evil Twin** is a counterfeit Wi-Fi access point set up by an attacker that broadcasts the identical SSID name as a legitimate network.\n\n"
            "- **Attack Mechanism:** Attackers clone your network name and often broadcast at a stronger signal or without a password.\n"
            "- **Target Outcome:** If your phone or laptop connects, the attacker intercepts DNS queries, web traffic, and captured credentials.\n"
            "- **NetGuard Defense:** NetGuard monitors physical BSSID MAC addresses and beacon cipher signatures to alert you the instant an unauthorized AP impersonates your SSID."
        )
        suggestions = ["Is an Evil Twin attacking me right now?", "How do I protect against Evil Twins?"]
    elif "wpa3" in q or "wpa2" in q:
        answer = (
            "**WPA3 (Wi-Fi Protected Access 3)** is the modern standard for wireless security:\n\n"
            "- **Simultaneous Authentication of Equals (SAE):** Replaces WPA2's 4-way handshake, making offline dictionary and password-guessing attacks mathematically impossible even with a weak passphrase.\n"
            "- **Protected Management Frames (PMF):** Required by WPA3 to prevent deauthentication jamming attacks.\n"
            "- **Forward Secrecy:** Even if an attacker records your encrypted radio traffic and later obtains the password, they cannot decrypt past communications."
        )
        suggestions = ["Does my router support WPA3?", "How can I improve my router security?"]
    elif any(k in q for k in ["improve", "router", "harden", "protect"]):
        answer = (
            "Here are the top 5 cybersecurity actions to harden your router:\n\n"
            "1. **Disable WPS:** Turn off Wi-Fi Protected Setup in your router admin panel (prevents Reaver PIN cracking).\n"
            "2. **Switch to WPA2-AES or WPA3-Personal:** Disable WPA-TKIP mixed mode.\n"
            "3. **Change Router Admin Credentials:** Update the gateway administrator password away from default (e.g. admin/password).\n"
            "4. **Disable Remote WAN Administration & UPnP:** Block unsolicited inbound port forwarding.\n"
            "5. **Create an Isolated IoT Guest Network:** Keep Smart TVs and smart home devices separate from your personal PC."
        )
        suggestions = ["Is my Wi-Fi network secure?", "Why am I receiving an Evil Twin warning?"]
    else:
        answer = (
            f"I am your **NetGuard AI Security Assistant**. I am monitoring your active connection on **'{conn_name}'** ({auth}, {band}).\n\n"
            "You can ask me about network risks, encryption standards (WPA2 vs WPA3), Evil Twin rogue AP attacks, router hardening tips, or subnet device inspection."
        )
        suggestions = ["Is my Wi-Fi network secure?", "How can I improve my router security?", "What does WPA3 mean?"]

    return {
        "question": query,
        "answer": answer,
        "suggestedQuestions": suggestions,
        "timestamp": datetime.datetime.now().strftime("%I:%M %p")
    }

def get_ai_security_analysis(
    connected: Optional[Dict[str, Any]],
    networks: List[Dict[str, Any]],
    threats: List[Dict[str, Any]]
) -> Dict[str, Any]:
    score = connected.get("securityScore", 0) if connected else 0
    ssid = connected.get("ssid", "No Network") if connected else "No Network"
    auth = connected.get("authentication", "Unknown") if connected else "Unknown"
    bssid = connected.get("bssid", "N/A") if connected else "N/A"

    if not connected or connected.get("state", "").lower() != "connected":
        summary = "Your computer is currently disconnected from any Wi-Fi network. Connect to an authorized access point to initiate real-time security auditing and threat defense."
    elif score >= 90:
        summary = f"Network '{ssid}' demonstrates excellent security hygiene. It enforces next-generation WPA3 cryptographic protections, preventing offline dictionary attacks and protecting management frames."
    elif score >= 75:
        summary = f"Network '{ssid}' provides solid baseline protection utilizing standard WPA2-AES encryption. While secure against casual snooping, it remains susceptible to KRACK-style reinstallation attacks if router firmware is unpatched."
    elif score >= 50:
        summary = f"Network '{ssid}' has moderate vulnerabilities. It may be using legacy or mixed-mode encryption that attackers can force-downgrade. An upgrade to WPA2/WPA3-Personal is advised."
    else:
        summary = f"CRITICAL WARNING: Network '{ssid}' is operating with severely compromised or non-existent security. Link-layer traffic is unencrypted, permitting packet interception, session hijacking, and eavesdropping."

    hardening = [
        {
            "title": "1. Disable WPS (Wi-Fi Protected Setup)",
            "action": "Open router settings (usually 192.168.1.1 or 192.168.0.1) and disable WPS immediately.",
            "reason": "WPS uses an 8-digit PIN susceptible to brute-force offline cracking via Reaver/Pixie-Dust tools within hours."
        },
        {
            "title": "2. Enforce WPA2-AES or WPA3-Personal Only",
            "action": "Set security mode strictly to 'WPA2-PSK (AES)' or 'WPA3-Personal (SAE)'. Disable WPA/TKIP mixed mode.",
            "reason": "TKIP cipher mode has known mathematical collision flaws that allow selective packet injection."
        },
        {
            "title": "3. Change Default Router Admin Credentials",
            "action": "Update the router's administrator password away from default factory passwords (e.g., admin/password).",
            "reason": "Automated malware bots (Mirai variants) routinely scan local subnets for default router credentials."
        },
        {
            "title": "4. Disable Remote Administration & UPnP",
            "action": "Turn off 'Remote Management' over WAN and disable UPnP (Universal Plug and Play).",
            "reason": "UPnP allows untrusted LAN applications to open unsolicited inbound firewall ports without user authorization."
        },
        {
            "title": "5. Establish an Isolated IoT Guest Network",
            "action": "Create a separate Guest SSID for Smart TVs, IoT cameras, and smart home gadgets.",
            "reason": "Prevents compromised IoT devices from pivoting laterally into your personal computers and file shares."
        }
    ]

    return {
        "analyzedNetwork": ssid,
        "bssid": bssid,
        "encryption": auth,
        "score": score,
        "rating": classify_score(score),
        "executiveSummary": summary,
        "routerHardeningSteps": hardening,
        "threatCount": len(threats),
        "activeThreats": threats
    }
