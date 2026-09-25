"""
CyberShield Wi-Fi Security Analyzer & Spectrum Auditor
Defensive WLAN Security Analysis & Risk Assessment Engine.

Evaluates Wi-Fi network configurations against cybersecurity standards
(NIST SP 800-153, CIS Wireless Guidelines, and Wi-Fi Alliance specifications).
Utilizes a project-defined risk assessment scoring model.
"""
import re
from typing import Dict, List, Any


def evaluate_network_security(network: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates an 802.11 access point configuration using the CyberShield
    project-defined risk model and assigns a security score, risk level,
    vulnerability findings, and security recommendations.

    Project Risk Model Baseline:
      - WPA3 + strong encryption         -> LOW risk (Score: 98, Grade A+)
      - WPA2-Personal + CCMP/AES         -> LOW risk (Score: 85, Grade A)
      - WPA/WPA2 mixed or WPA-Personal   -> MODERATE risk (Score: 60, Grade B)
      - WEP (Wired Equivalent Privacy)    -> HIGH risk (Score: 25, Grade D)
      - Open / unencrypted               -> CRITICAL risk (Score: 10, Grade F)

    Notice: This score is calculated using the CyberShield Project Risk
    Assessment Model designed for educational and defensive auditing purposes.
    """
    auth = str(network.get("authentication", "Open")).strip()
    enc = str(network.get("encryption", "None")).strip()
    is_hidden = network.get("is_hidden", False)

    auth_upper = auth.upper()
    enc_upper = enc.upper()

    score = 85
    risk_level = "LOW"  # CRITICAL, HIGH, MODERATE, LOW
    grade = "A"
    explanation = ""
    recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
    recommendations: List[str] = []
    vulnerabilities: List[Dict[str, str]] = []
    badges: List[Dict[str, str]] = []

    # Detection flags
    is_open = ("OPEN" in auth_upper) or ("NONE" in enc_upper) or (enc_upper == "NONE")
    is_wep = ("WEP" in auth_upper) or ("WEP" in enc_upper)
    is_wpa3 = "WPA3" in auth_upper
    is_mixed = ("/" in auth) or ("MIXED" in auth_upper) or (
        bool(re.search(r'\bWPA\b', auth_upper)) and bool(re.search(r'\bWPA2\b', auth_upper))
    )
    is_tkip = "TKIP" in enc_upper
    is_wpa1 = bool(re.search(r'\bWPA\b', auth_upper)) and not bool(re.search(r'WPA[23]', auth_upper))

    # 1. Open / Unencrypted Wireless (CRITICAL)
    if is_open:
        score = 10
        risk_level = "CRITICAL"
        grade = "F"
        explanation = (
            "This network is completely unencrypted. All wireless frames are transmitted in cleartext, "
            "allowing any device within radio range to capture passwords, session cookies, and personal traffic "
            "using passive packet sniffers."
        )
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        vulnerabilities.append({
            "severity": "CRITICAL",
            "title": "Unencrypted Cleartext 802.11 Airspace",
            "cwe": "CWE-311: Missing Encryption of Sensitive Data",
            "description": "Frames are broadcast without cryptographic encryption, exposing all communications to passive interception.",
            "impact": "Total confidentiality loss, credential harvesting, session hijacking, and vulnerability to rogue portal injection."
        })
        recommendations.append("Immediately enable WPA2-Personal (AES) or WPA3-Personal on this access point.")
        recommendations.append("Avoid entering sensitive credentials without an end-to-end encrypted VPN tunnel.")
        badges.append({"type": "critical", "label": "No Encryption (Open)"})

    # 2. Legacy WEP Protocol (HIGH)
    elif is_wep:
        score = 25
        risk_level = "HIGH"
        grade = "D"
        explanation = (
            "This network uses legacy WEP (Wired Equivalent Privacy), an obsolete protocol with weak 24-bit "
            "Initialization Vectors and vulnerable RC4 stream encryption. The master key can be recovered within "
            "minutes via automated cryptanalytic tools."
        )
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        vulnerabilities.append({
            "severity": "HIGH",
            "title": "Broken WEP Cryptographic Standard",
            "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "description": "WEP's short IV space and flawed key scheduling allow rapid automated mathematical key recovery.",
            "impact": "Trivial unauthorized network penetration and complete traffic decryption."
        })
        recommendations.append("Upgrade router security to WPA2-Personal (AES/CCMP) or WPA3.")
        recommendations.append("Retire legacy router hardware that does not support modern WPA2/WPA3 standards.")
        badges.append({"type": "danger", "label": "WEP Broken"})

    # 3. WPA3 Next-Generation Protocol (LOW / SECURE)
    elif is_wpa3:
        score = 98
        risk_level = "LOW"
        grade = "A+"
        explanation = (
            "Modern WPA3 security standard featuring Simultaneous Authentication of Equals (SAE Dragonfly handshake) "
            "and mandatory Protected Management Frames (PMF). Defends against offline dictionary attacks and deauthentication spoofing."
        )
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        recommendations.append("Optimal configuration. Verify all connecting client devices support WPA3-SAE.")
        recommendations.append("Keep router firmware updated with manufacturer security patches.")
        badges.append({"type": "success", "label": "WPA3 Protected"})
        badges.append({"type": "success", "label": "PMF Active"})

    # 4. Mixed WPA/WPA2 or TKIP Cipher (MODERATE)
    elif is_mixed or is_tkip:
        score = 60
        risk_level = "MODERATE"
        grade = "B"
        explanation = (
            "This access point is configured in backward-compatibility mode (WPA/WPA2 mixed or TKIP cipher). "
            "Allowing legacy TKIP exposes the network to cryptographic downgrade attacks and limits speed to 54 Mbps."
        )
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        vulnerabilities.append({
            "severity": "MODERATE",
            "title": "Mixed Security / Deprecated TKIP Fallback Enabled",
            "cwe": "CWE-327: Deprecated Cryptographic Cipher Allowed",
            "description": "TKIP was officially deprecated by the Wi-Fi Alliance in 2012 due to known packet injection and keystream recovery weaknesses.",
            "impact": "Exposes network to downgrade attacks and limits maximum wireless throughput."
        })
        recommendations.append("In router settings, set security to pure WPA2-PSK (AES) and disable WPA/TKIP mixed mode.")
        badges.append({"type": "warning", "label": "Mixed / TKIP"})

    # 5. Standard WPA2-Personal / Enterprise with CCMP/AES (LOW / SECURE)
    elif "WPA2" in auth_upper:
        score = 85
        risk_level = "LOW"
        grade = "A"
        explanation = (
            "Standard robust WPA2 implementation utilizing Counter Mode CBC-MAC Protocol (CCMP) with 128-bit AES encryption. "
            "Provides reliable confidentiality and integrity against over-the-air interception."
        )
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        recommendations.append("Ensure pre-shared passphrase has high entropy (16+ characters with mixed case, digits, and symbols).")
        recommendations.append("Enable Protected Management Frames (802.11w / PMF) in router settings if available.")
        badges.append({"type": "success", "label": "WPA2-CCMP (AES)"})

    # 6. Legacy First-Generation WPA-Personal (HIGH)
    elif is_wpa1:
        score = 40
        risk_level = "HIGH"
        grade = "D"
        explanation = (
            "First-generation WPA is outdated, susceptible to key recovery vulnerabilities, and relies on deprecated TKIP ciphers."
        )
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        vulnerabilities.append({
            "severity": "HIGH",
            "title": "Deprecated WPA1 Protocol In Use",
            "cwe": "CWE-326: Inadequate Encryption Strength",
            "description": "WPA1 lacks modern AES encryption and suffers from message integrity verification weaknesses.",
            "impact": "Vulnerable to keystream extraction and packet injection attacks."
        })
        recommendations.append("Upgrade router settings to WPA2-AES or WPA3.")
        badges.append({"type": "danger", "label": "WPA1 Deprecated"})

    # 7. Unrecognized authentication fallback
    else:
        score = 70
        risk_level = "MODERATE"
        grade = "B"
        explanation = f"Network utilizes {auth} authentication with {enc} encryption."
        recommendation = "Use WPA3 or WPA2-AES/CCMP and avoid legacy WEP or open authentication."
        badges.append({"type": "info", "label": auth})

    # Hidden SSID Evaluation (Privacy & Obscurity finding)
    if is_hidden:
        score = max(score - 5, 0)
        vulnerabilities.append({
            "severity": "LOW",
            "title": "Hidden SSID (Privacy Leak & False Sense of Security)",
            "cwe": "CWE-656: Reliance on Security Through Obscurity",
            "description": (
                "Hiding the SSID does not conceal wireless beacons from spectrum tools. Client devices configured "
                "for hidden networks continuously transmit directed probe requests, broadcasting past connection history."
            ),
            "impact": "Client tracking across locations and increased battery consumption without cryptographic protection."
        })
        recommendations.append("Un-hide SSID and rely on robust WPA2/WPA3 authentication instead of obscurity.")
        badges.append({"type": "warning", "label": "Hidden SSID"})

    # Map risk category for breakdown
    # Categories: CRITICAL, HIGH, MODERATE, SECURE
    risk_category = "SECURE" if risk_level == "LOW" else risk_level

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_category": risk_category,
        "grade": grade,
        "explanation": explanation,
        "recommendation": recommendation,
        "recommendations": recommendations,
        "vulnerabilities": vulnerabilities,
        "badges": badges,
        "model_name": "CyberShield Project Risk Assessment Model"
    }


def analyze_scan_results(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Performs full security audit on scanned networks, calculating:
      1. Airspace Security Health Score (dynamic, calculated from detected networks)
      2. Vulnerability Breakdown counts (CRITICAL, HIGH, MODERATE, SECURE)
      3. 2.4 GHz Channel Overlap and Congestion Analysis
      4. Rogue AP / Evil Twin heuristics
    """
    networks = scan_data.get("networks", [])
    analyzed_networks: List[Dict[str, Any]] = []

    critical_count = 0
    high_count = 0
    moderate_count = 0
    safe_count = 0

    # Map SSIDs to identify potential Evil Twins / Duplicate SSIDs
    ssid_map: Dict[str, List[Dict[str, Any]]] = {}

    for net in networks:
        ssid = net.get("ssid", "[Unknown]")
        sec_eval = evaluate_network_security(net)
        net["security"] = sec_eval

        risk = sec_eval["risk_level"]
        if risk == "CRITICAL":
            critical_count += 1
        elif risk == "HIGH":
            high_count += 1
        elif risk == "MODERATE":
            moderate_count += 1
        else:
            safe_count += 1

        if ssid not in ssid_map:
            ssid_map[ssid] = []
        ssid_map[ssid].append(net)

        analyzed_networks.append(net)

    # Evil Twin / Rogue AP Detection Heuristic
    rogue_alerts: List[Dict[str, Any]] = []
    for ssid, net_list in ssid_map.items():
        if ssid in ("[Hidden Network]", "[Unknown]") or len(net_list) <= 1:
            continue

        # Check if identical SSID has conflicting authentication/encryption
        auth_types = set(n.get("authentication") for n in net_list)
        enc_types = set(n.get("encryption") for n in net_list)

        if len(auth_types) > 1 or len(enc_types) > 1:
            rogue_alerts.append({
                "ssid": ssid,
                "type": "EVIL_TWIN_MISMATCH",
                "severity": "CRITICAL",
                "title": f"Potential Evil Twin / Rogue AP Detected on '{ssid}'",
                "description": (
                    f"Multiple access points are broadcasting the SSID '{ssid}' with differing security suites "
                    f"({', '.join(auth_types)}). An adversary may be operating a rogue AP to harvest credentials."
                ),
                "recommendation": "Do not connect to unverified BSSIDs of this network. Verify the AP MAC address with your network administrator."
            })

    # Channel Congestion & Distribution (2.4 GHz and 5 GHz)
    channels_24: Dict[int, int] = {ch: 0 for ch in range(1, 15)}
    channels_5: Dict[int, int] = {}

    for net in analyzed_networks:
        for bssid in net.get("bssids", []):
            ch = bssid.get("channel", 0)
            if 1 <= ch <= 14:
                channels_24[ch] = channels_24.get(ch, 0) + 1
            elif ch > 14:
                channels_5[ch] = channels_5.get(ch, 0) + 1

    # Overlap warning for non-standard 2.4GHz channels (anything other than 1, 6, 11)
    non_standard_channels = [2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14]
    interfering_aps_24 = sum(channels_24.get(ch, 0) for ch in non_standard_channels)

    # Dynamic Airspace Security Health Score (0 - 100)
    # Calculated dynamically from the scanned networks in range
    total_networks = len(analyzed_networks)
    if total_networks == 0:
        airspace_health = 100
        health_status = "No Airspace Detected"
    else:
        avg_score = sum(n["security"]["score"] for n in analyzed_networks) / total_networks
        # Deduct penalties for hazardous networks in local radio airspace
        penalties = (critical_count * 20) + (high_count * 12) + (moderate_count * 5)
        raw_health = (avg_score * 0.70) + max(0, 100 - penalties) * 0.30
        airspace_health = max(10, min(100, round(raw_health)))

        if airspace_health >= 80:
            health_status = "Airspace Secure"
        elif airspace_health >= 60:
            health_status = "Airspace Moderate"
        else:
            health_status = "Airspace Critical"

    return {
        "networks": analyzed_networks,
        "total_networks": total_networks,
        "total_aps": scan_data.get("total_aps", 0),
        "metrics": {
            "critical_count": critical_count,
            "high_count": high_count,
            "warning_count": moderate_count,
            "moderate_count": moderate_count,
            "safe_count": safe_count,
            "airspace_health": airspace_health,
            "health_status": health_status
        },
        "rogue_alerts": rogue_alerts,
        "channels": {
            "band_24": channels_24,
            "band_5": channels_5,
            "interfering_aps_24": interfering_aps_24,
            "congested_channel_24": max(channels_24, key=channels_24.get) if any(channels_24.values()) else 6
        }
    }
