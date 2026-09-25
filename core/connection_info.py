"""
Active Wi-Fi Connection and Network Interface Diagnostics.
Retrieves connected AP parameters, gateway latency, DNS configuration, and driver security capabilities.
"""
import subprocess
import re
import socket
import time
from typing import Dict, Any, List
from .oui_lookup import lookup_vendor

KNOWN_SECURE_DNS = {
    "1.1.1.1": "Cloudflare DNS (Fast & Privacy-Focused)",
    "1.0.0.1": "Cloudflare DNS (Secondary)",
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS (Secondary)",
    "9.9.9.9": "Quad9 (Malware-Blocking Secure DNS)",
    "149.112.112.112": "Quad9 (Secondary)",
    "208.67.222.222": "Cisco OpenDNS",
    "208.67.220.220": "Cisco OpenDNS (Secondary)",
    "94.140.14.14": "AdGuard DNS (Ad/Tracking Blocker)",
    "94.140.15.15": "AdGuard DNS (Secondary)"
}

def get_active_wifi_interface() -> Dict[str, Any]:
    """Parse netsh wlan show interfaces for active connection stats."""
    info = {
        "connected": False,
        "name": "Wi-Fi",
        "ssid": "Not Connected",
        "bssid": "",
        "vendor": "Unknown",
        "state": "disconnected",
        "radio_type": "Unknown",
        "authentication": "Unknown",
        "cipher": "Unknown",
        "channel": 0,
        "receive_rate_mbps": 0.0,
        "transmit_rate_mbps": 0.0,
        "signal_percent": 0,
        "profile": ""
    }

    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )
        lines = res.stdout.splitlines()

        for line in lines:
            line_str = line.strip()
            if not line_str or ":" not in line_str:
                continue

            k, v = [part.strip() for part in line_str.split(":", 1)]
            k_lower = k.lower()

            if k_lower == "name":
                info["name"] = v
            elif k_lower == "state":
                info["state"] = v
                if "connected" in v.lower():
                    info["connected"] = True
            elif k_lower == "ssid":
                info["ssid"] = v
            elif k_lower == "bssid":
                info["bssid"] = v.lower()
                info["vendor"] = lookup_vendor(v)
            elif k_lower == "radio type":
                info["radio_type"] = v
            elif k_lower == "authentication":
                info["authentication"] = v
            elif k_lower == "cipher":
                info["cipher"] = v
            elif k_lower == "channel":
                try:
                    info["channel"] = int(v)
                except ValueError:
                    pass
            elif "receive rate" in k_lower:
                try:
                    info["receive_rate_mbps"] = float(v)
                except ValueError:
                    pass
            elif "transmit rate" in k_lower:
                try:
                    info["transmit_rate_mbps"] = float(v)
                except ValueError:
                    pass
            elif k_lower == "signal":
                m = re.search(r"(\d+)%", v)
                if m:
                    info["signal_percent"] = int(m.group(1))
            elif k_lower == "profile":
                info["profile"] = v

    except Exception:
        pass

    return info

def get_network_adapter_details() -> Dict[str, Any]:
    """Parse ipconfig /all for IP, Gateway, and DNS servers of the active Wi-Fi adapter."""
    details = {
        "ip_address": "",
        "subnet_mask": "",
        "default_gateway": "",
        "dhcp_server": "",
        "dns_servers": [],
        "dhcp_enabled": False
    }

    try:
        res = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )
        
        # Split ipconfig output into adapter blocks
        blocks = re.split(r"\n(?=[A-Za-z0-9].*adapter )", res.stdout)
        
        for block in blocks:
            # Check if this block is a Wireless LAN adapter and not disconnected
            if ("Wireless LAN" in block or "Wi-Fi" in block) and "Media disconnected" not in block:
                lines = block.splitlines()
                for i, line in enumerate(lines):
                    line_str = line.strip()
                    
                    if "IPv4 Address" in line_str or "IP Address" in line_str:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_str)
                        if m and not details["ip_address"]:
                            details["ip_address"] = m.group(1)

                    elif "Subnet Mask" in line_str:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_str)
                        if m and not details["subnet_mask"]:
                            details["subnet_mask"] = m.group(1)

                    elif "Default Gateway" in line_str:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_str)
                        if m and not details["default_gateway"]:
                            details["default_gateway"] = m.group(1)

                    elif "DHCP Server" in line_str:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_str)
                        if m and not details["dhcp_server"]:
                            details["dhcp_server"] = m.group(1)

                    elif "DHCP Enabled" in line_str:
                        if "yes" in line_str.lower():
                            details["dhcp_enabled"] = True

                    elif "DNS Servers" in line_str:
                        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_str)
                        if m:
                            details["dns_servers"].append(m.group(1))
                        # Grab additional DNS IPs on subsequent lines
                        j = i + 1
                        while j < len(lines) and lines[j].startswith(" ") and ":" not in lines[j]:
                            next_m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", lines[j])
                            if next_m:
                                details["dns_servers"].append(next_m.group(1))
                            j += 1

                if details["ip_address"]:
                    break

    except Exception:
        pass

    return details

def ping_gateway(gateway_ip: str) -> Dict[str, Any]:
    """Test ping latency to default gateway."""
    if not gateway_ip:
        return {"reachable": False, "latency_ms": None}

    try:
        start = time.time()
        res = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", gateway_ip],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )
        elapsed = int((time.time() - start) * 1000)
        
        if res.returncode == 0:
            m = re.search(r"time[<=](\d+)ms", res.stdout, re.IGNORECASE)
            lat = int(m.group(1)) if m else elapsed
            return {"reachable": True, "latency_ms": lat}
    except Exception:
        pass

    return {"reachable": False, "latency_ms": None}

def check_driver_capabilities() -> Dict[str, Any]:
    """Inspect Wi-Fi hardware driver security capabilities."""
    caps = {
        "driver_name": "",
        "pmf_supported": False, # 802.11w
        "fips_supported": False,
        "wpa3_supported": False
    }

    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "drivers"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )
        out = res.stdout

        for line in out.splitlines():
            line_str = line.strip()
            if "Driver" in line_str and ":" in line_str:
                caps["driver_name"] = line_str.split(":", 1)[1].strip()
            elif "802.11w" in line_str and "yes" in line_str.lower():
                caps["pmf_supported"] = True
            elif "FIPS 140-2" in line_str and "yes" in line_str.lower():
                caps["fips_supported"] = True
            elif "WPA3" in line_str:
                caps["wpa3_supported"] = True
    except Exception:
        pass

    return caps

def audit_current_connection() -> Dict[str, Any]:
    """
    Combines interface, adapter, driver, gateway, and DNS diagnostics
    into an integrated security posture analysis of the active connection.
    """
    wifi = get_active_wifi_interface()
    adapter = get_network_adapter_details()
    driver = check_driver_capabilities()

    gateway_status = ping_gateway(adapter.get("default_gateway", ""))

    # Evaluate DNS configuration
    dns_analysis: List[Dict[str, Any]] = []
    has_encrypted_public_dns = False

    for dns in adapter.get("dns_servers", []):
        provider = KNOWN_SECURE_DNS.get(dns)
        if provider:
            has_encrypted_public_dns = True
            dns_analysis.append({
                "ip": dns,
                "type": "SECURE_PUBLIC",
                "provider": provider,
                "assessment": "Known secure / high-reputation DNS resolver."
            })
        else:
            dns_analysis.append({
                "ip": dns,
                "type": "LOCAL_OR_ISP",
                "provider": "Local Gateway / ISP DNS",
                "assessment": "Traffic may be subject to ISP DNS hijacking, unencrypted queries, or filtering."
            })

    # Calculate overall connection security score (0-100)
    score = 100
    risks: List[Dict[str, str]] = []

    if not wifi["connected"]:
        return {
            "connected": False,
            "message": "Wi-Fi is currently disconnected or in airplane mode."
        }

    auth = wifi.get("authentication", "").upper()
    cipher = wifi.get("cipher", "").upper()

    if "OPEN" in auth or "NONE" in cipher:
        score -= 70
        risks.append({
            "severity": "CRITICAL",
            "text": "Active connection is completely unencrypted. Your data is exposed to everyone on this network."
        })
    elif "WEP" in auth or "WEP" in cipher:
        score -= 60
        risks.append({
            "severity": "CRITICAL",
            "text": "Active connection uses deprecated WEP cipher, vulnerable to immediate decryption."
        })
    elif "TKIP" in cipher:
        score -= 30
        risks.append({
            "severity": "HIGH",
            "text": "Active connection uses legacy TKIP cipher instead of AES-CCMP."
        })
    elif "WPA3" in auth:
        score = 98
    else:
        # WPA2-Personal CCMP standard
        score = 85

    # Check DNS security
    if not has_encrypted_public_dns and adapter.get("dns_servers"):
        score -= 10
        risks.append({
            "severity": "MODERATE",
            "text": "Using unencrypted local/ISP DNS. Consider enabling DNS-over-HTTPS (DoH) or Cloudflare/Quad9 resolvers."
        })

    # Grade
    grade = "A"
    if score >= 90:
        grade = "A+"
    elif score >= 75:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 45:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "connected": True,
        "wifi": wifi,
        "adapter": adapter,
        "driver": driver,
        "gateway": gateway_status,
        "dns": {
            "servers": adapter.get("dns_servers", []),
            "analysis": dns_analysis,
            "has_secure_dns": has_encrypted_public_dns
        },
        "security": {
            "score": score,
            "grade": grade,
            "risks": risks
        }
    }
