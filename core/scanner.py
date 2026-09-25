"""
Wi-Fi Spectrum and Access Point Scanner for Windows.
Parses output from Windows Native WLAN API via netsh.
"""
import subprocess
import re
from typing import List, Dict, Any
from .oui_lookup import lookup_vendor

def channel_to_band(channel: int) -> str:
    """Determine frequency band from channel number."""
    if 1 <= channel <= 14:
        return "2.4 GHz"
    elif 32 <= channel <= 177:
        return "5 GHz"
    elif channel > 177:
        return "6 GHz"
    return "Unknown Band"

def signal_to_dbm(signal_percent: int) -> int:
    """Approximate dBm from Windows signal percentage (0-100%)."""
    # 0% ~ -100 dBm, 100% ~ -50 dBm
    return int((signal_percent / 2.0) - 100)

def scan_wifi_networks() -> Dict[str, Any]:
    """
    Executes netsh wlan show networks mode=bssid and returns parsed network data.
    """
    try:
        # Run netsh command with cp850 / utf-8 fallback
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )
        output = result.stdout
    except Exception as e:
        return {"error": str(e), "networks": [], "total_networks": 0, "total_aps": 0}

    networks: List[Dict[str, Any]] = []
    current_net: Dict[str, Any] = None
    current_bssid: Dict[str, Any] = None

    lines = output.splitlines()
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # Match SSID header e.g. "SSID 1 : CITNC-Boys Hostel"
        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line_clean, re.IGNORECASE)
        if ssid_match:
            ssid_name = ssid_match.group(1).strip()
            # If empty SSID, it is a Hidden Network
            if not ssid_name:
                ssid_name = "[Hidden Network]"

            current_net = {
                "ssid": ssid_name,
                "is_hidden": ssid_name == "[Hidden Network]",
                "network_type": "Infrastructure",
                "authentication": "Open",
                "encryption": "None",
                "bssids": []
            }
            networks.append(current_net)
            current_bssid = None
            continue

        if current_net is None:
            continue

        # Match Network Properties
        if line_clean.lower().startswith("network type"):
            parts = line_clean.split(":", 1)
            if len(parts) == 2:
                current_net["network_type"] = parts[1].strip()

        elif line_clean.lower().startswith("authentication"):
            parts = line_clean.split(":", 1)
            if len(parts) == 2:
                current_net["authentication"] = parts[1].strip()

        elif line_clean.lower().startswith("encryption"):
            parts = line_clean.split(":", 1)
            if len(parts) == 2:
                current_net["encryption"] = parts[1].strip()

        # Match BSSID entry e.g. "BSSID 1 : dc:b7:ac:fe:89:02"
        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:-]{17})$", line_clean, re.IGNORECASE)
        if bssid_match:
            bssid_mac = bssid_match.group(1).strip().lower()
            current_bssid = {
                "bssid": bssid_mac,
                "signal_percent": 0,
                "signal_dbm": -100,
                "radio_type": "Unknown",
                "channel": 0,
                "band": "Unknown Band",
                "vendor": lookup_vendor(bssid_mac),
                "basic_rates": "",
                "other_rates": ""
            }
            current_net["bssids"].append(current_bssid)
            continue

        if current_bssid is not None:
            if line_clean.lower().startswith("signal"):
                # e.g. "Signal : 81%"
                sig_match = re.search(r"(\d+)%", line_clean)
                if sig_match:
                    val = int(sig_match.group(1))
                    current_bssid["signal_percent"] = val
                    current_bssid["signal_dbm"] = signal_to_dbm(val)

            elif line_clean.lower().startswith("radio type"):
                parts = line_clean.split(":", 1)
                if len(parts) == 2:
                    current_bssid["radio_type"] = parts[1].strip()

            elif line_clean.lower().startswith("channel"):
                parts = line_clean.split(":", 1)
                if len(parts) == 2:
                    try:
                        ch = int(parts[1].strip())
                        current_bssid["channel"] = ch
                        current_bssid["band"] = channel_to_band(ch)
                    except ValueError:
                        pass

            elif line_clean.lower().startswith("basic rates"):
                parts = line_clean.split(":", 1)
                if len(parts) == 2:
                    current_bssid["basic_rates"] = parts[1].strip()

            elif line_clean.lower().startswith("other rates"):
                parts = line_clean.split(":", 1)
                if len(parts) == 2:
                    current_bssid["other_rates"] = parts[1].strip()

    # Calculate flattened AP list and aggregates
    total_aps = sum(len(net["bssids"]) for net in networks)
    
    return {
        "networks": networks,
        "total_networks": len(networks),
        "total_aps": total_aps
    }
