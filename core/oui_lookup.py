"""
OUI (Organizationally Unique Identifier) Vendor Lookup Helper.
Maps MAC / BSSID prefixes to hardware vendors.
"""
import re

# Comprehensive list of major Wi-Fi AP and NIC hardware vendors
COMMON_OUIS = {
    # Ubiquiti
    "00:27:22": "Ubiquiti Networks",
    "24:a4:3c": "Ubiquiti Networks",
    "44:d9:e7": "Ubiquiti Networks",
    "68:d7:9a": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "80:2a:a8": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "dc:9f:db": "Ubiquiti Networks",
    "f0:9f:c2": "Ubiquiti Networks",
    
    # Cisco / Meraki
    "00:1c:58": "Cisco Systems",
    "00:24:97": "Cisco Systems",
    "00:26:0b": "Cisco Systems",
    "0c:85:25": "Cisco Meraki",
    "e0:55:3d": "Cisco Meraki",
    "f0:7f:06": "Cisco Meraki",
    "88:43:e1": "Cisco Systems",
    "a0:ec:f9": "Cisco Systems",
    
    # TP-Link
    "00:25:86": "TP-Link Technologies",
    "14:cc:20": "TP-Link Technologies",
    "18:a6:f7": "TP-Link Technologies",
    "30:de:4b": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "60:32:b1": "TP-Link Technologies",
    "84:16:f9": "TP-Link Technologies",
    "98:48:27": "TP-Link Technologies",
    "a4:2b:b0": "TP-Link Technologies",
    "c0:06:c3": "TP-Link Technologies",
    "d8:07:b6": "TP-Link Technologies",
    "e8:48:b8": "TP-Link Technologies",
    
    # Netgear
    "00:14:6c": "Netgear",
    "00:1f:33": "Netgear",
    "00:24:b2": "Netgear",
    "04:a1:51": "Netgear",
    "20:e5:2a": "Netgear",
    "44:94:fc": "Netgear",
    "84:1b:5e": "Netgear",
    "9c:3d:cf": "Netgear",
    "b0:39:56": "Netgear",
    "c4:04:15": "Netgear",
    
    # D-Link
    "00:13:46": "D-Link",
    "00:1b:11": "D-Link",
    "1c:7e:e5": "D-Link",
    "28:10:7b": "D-Link",
    "78:54:2e": "D-Link",
    "c8:d3:a3": "D-Link",
    
    # Asus
    "04:d9:f5": "ASUSTek Computer",
    "10:7b:44": "ASUSTek Computer",
    "2c:fd:a1": "ASUSTek Computer",
    "ac:22:0b": "ASUSTek Computer",
    "b0:6e:bf": "ASUSTek Computer",
    
    # Aruba / HP
    "00:0b:86": "Aruba Networks",
    "24:de:c6": "Aruba Networks",
    "6c:f3:7f": "Aruba Networks",
    "94:b4:0f": "Aruba Networks",
    "ac:a3:1e": "Aruba Networks",
    
    # Huawei
    "00:1e:10": "Huawei Technologies",
    "04:b0:e7": "Huawei Technologies",
    "20:08:89": "Huawei Technologies",
    "48:46:fb": "Huawei Technologies",
    "70:7b:e8": "Huawei Technologies",
    "80:b6:86": "Huawei Technologies",
    "a4:99:9b": "Huawei Technologies",
    
    # Apple
    "00:03:93": "Apple",
    "00:1c:b3": "Apple",
    "3c:07:54": "Apple",
    "68:fe:f7": "Apple",
    "70:56:81": "Apple",
    "8c:85:90": "Apple",
    "bc:d0:74": "Apple",
    "f0:18:98": "Apple",
    
    # Intel / Realtek
    "00:1b:21": "Intel Corporate",
    "00:21:6a": "Intel Corporate",
    "34:13:e8": "Intel Corporate",
    "80:86:f2": "Intel Corporate",
    "dc:b7:ac": "Realtek Semiconductor Corp.",
    "00:e0:4c": "Realtek Semiconductor Corp.",
    "52:54:00": "QEMU / Virtual",
    
    # Google
    "30:fd:38": "Google LLC",
    "54:60:09": "Google LLC",
    "f4:f5:db": "Google LLC",
    
    # MikroTik
    "00:0c:42": "MikroTik",
    "48:8f:5a": "MikroTik",
    "64:d1:54": "MikroTik",
    "cc:2d:e0": "MikroTik",
    
    # Espressif (IoT)
    "24:0a:c4": "Espressif Inc (IoT/ESP)",
    "30:ae:a4": "Espressif Inc (IoT/ESP)",
    "84:f3:eb": "Espressif Inc (IoT/ESP)",
    "bc:dd:c2": "Espressif Inc (IoT/ESP)"
}

def lookup_vendor(mac_address: str) -> str:
    """Return hardware vendor name for a given MAC/BSSID."""
    if not mac_address:
        return "Unknown"
    
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address).lower()
    if len(clean_mac) < 6:
        return "Unknown"
    
    # Check if locally administered / randomized address
    # In IEEE 802 MACs, if the 2nd least significant bit of the first byte is 1, it's locally administered (randomized MAC)
    first_byte = int(clean_mac[:2], 16)
    is_randomized = bool(first_byte & 0x02)
    
    prefix = f"{clean_mac[0:2]}:{clean_mac[2:4]}:{clean_mac[4:6]}"
    vendor = COMMON_OUIS.get(prefix)
    
    if vendor:
        return vendor
    
    if is_randomized:
        return "Private/Randomized MAC (Anti-Tracking)"
    
    return "Generic Wi-Fi Hardware"
