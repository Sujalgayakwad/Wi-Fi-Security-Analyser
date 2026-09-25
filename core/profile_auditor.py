"""
Wi-Fi Saved Profiles and Password Security Auditor.
Audits Windows WLAN profiles for risky auto-connect configurations,
and provides password strength / entropy analysis.
"""
import subprocess
import re
import math
from typing import Dict, List, Any

def audit_saved_profiles() -> List[Dict[str, Any]]:
    """
    Enumerates all saved Wi-Fi profiles in Windows and audits their security posture.
    """
    profiles: List[Dict[str, Any]] = []

    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="ignore"
        )
        profile_names = []
        for line in res.stdout.splitlines():
            if "All User Profile" in line and ":" in line:
                pname = line.split(":", 1)[1].strip()
                if pname:
                    profile_names.append(pname)

        for name in profile_names:
            detail = audit_single_profile(name)
            profiles.append(detail)

    except Exception:
        pass

    return profiles

def audit_single_profile(name: str) -> Dict[str, Any]:
    """Inspects a single Wi-Fi profile via netsh wlan show profile."""
    prof_info = {
        "name": name,
        "auto_connect": False,
        "mac_randomization": "Disabled",
        "authentication": "Unknown",
        "cipher": "Unknown",
        "key_present": False,
        "security_risk": "LOW",
        "flags": []
    }

    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "profile", f"name={name}"],
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

            k, v = [x.strip() for x in line_str.split(":", 1)]
            k_lower = k.lower()

            if "connection mode" in k_lower:
                if "automatically" in v.lower():
                    prof_info["auto_connect"] = True
            elif "mac randomization" in k_lower:
                prof_info["mac_randomization"] = v
            elif "authentication" in k_lower:
                prof_info["authentication"] = v
            elif "cipher" in k_lower:
                prof_info["cipher"] = v
            elif "security key" in k_lower:
                if "present" in v.lower():
                    prof_info["key_present"] = True

        # Security Risk Assessment
        auth = prof_info["authentication"].upper()
        cipher = prof_info["cipher"].upper()

        if "OPEN" in auth or not prof_info["key_present"]:
            if prof_info["auto_connect"]:
                prof_info["security_risk"] = "CRITICAL"
                prof_info["flags"].append("CRITICAL: Auto-connect enabled on unencrypted open network (Karma / Rogue AP trap risk!)")
            else:
                prof_info["security_risk"] = "HIGH"
                prof_info["flags"].append("Unencrypted Open network profile saved on device.")

        if "WEP" in auth or "WEP" in cipher:
            prof_info["security_risk"] = "CRITICAL"
            prof_info["flags"].append("Insecure WEP profile.")

        if "TKIP" in cipher:
            prof_info["security_risk"] = "MODERATE"
            prof_info["flags"].append("Deprecated TKIP cipher saved in profile.")

        if prof_info["mac_randomization"].lower() == "disabled":
            prof_info["flags"].append("MAC Randomization is disabled (Device hardware MAC visible to network trackers).")

    except Exception:
        pass

    return prof_info

def analyze_password_security(password: str) -> Dict[str, Any]:
    """
    Evaluates Wi-Fi Pre-Shared Key (PSK) / Passphrase entropy and cracking resistance.
    """
    if not password:
        return {
            "score": 0,
            "entropy_bits": 0,
            "verdict": "Empty Password",
            "crack_time_estimate": "Instant",
            "recommendations": ["Enter a valid Wi-Fi passphrase."]
        }

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digits = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_special:
        pool_size += 33

    pool_size = max(pool_size, 1)

    # Shannon Entropy = L * log2(R)
    entropy_bits = round(length * math.log2(pool_size), 1)

    # WPA2 requires 8 to 63 chars
    recommendations = []
    if length < 8:
        recommendations.append("WPA2/WPA3 passphrases must be at least 8 characters long.")
    elif length < 12:
        recommendations.append("Increase passphrase length to 14-16+ characters for brute-force resistance.")

    if not has_upper:
        recommendations.append("Add uppercase letters (A-Z).")
    if not has_digits:
        recommendations.append("Include numeric digits (0-9).")
    if not has_special:
        recommendations.append("Include special symbols (!, @, #, $, etc.).")

    # Common weak Wi-Fi passwords dictionary check
    common_passwords = {
        "password", "12345678", "123456789", "admin123", "qwerty123",
        "wifi1234", "password123", "internet", "welcome1", "letmein1"
    }
    if password.lower() in common_passwords:
        entropy_bits = 5.0
        recommendations.insert(0, "CRITICAL: Passphrase is in known top dictionary lists. Easily cracked in seconds!")

    # Cracking time estimate based on high-end 8x RTX 4090 GPU rig (~800,000 WPA-PMK keys/sec)
    attempts_per_sec = 800_000
    possible_combinations = pool_size ** length
    avg_seconds = (possible_combinations / 2) / attempts_per_sec

    if avg_seconds < 1:
        crack_time = "Under 1 second"
        verdict = "Extremely Weak"
        score = 15
    elif avg_seconds < 60:
        crack_time = f"{int(avg_seconds)} seconds"
        verdict = "Very Weak"
        score = 30
    elif avg_seconds < 3600:
        crack_time = f"{int(avg_seconds / 60)} minutes"
        verdict = "Weak"
        score = 45
    elif avg_seconds < 86400:
        crack_time = f"{int(avg_seconds / 3600)} hours"
        verdict = "Moderate"
        score = 65
    elif avg_seconds < 31536000:
        crack_time = f"{int(avg_seconds / 86400)} days"
        verdict = "Strong"
        score = 85
    elif avg_seconds < 31536000 * 100:
        crack_time = f"{int(avg_seconds / 31536000)} years"
        verdict = "Very Strong"
        score = 95
    else:
        crack_time = "Centuries / Practically Uncrackable"
        verdict = "Fortress-Level"
        score = 100

    return {
        "score": score,
        "entropy_bits": entropy_bits,
        "pool_size": pool_size,
        "length": length,
        "verdict": verdict,
        "crack_time_estimate": crack_time,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digits": has_digits,
        "has_special": has_special,
        "recommendations": recommendations
    }
