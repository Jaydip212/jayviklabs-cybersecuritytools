# backend/utils.py
import hashlib
import base64
import json
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import re

# 1) Password strength (educational estimator)
COMMON_PASSWORDS = {
    "123456", "password", "qwerty", "letmein", "admin", "welcome", 
    "monkey", "dragon", "123456789", "password123", "abc123",
    "iloveyou", "master", "sunshine", "princess", "football"
}

def password_strength(pw: str):
    """
    Analyze password strength for educational purposes.
    Returns score, strength level, reasons for weakness, and suggestions.
    """
    score = 0
    reasons = []
    
    # Length check
    if len(pw) >= 8:
        score += 1
    else:
        reasons.append('Use at least 8 characters')
    
    # Case mixing
    if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
        score += 1
    else:
        reasons.append('Mix upper and lower case letters')
    
    # Numbers
    if any(c.isdigit() for c in pw):
        score += 1
    else:
        reasons.append('Add numbers')
    
    # Special characters
    if any(not c.isalnum() for c in pw):
        score += 1
    else:
        reasons.append('Add special symbols (!@#$%^&*)')
    
    # Common password check
    if pw.lower() in COMMON_PASSWORDS:
        score = 0
        reasons = ['Password is commonly used — NEVER use this password!']
    
    # Strength mapping
    strength_levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong']
    strength = strength_levels[min(score, 4)]
    
    # Suggestions
    suggestions = []
    if score < 3:
        suggestions.append('Use a passphrase with 3+ random words')
        suggestions.append('Consider using a password manager')
    if score >= 3:
        suggestions.append('Great! This password shows good security practices')
    
    return {
        "score": score,
        "strength": strength,
        "reasons": reasons,
        "suggestions": suggestions,
        "length": len(pw),
        "educational_note": "Strong passwords are your first line of defense!"
    }

# 2) Hashing demonstrator
def generate_hashes(text: str):
    """
    Generate MD5, SHA-1, and SHA-256 hashes for educational comparison.
    Includes security notes about each algorithm.
    """
    return {
        'original': text,
        'md5': hashlib.md5(text.encode()).hexdigest(),
        'sha1': hashlib.sha1(text.encode()).hexdigest(),
        'sha256': hashlib.sha256(text.encode()).hexdigest(),
        'educational_notes': {
            'md5': 'MD5 is BROKEN - do not use for security!',
            'sha1': 'SHA-1 is deprecated - avoid for new applications',
            'sha256': 'SHA-256 is currently secure and recommended'
        }
    }

# 3) AES (symmetric) — educational demo using random key stored only in memory
# WARNING: This is for education only. In production, keys must be managed securely!
_KEY = secrets.token_bytes(16)  # random key on server start — educational only

def aes_encrypt(plaintext: str):
    """
    AES encryption demonstration with CBC mode.
    Returns base64 encoded ciphertext and IV.
    """
    iv = secrets.token_bytes(16)  # Random IV for each encryption
    cipher = AES.new(_KEY, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(iv).decode()
    )

def aes_decrypt(ciphertext_b64: str, iv_b64: str):
    """
    AES decryption demonstration.
    Decrypts base64 encoded ciphertext using provided IV.
    """
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        cipher = AES.new(_KEY, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded, AES.block_size)
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# 4) Caesar cipher and Base64 simple functions
def caesar_cipher(text: str, shift: int = 3):
    """
    Caesar cipher implementation for educational purposes.
    Only shifts alphabetic characters, preserves case.
    """
    result = []
    for char in text:
        if char.isalpha():
            # Determine if uppercase or lowercase
            base = ord('A') if char.isupper() else ord('a')
            # Apply shift with wraparound
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            # Non-alphabetic characters remain unchanged
            result.append(char)
    return ''.join(result)

def base64_encode_decode(text: str):
    """
    Base64 encoding/decoding demonstration.
    Shows both encoded and decoded versions for comparison.
    """
    try:
        encoded = base64.b64encode(text.encode()).decode()
        # Verify by decoding
        decoded = base64.b64decode(encoded).decode()
        return {
            "original": text,
            "encoded": encoded,
            "decoded": decoded,
            "note": "Base64 is encoding, NOT encryption!"
        }
    except Exception as e:
        return {
            "error": f"Base64 operation failed: {str(e)}"
        }

# 5) Simulated port scan — returns deterministic fictional results
def simulated_port_scan(target: str):
    """
    SAFE PORT SCAN SIMULATION ONLY!
    This function NEVER scans real networks or IP addresses.
    Returns fictional, deterministic results based on input hash.
    
    IMPORTANT: This is for educational purposes only. 
    Real port scanning without permission is illegal and unethical.
    """
    # Create deterministic results based on target string
    target_hash = hashlib.sha256(target.encode()).hexdigest()
    hash_int = int(target_hash[:8], 16)  # Use first 8 hex chars
    
    # Predefined fictional hosts with different port configurations
    fictional_hosts = [
        {
            "ip": "192.168.100.10",
            "hostname": "web-server-sim",
            "ports": [
                {"port": 22, "state": "open", "service": "ssh"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "closed", "service": "https"}
            ]
        },
        {
            "ip": "192.168.100.20", 
            "hostname": "secure-server-sim",
            "ports": [
                {"port": 443, "state": "open", "service": "https"},
                {"port": 8080, "state": "filtered", "service": "http-proxy"},
                {"port": 22, "state": "closed", "service": "ssh"}
            ]
        },
        {
            "ip": "192.168.100.30",
            "hostname": "workstation-sim", 
            "ports": [
                {"port": 135, "state": "open", "service": "msrpc"},
                {"port": 445, "state": "open", "service": "microsoft-ds"},
                {"port": 3389, "state": "closed", "service": "rdp"}
            ]
        },
        {
            "ip": "192.168.100.40",
            "hostname": "database-sim",
            "ports": [
                {"port": 3306, "state": "open", "service": "mysql"},
                {"port": 5432, "state": "filtered", "service": "postgresql"},
                {"port": 1433, "state": "closed", "service": "mssql"}
            ]
        }
    ]
    
    # Select result based on hash (deterministic)
    selected_host = fictional_hosts[hash_int % len(fictional_hosts)]
    
    return {
        "target_requested": target,
        "target_simulated": selected_host["ip"],
        "hostname": selected_host["hostname"],
        "scan_type": "SYN Stealth Scan (SIMULATED)",
        "ports_scanned": "Common ports (22, 80, 443, 8080, etc.)",
        "results": selected_host["ports"],
        "scan_time": "0.42s (simulated)",
        "disclaimer": "⚠️  SIMULATION ONLY - No real network scanning performed!",
        "educational_note": "Real port scanning requires proper authorization and is illegal without permission!"
    }

# 6) Phishing email analyzer (heuristic, educational)
PHISHING_KEYWORDS = {
    "urgent", "verify", "suspend", "password", "click", "login", "invoice", "immediately",
    "account", "update", "confirm", "limited", "payment", "warning"
}

def phishing_analyzer(email_body: str):
    """
    Heuristically analyze email text for common phishing signals.
    Returns a risk score (0-100) with flagged indicators and safety guidance.
    """
    normalized = email_body.lower()
    indicators = []
    score = 0

    if not email_body.strip():
        return {
            "risk_score": 0,
            "risk_level": "None",
            "indicators": [],
            "summary": "Provide an email or message to analyze.",
            "tips": [
                "Look for urgency, mismatched URLs, and requests for credentials.",
                "Verify through trusted channels before acting on unexpected emails."
            ]
        }

    urgency_patterns = [r"immediate action", r"within \d+ hours", r"final notice", r"last chance"]
    for pattern in urgency_patterns:
        if re.search(pattern, normalized):
            score += 15
            indicators.append({
                "type": "Urgency", "detail": f"Found urgent language: '{pattern}'", "severity": "high"
            })
            break

    keyword_hits = [word for word in PHISHING_KEYWORDS if word in normalized]
    if keyword_hits:
        add = min(len(keyword_hits) * 5, 20)
        score += add
        indicators.append({
            "type": "Suspicious Keywords",
            "detail": f"Contains high-risk terms: {', '.join(sorted(keyword_hits))}",
            "severity": "medium"
        })

    url_pattern = r"https?://[\w.-]+"
    urls = re.findall(url_pattern, email_body, flags=re.IGNORECASE)
    if urls:
        for url in urls:
            if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
                score += 20
                indicators.append({
                    "type": "Suspicious URL",
                    "detail": f"Links to raw IP address: {url}",
                    "severity": "high"
                })
            elif url.startswith("http://"):
                score += 10
                indicators.append({
                    "type": "Insecure Link",
                    "detail": f"Non-HTTPS link detected: {url}",
                    "severity": "medium"
                })
        if len(urls) > 3:
            score += 5
            indicators.append({
                "type": "Link Volume",
                "detail": "Large number of links can indicate lures to malicious sites.",
                "severity": "low"
            })

    if re.search(r"attachment", normalized) or re.search(r"\.zip|\.exe|\.docm", normalized):
        score += 10
        indicators.append({
            "type": "Attachment Reference",
            "detail": "Mentions or references to potentially dangerous attachments.",
            "severity": "medium"
        })

    if re.search(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_body):
        suspicious_domains = [mail for mail in re.findall(r"[^@\s]+@([^@\s]+)", email_body)
                               if mail.endswith(".ru") or mail.endswith(".cn")]
        if suspicious_domains:
            score += 10
            indicators.append({
                "type": "Sender Domain",
                "detail": f"Email references unfamiliar domain(s): {', '.join(suspicious_domains)}",
                "severity": "medium"
            })

    score = min(score, 100)
    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Moderate"
    elif score > 0:
        level = "Low"
    else:
        level = "None"

    tips = [
        "Verify sender identity via a second channel before responding.",
        "Hover over links to confirm domains before clicking.",
        "Report suspicious messages to your security team or service provider."
    ]

    return {
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "summary": "Heuristic analysis only — always follow organizational policy.",
        "tips": tips
    }

# 7) Recon blueprint generator (educational recon checklist)
RECON_PHASES = [
    {
        "phase": "OSINT Discovery",
        "tasks": ["Check certificate transparency logs", "Review subdomains", "Identify public repos"],
        "tools": ["crt.sh", "Amass", "GitHub"]
    },
    {
        "phase": "Surface Mapping",
        "tasks": ["Enumerate DNS records", "Probe common web ports", "Review HTTP response headers"],
        "tools": ["dig", "Nmap", "httpx"]
    },
    {
        "phase": "Service Fingerprinting",
        "tasks": ["Gather banner info", "Identify versions", "Cross-check CVE feeds"],
        "tools": ["Nmap -sV", "WhatWeb", "cve-search"]
    },
    {
        "phase": "Authentication Review",
        "tasks": ["Test MFA availability", "Inspect password policy", "Look for default admin portals"],
        "tools": ["OWASP ZAP", "Burp Suite", "Browser DevTools"]
    }
]

RECON_PROFILES = [
    {
        "profile": "SaaS Platform",
        "focus": ["OAuth flows", "Subdomain takeover", "Misconfigured cloud storage"],
        "playbooks": [
            "Enumerate tenant-specific subdomains",
            "Check forgotten S3 buckets for open ACLs",
            "Verify redirects in auth flows"
        ]
    },
    {
        "profile": "E-commerce",
        "focus": ["Payment gateway", "Sensitive cookies", "Inventory APIs"],
        "playbooks": [
            "Analyze checkout API for insecure methods",
            "Inspect cookie flags (Secure, HttpOnly)",
            "Review caching rules for PII exposure"
        ]
    },
    {
        "profile": "SaaS Admin Portal",
        "focus": ["Privilege escalation", "Role misconfiguration", "Weak password reset"],
        "playbooks": [
            "Attempt horizontal privilege checks",
            "Confirm least privilege role defaults",
            "Review password reset workflow for predictable tokens"
        ]
    }
]

def recon_blueprint(target: str):
    """
    Generate a deterministic recon plan for a given target string.
    Useful for teaching ethical hacking planning without touching real systems.
    """
    sanitized = target.strip() or "example.com"
    target_hash = hashlib.sha256(sanitized.encode()).hexdigest()
    phase_offset = int(target_hash[:2], 16)
    profile_index = int(target_hash[2:4], 16) % len(RECON_PROFILES)

    selected_phases = []
    for idx, phase in enumerate(RECON_PHASES):
        if (phase_offset + idx) % 2 == 0:
            selected_phases.append(phase)
    if not selected_phases:
        selected_phases = RECON_PHASES[:2]

    profile = RECON_PROFILES[profile_index]

    return {
        "target": sanitized,
        "profile": profile["profile"],
        "focus_areas": profile["focus"],
        "playbook": profile["playbooks"],
        "recommended_phases": selected_phases,
        "disclaimer": "Simulated recon checklist. Perform real testing only with explicit authorization.",
        "ethics": [
            "Respect scope boundaries defined in Rules of Engagement.",
            "Never exploit beyond agreed depth during recon simulations.",
            "Document findings responsibly and report securely."
        ]
    }