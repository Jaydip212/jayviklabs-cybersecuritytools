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

# 9) NMAP SIMULATOR - Port scanning simulation
def nmap_simulator(target: str, scan_type: str = "syn"):
    """
    Simulate nmap port scanning. Returns deterministic fictional ports based on target hash.
    EDUCATIONAL ONLY - NO REAL SCANNING PERFORMED.
    """
    sanitized = target.strip() or "example.com"
    target_hash = hashlib.sha256(sanitized.encode()).hexdigest()
    seed_val = int(target_hash[:8], 16)
    
    common_ports = {
        22: "ssh", 80: "http", 443: "https", 3306: "mysql", 5432: "postgresql",
        3389: "rdp", 8080: "http-proxy", 8000: "http-alt", 445: "smb", 21: "ftp",
        25: "smtp", 110: "pop3", 143: "imap", 53: "dns", 389: "ldap"
    }
    
    selected_ports = []
    for port in list(common_ports.keys())[:7]:
        if (seed_val + port) % 3 == 0:
            selected_ports.append(port)
    
    if not selected_ports:
        selected_ports = [22, 80, 443]
    
    open_ports = [
        {"port": p, "service": common_ports[p], "state": "open", "reason": "syn-ack"} 
        for p in sorted(selected_ports)
    ]
    
    return {
        "target": sanitized,
        "scan_type": scan_type,
        "open_ports": open_ports,
        "closed_ports": 65535 - len(open_ports),
        "scan_time": "0.42s",
        "disclaimer": "Simulated scan - NO real network traffic generated."
    }

# 10) DNS ENUMERATION
def dns_enumeration(domain: str):
    """
    Simulate DNS record enumeration for educational purposes.
    Returns common record types: A, AAAA, MX, TXT, NS, CNAME
    """
    sanitized = domain.strip() or "example.com"
    domain_hash = hashlib.md5(sanitized.encode()).hexdigest()
    
    a_octets = [int(domain_hash[i:i+2], 16) % 255 for i in range(0, 8, 2)]
    a_record = ".".join(str(o) for o in a_octets)
    
    aaaa_parts = [domain_hash[i:i+4] for i in range(0, 16, 4)]
    aaaa_record = ":".join(aaaa_parts)
    
    return {
        "domain": sanitized,
        "records": {
            "A": [{"value": a_record, "ttl": 3600}],
            "AAAA": [{"value": f"2001:db8::{aaaa_parts[0]}", "ttl": 3600}],
            "MX": [
                {"priority": 10, "value": f"mail.{sanitized}", "ttl": 3600},
                {"priority": 20, "value": f"mail2.{sanitized}", "ttl": 3600}
            ],
            "TXT": [
                {"value": "v=spf1 include:_spf.google.com ~all", "ttl": 3600},
                {"value": "google-site-verification=1a2b3c4d5e6f", "ttl": 3600}
            ],
            "NS": [
                {"value": "ns1.example.com", "ttl": 172800},
                {"value": "ns2.example.com", "ttl": 172800}
            ]
        },
        "disclaimer": "Simulated DNS records - not querying real nameservers."
    }

# 11) SSL CERTIFICATE ANALYZER
def ssl_analyzer(domain: str):
    """
    Simulate SSL/TLS certificate analysis. Returns fictional cert details.
    """
    sanitized = domain.strip() or "example.com"
    cert_hash = hashlib.sha256(sanitized.encode()).hexdigest()
    cert_serial = cert_hash[:16].upper()
    
    from datetime import datetime, timedelta
    issued = datetime.now() - timedelta(days=365)
    expires = datetime.now() + timedelta(days=365)
    
    return {
        "domain": sanitized,
        "certificate": {
            "subject": f"CN={sanitized}",
            "issuer": "Simulated CA",
            "serial": cert_serial,
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_bits": 2048,
            "issued": issued.strftime("%Y-%m-%d"),
            "expires": expires.strftime("%Y-%m-%d"),
            "validity_days": 365,
            "san": [sanitized, f"*.{sanitized}"],
            "is_valid": True,
            "is_wildcard": False
        },
        "tls_versions": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites": [
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        ],
        "security_rating": "A+",
        "disclaimer": "Simulated certificate - not connecting to real servers."
    }

# 12) SUBDOMAIN ENUMERATOR
def subdomain_enumerator(domain: str):
    """
    Simulate subdomain enumeration via common wordlist.
    Returns fictional subdomains based on domain hash.
    """
    sanitized = domain.strip() or "example.com"
    domain_hash = hashlib.sha256(sanitized.encode()).hexdigest()
    
    common_subdomains = [
        "www", "mail", "api", "admin", "dev", "staging", "test", "ftp", "cdn",
        "backup", "db", "app", "blog", "shop", "support", "vpn", "ssh", "ns1",
        "ns2", "mx", "mail1", "mail2", "pop", "smtp", "imap", "webmail"
    ]
    
    found = []
    for i, sub in enumerate(common_subdomains):
        if (int(domain_hash[:8], 16) + i) % 3 == 0:
            found.append({
                "subdomain": f"{sub}.{sanitized}",
                "ip": f"192.168.{(i+1)}.{(i*10) % 255}",
                "resolved": True
            })
    
    if not found:
        found = [{"subdomain": f"www.{sanitized}", "ip": "192.168.1.1", "resolved": True}]
    
    return {
        "domain": sanitized,
        "subdomains_found": len(found),
        "subdomains": sorted(found, key=lambda x: x["subdomain"]),
        "disclaimer": "Simulated enumeration - no real brute-force or queries performed."
    }

# 13) WHOIS LOOKUP
def whois_lookup(domain: str):
    """
    Simulate WHOIS domain lookup with fictional registrar info.
    """
    sanitized = domain.strip() or "example.com"
    domain_hash = hashlib.md5(sanitized.encode()).hexdigest()
    
    registrars = ["GoDaddy", "NameCheap", "AWS Route53", "CloudFlare", "Verisign"]
    reg_idx = int(domain_hash[:8], 16) % len(registrars)
    
    from datetime import datetime, timedelta
    created = datetime.now() - timedelta(days=1095)
    expires = datetime.now() + timedelta(days=180)
    
    return {
        "domain": sanitized,
        "registrar": registrars[reg_idx],
        "registrant": {
            "name": "Registrant Name",
            "email": f"admin@{sanitized}",
            "country": "US"
        },
        "created_date": created.strftime("%Y-%m-%d"),
        "expiry_date": expires.strftime("%Y-%m-%d"),
        "updated_date": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d"),
        "name_servers": [
            f"ns1.example.com",
            f"ns2.example.com"
        ],
        "dnssec": "signed",
        "status": "ok",
        "disclaimer": "Simulated WHOIS data - not querying real WHOIS servers."
    }

# 17) Steganography - Hide/Reveal text in images (LSB)
def encode_text_in_image(image_data_b64: str, text: str) -> dict:
    """
    Encode text into image using Least Significant Bit (LSB) steganography.
    Educational demonstration - not for production use.
    """
    try:
        from PIL import Image
        import io
        
        # Decode base64 image
        image_bytes = base64.b64decode(image_data_b64.split(',')[1] if ',' in image_data_b64 else image_data_b64)
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        
        # Convert text to binary
        text_bytes = text.encode('utf-8')
        text_binary = ''.join(format(byte, '08b') for byte in text_bytes)
        
        # Add length header (32 bits)
        length_binary = format(len(text_bytes), '032b')
        full_binary = length_binary + text_binary
        
        if len(full_binary) > img.width * img.height * 3:
            return {"error": "Text too long for this image"}
        
        # Encode into LSB
        pixels = img.load()
        bit_index = 0
        
        for y in range(img.height):
            for x in range(img.width):
                if bit_index >= len(full_binary):
                    break
                r, g, b = pixels[x, y][:3]
                
                # Modify LSB of R channel
                if bit_index < len(full_binary):
                    r = (r & 0xFE) | int(full_binary[bit_index])
                    bit_index += 1
                
                pixels[x, y] = (r, g, b)
        
        # Convert back to base64
        output = io.BytesIO()
        img.save(output, format='PNG')
        encoded = base64.b64encode(output.getvalue()).decode()
        
        return {
            "success": True,
            "encoded_image": f"data:image/png;base64,{encoded}",
            "text_length": len(text),
            "capacity": img.width * img.height * 3,
            "message": f"Text successfully hidden in image! ({len(text)} bytes encoded)"
        }
    except Exception as e:
        return {"error": f"Encoding failed: {str(e)}"}

def decode_text_from_image(image_data_b64: str) -> dict:
    """
    Decode hidden text from steganographic image (LSB).
    """
    try:
        from PIL import Image
        import io
        
        # Decode base64 image
        image_bytes = base64.b64decode(image_data_b64.split(',')[1] if ',' in image_data_b64 else image_data_b64)
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        
        # Extract binary data
        pixels = img.load()
        binary_str = ''
        
        for y in range(img.height):
            for x in range(img.width):
                r, g, b = pixels[x, y][:3]
                binary_str += str(r & 1)  # Get LSB
        
        # Extract length (first 32 bits)
        if len(binary_str) < 32:
            return {"error": "Image too small or no hidden data"}
        
        length = int(binary_str[:32], 2)
        text_binary = binary_str[32:32 + length * 8]
        
        if len(text_binary) < length * 8:
            return {"error": "Incomplete or corrupted hidden data"}
        
        # Convert binary to text
        decoded_text = ''.join(
            chr(int(text_binary[i:i+8], 2)) 
            for i in range(0, len(text_binary), 8)
        )
        
        return {
            "success": True,
            "hidden_text": decoded_text,
            "text_length": length,
            "message": f"Successfully extracted {length} bytes of hidden text!"
        }
    except Exception as e:
        return {"error": f"Decoding failed: {str(e)}"}

# 18) Hashing Cracker - Rainbow table simulator
COMMON_PASSWORD_LIST = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein",
    "trustno1", "dragon", "baseball", "111111", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "welcome", "jesus", "ninja", "mustang",
    "password123", "admin", "letmein", "princess", "qwerty123", "freedom",
    "whatever", "solo", "starwars", "batman", "cheater", "harley", "jordan",
    "hotmail", "passpass", "pass123", "pass", "pass1", "pass@123"
]

def hash_cracker(hash_value: str, hash_type: str) -> dict:
    """
    Attempt to crack hash using rainbow table (educational simulation).
    Returns password if found, attempts count, and time estimate.
    """
    hash_value = hash_value.lower().strip()
    hash_type = hash_type.lower()
    
    if hash_type not in ['md5', 'sha1', 'sha256']:
        return {"error": f"Unsupported hash type: {hash_type}"}
    
    # Hash function selector
    if hash_type == 'md5':
        hash_func = lambda x: hashlib.md5(x.encode()).hexdigest()
    elif hash_type == 'sha1':
        hash_func = lambda x: hashlib.sha1(x.encode()).hexdigest()
    else:
        hash_func = lambda x: hashlib.sha256(x.encode()).hexdigest()
    
    attempts = 0
    for password in COMMON_PASSWORD_LIST:
        attempts += 1
        if hash_func(password) == hash_value:
            return {
                "success": True,
                "found": True,
                "password": password,
                "attempts": attempts,
                "time_estimate": f"{attempts * 0.001:.3f} seconds",
                "message": f"✓ Password cracked in {attempts} attempts!"
            }
    
    return {
        "success": True,
        "found": False,
        "attempts": len(COMMON_PASSWORD_LIST),
        "time_estimate": f"{len(COMMON_PASSWORD_LIST) * 0.001:.3f} seconds",
        "message": f"Password not found in rainbow table ({len(COMMON_PASSWORD_LIST)} passwords tested)",
        "tip": "Try a longer or more complex password - stronger passwords take exponentially longer to crack!"
    }

# 19) CVE Vulnerability Scanner - Simulated lookup
CVE_DATABASE = {
    "apache httpd": {
        "2.4.49": [
            {"id": "CVE-2021-41773", "cvss": 7.5, "severity": "high", "description": "Path traversal vulnerability in mod_proxy", "remediation": "Upgrade to 2.4.50 or apply patch"},
            {"id": "CVE-2021-42013", "cvss": 7.5, "severity": "high", "description": "Path traversal in mod_proxy", "remediation": "Apply security update"}
        ],
        "2.4.41": [
            {"id": "CVE-2021-33193", "cvss": 7.5, "severity": "high", "description": "HTTP request smuggling", "remediation": "Upgrade to 2.4.48"}
        ]
    },
    "openssl": {
        "1.0.2": [
            {"id": "CVE-2016-2183", "cvss": 6.5, "severity": "medium", "description": "SWEET32 attack - weak encryption", "remediation": "Disable 3DES or upgrade"},
            {"id": "CVE-2019-1010023", "cvss": 5.3, "severity": "medium", "description": "Side-channel attack", "remediation": "Upgrade to 1.0.2u"}
        ],
        "1.1.1": [
            {"id": "CVE-2021-3711", "cvss": 8.1, "severity": "high", "description": "Out-of-bounds read in X.509", "remediation": "Upgrade to 1.1.1k"}
        ]
    },
    "mysql": {
        "5.7.10": [
            {"id": "CVE-2016-2047", "cvss": 6.7, "severity": "medium", "description": "Authentication bypass", "remediation": "Upgrade to 5.7.11"},
            {"id": "CVE-2015-3152", "cvss": 5.1, "severity": "medium", "description": "SSL negotiation flaw", "remediation": "Apply patch"}
        ],
        "8.0.0": [
            {"id": "CVE-2021-2154", "cvss": 8.8, "severity": "high", "description": "SQL injection in prepared statements", "remediation": "Upgrade to 8.0.23"}
        ]
    },
    "wordpress": {
        "5.0": [
            {"id": "CVE-2019-6340", "cvss": 7.2, "severity": "high", "description": "Unauthenticated REST API access", "remediation": "Upgrade to 5.1.1"}
        ],
        "5.7": [
            {"id": "CVE-2021-24487", "cvss": 6.5, "severity": "medium", "description": "Stored XSS in comments", "remediation": "Upgrade to 5.7.2"}
        ]
    },
    "django": {
        "2.2": [
            {"id": "CVE-2021-33571", "cvss": 6.5, "severity": "medium", "description": "Potential SQL injection via QuerySet.order_by", "remediation": "Upgrade to 2.2.20"},
            {"id": "CVE-2020-9402", "cvss": 5.3, "severity": "medium", "description": "SQL injection in GIS functions", "remediation": "Apply patch"}
        ],
        "3.2": [
            {"id": "CVE-2021-44716", "cvss": 7.5, "severity": "high", "description": "Denial of service via HTTP", "remediation": "Upgrade to 3.2.10"}
        ]
    }
}

def cve_lookup(software_name: str, version: str = None) -> dict:
    """
    Look up known CVEs for software (simulated database).
    Educational - uses fictional but realistic data.
    """
    software_name = software_name.lower().strip()
    
    if software_name not in CVE_DATABASE:
        return {
            "found": False,
            "software": software_name,
            "message": f"No CVEs found in database for '{software_name}'",
            "suggestion": "Try: apache httpd, openssl, mysql, wordpress, django"
        }
    
    db = CVE_DATABASE[software_name]
    
    if version and version not in db:
        return {
            "found": False,
            "software": software_name,
            "version": version,
            "message": f"No CVEs found for version {version}",
            "available_versions": list(db.keys())
        }
    
    results = []
    if version:
        results = db[version]
    else:
        # Return all CVEs for software
        for v in db.values():
            results.extend(v)
    
    # Sort by CVSS score
    results = sorted(results, key=lambda x: x['cvss'], reverse=True)
    
    return {
        "found": True,
        "software": software_name,
        "version": version if version else "all",
        "total_cves": len(results),
        "cves": results,
        "risk_level": "CRITICAL" if any(cve['cvss'] >= 9 for cve in results) else "HIGH" if any(cve['cvss'] >= 7 for cve in results) else "MEDIUM"
    }

# 14) PASSWORD GENERATOR
def password_generator(length: int = 16, include_symbols: bool = True, include_numbers: bool = True, include_uppercase: bool = True, include_lowercase: bool = True):
    """
    Generate strong random passwords with customizable rules.
    """
    import string
    characters = ""
    
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not characters:
        characters = string.ascii_letters + string.digits
    
    length = max(8, min(length, 128))  # Enforce 8-128 character range
    password = "".join(secrets.choice(characters) for _ in range(length))
    
    strength = "Strong"
    if length < 12:
        strength = "Medium"
    elif length < 8:
        strength = "Weak"
    
    return {
        "password": password,
        "length": length,
        "strength": strength,
        "entropy_bits": length * 5.7,
        "includes": {
            "lowercase": include_lowercase,
            "uppercase": include_uppercase,
            "numbers": include_numbers,
            "symbols": include_symbols
        },
        "tips": [
            "Use unique passwords for each account",
            "Avoid personal information (names, birthdates)",
            "Consider using a password manager",
            "Enable two-factor authentication when possible"
        ]
    }

# 15) EMAIL HEADER ANALYZER
def email_header_analyzer(headers: str):
    """
    Analyze email headers for spoofing, authentication, and security issues.
    Educational tool for identifying phishing and email security problems.
    """
    lines = headers.strip().split('\n')
    header_dict = {}
    
    for line in lines:
        if ':' in line:
            key, val = line.split(':', 1)
            header_dict[key.strip()] = val.strip()
    
    issues = []
    warnings = []
    info = []
    
    # Check for missing authentication headers
    if 'Authentication-Results' not in header_dict and 'DKIM-Signature' not in header_dict:
        issues.append("No SPF, DKIM, or DMARC authentication detected - high spoofing risk")
    
    if 'Return-Path' not in header_dict:
        issues.append("Missing Return-Path header - may indicate forwarding")
    
    # Check for suspicious patterns
    from_addr = header_dict.get('From', '')
    if 'noreply' in from_addr.lower() or 'no-reply' in from_addr.lower():
        info.append("Message from automated system (noreply)")
    
    # Check for multiple hops
    received_count = sum(1 for k in header_dict if k.lower() == 'received')
    if received_count > 3:
        warnings.append(f"Message went through {received_count} mail servers - verify legitimacy")
    
    # Check for encryption
    if 'TLS' not in header_dict.get('Received', ''):
        warnings.append("Email may not be encrypted in transit")
    
    return {
        "from": header_dict.get('From', 'Unknown'),
        "to": header_dict.get('To', 'Unknown'),
        "subject": header_dict.get('Subject', 'Unknown'),
        "date": header_dict.get('Date', 'Unknown'),
        "received_count": received_count,
        "authentication": {
            "spf": "SPF-Signature" in header_dict,
            "dkim": "DKIM-Signature" in header_dict,
            "dmarc": "Authentication-Results" in header_dict
        },
        "issues": issues,
        "warnings": warnings,
        "info": info,
        "risk_level": "high" if issues else ("medium" if warnings else "low"),
        "raw_headers": header_dict,
        "disclaimer": "Educational analysis only - not official email security validation."
    }

# 16) SQL INJECTION SIMULATOR
def sql_injection_simulator(user_input: str, query_type: str = "login"):
    """
    Simulate SQL injection vulnerability detection and exploitation.
    Educational tool to show how SQL injection works and how to prevent it.
    """
    
    # Detect common SQL injection patterns
    injection_patterns = [
        (r"'\s*or\s*'1'\s*=\s*'1", "Classic OR-based injection"),
        (r"'\s*or\s*1\s*=\s*1", "Numeric OR injection"),
        (r"';\s*DROP", "DROP statement injection"),
        (r"';\s*DELETE", "DELETE statement injection"),
        (r"';\s*UPDATE", "UPDATE statement injection"),
        (r"'\s*UNION\s*SELECT", "UNION-based injection"),
        (r"';\s*INSERT", "INSERT statement injection"),
        (r"--\s*", "SQL comment injection"),
        (r"/\*.*\*/", "Multi-line comment injection"),
        (r"xp_", "Extended stored procedure call"),
        (r"sp_", "Stored procedure call"),
        (r"exec|execute", "Dynamic code execution")
    ]
    
    detected_attacks = []
    for pattern, attack_name in injection_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            detected_attacks.append(attack_name)
    
    # Simulate vulnerable query construction
    if query_type == "login":
        vulnerable_query = f"SELECT * FROM users WHERE username = '{user_input}'"
    else:
        vulnerable_query = f"SELECT * FROM users WHERE email = '{user_input}'"
    
    # Simulate safe query (parameterized)
    safe_query = "SELECT * FROM users WHERE username = ?" if query_type == "login" else "SELECT * FROM users WHERE email = ?"
    
    success = len(detected_attacks) > 0
    
    return {
        "input": user_input,
        "is_vulnerable": success,
        "attacks_detected": detected_attacks,
        "vulnerable_query": vulnerable_query,
        "safe_query": safe_query,
        "prevention_tips": [
            "Use parameterized queries / prepared statements",
            "Validate and sanitize all user inputs",
            "Use ORM frameworks (SQLAlchemy, Sequelize, etc.)",
            "Apply principle of least privilege to database users",
            "Enable SQL error suppression in production",
            "Use Web Application Firewalls (WAF)",
            "Perform regular security testing and code reviews"
        ],
        "severity": "Critical" if success else "None",
        "disclaimer": "Educational simulation - not actual SQL injection testing."
    }