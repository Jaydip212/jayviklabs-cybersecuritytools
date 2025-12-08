# Jayvik Labs — Cybersecurity Educational Tool

An interactive learning platform combining a React (Vite) frontend with a Python FastAPI backend. Everything runs locally and simulates cybersecurity concepts in a safe, legal environment — **no real networks or systems are touched.**

## ✨ Features (25 Interactive Tools)

### 🔐 Core Security Tools
- **Password Strength Analyzer** — Provides score, strength, and best-practice suggestions
- **Password Generator** — Create cryptographically strong passwords with custom rules
- **Hashing Demonstrator** — MD5, SHA-1, and SHA-256 with security notes
- **Hashing Cracker** — Rainbow table simulator with common password wordlist
- **Encryption & Encoding Lab** — AES encryption/decryption, Caesar cipher, Base64

### 🔍 Network & Domain Tools
- **Nmap Simulator** — Port scanning with SYN, Connect, UDP, ACK scan types (Educational)
- **DNS Enumeration** — A, AAAA, MX, TXT, NS record lookup with tabbed interface
- **SSL/TLS Certificate Analyzer** — Certificate details, validity checks, security ratings
- **Subdomain Enumerator** — Discover subdomains using wordlist simulation
- **WHOIS Lookup** — Domain registration info, registrar, dates, nameservers

### 🎯 Advanced Analysis & Web Security
- **Port Scan Simulator** — Safe, deterministic port scan demonstration with ethical reminders
- **Phishing Email Analyzer** — Spot social engineering red flags safely
- **Email Header Analyzer** — Detect spoofing, authentication issues, and phishing indicators
- **SQL Injection Lab** — Interactive SQL injection vulnerability detection and prevention
- **Steganography Tool** — Hide/reveal text in images using LSB encoding (educational)
- **XSS Vulnerability Tester** — Detect XSS attack patterns with severity ratings and prevention tips
- **Brute Force Password Simulator** — Dictionary, brute force, and hybrid attack simulations
- **Mobile Security Checker** — Android/iOS security audit with OWASP Mobile Top 10 mapping
- **API Security Analyzer** — Endpoint security analysis with OWASP API Security Top 10 (2023)
- **CSRF Token Generator** — Generate secure CSRF protection tokens with validation methods
- **Log Security Analyzer** — Analyze logs for threats, vulnerabilities, and suspicious patterns
- **URL Security Checker** — Check URLs for phishing, malware, and security risks

### 🛡️ Vulnerability & Threat Analysis
- **Vulnerability Scanner** — CVE lookup simulator with severity ratings and remediation
- **Threat Detection Simulator** — Quiz-style incident response scenarios
- **Recon Blueprint Planner** — Generate ethical recon checklists for penetration testing

### 📚 Learning & Awareness
- **Learn Mode** — OWASP Top 10 reference grid with interactive quiz
- **About Page** — Meet founder Jaydip Jadhav and learn about Jayvik Labs' ethical hacking mission

### 🎮 Gamification
- **Achievement System** — Earn XP points and level up as you use tools
- **Progress Tracking** — localStorage persistence of your XP, level, and achievements

## 🧱 Project Structure

```
jayvik-cybertool/
├── backend/
│   ├── app.py            # FastAPI application
│   ├── utils.py          # Hashing, crypto helpers, safe port scan simulation
│   ├── requirements.txt  # Backend dependencies
│   └── README.md (optional)
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── index.css
│       └── components/
           ├── Navbar.jsx
           ├── PasswordAnalyzer.jsx
           ├── PasswordGenerator.jsx
           ├── PortSimulator.jsx
           ├── HashDemo.jsx
           ├── HashingCracker.jsx
           ├── CryptoLab.jsx
           ├── PhishingAnalyzer.jsx
           ├── EmailHeaderAnalyzer.jsx
           ├── ReconPlanner.jsx
           ├── ThreatSimulator.jsx
           ├── NmapSimulator.jsx
           ├── DnsEnumerator.jsx
           ├── SslAnalyzer.jsx
           ├── SubdomainEnumerator.jsx
           ├── WhoisLookup.jsx
           ├── SqlInjectionLab.jsx
           ├── SteganographyTool.jsx
           ├── VulnerabilityScanner.jsx
           ├── XssTester.jsx
           ├── BruteForceSimulator.jsx
           ├── MobileSecurityChecker.jsx
           ├── ApiSecurityAnalyzer.jsx
           ├── CsrfTokenGenerator.jsx
           ├── LogAnalyzer.jsx
           ├── UrlSecurityChecker.jsx
           ├── LearnMode.jsx
           └── AboutPage.jsx
└── README.md
```

## 🚀 Getting Started

### 1. Backend (FastAPI)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate    # Windows
# source .venv/bin/activate  # macOS/Linux
python -m pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

### 2. Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
# open http://localhost:5173 in the browser
```

## 📡 API Endpoints

| Endpoint               | Method | Description                                      |
|------------------------|--------|--------------------------------------------------|
| `/`                    | GET    | Health check                                     |
| **Password & Hashing** |        |                                                  |
| `/password-strength`   | POST   | Analyze password strength                        |
| `/password/generate`   | POST   | Generate strong random passwords                 |
| `/hashes`              | POST   | Return MD5, SHA-1, and SHA-256                   |
| `/hashes/crack`        | POST   | Crack hash using rainbow table simulator         |
| **Encryption**         |        |                                                  |
| `/encrypt/aes`         | POST   | AES encryption demo                              |
| `/decrypt/aes`         | POST   | AES decryption demo                              |
| `/encrypt/caesar`      | POST   | Caesar cipher with customizable shift            |
| `/base64`              | POST   | Base64 encode/decode                             |
| **Network Scanning**   |        |                                                  |
| `/port-scan`           | POST   | Safe simulated port scan (no real scanning)      |
| `/nmap/scan`           | POST   | Nmap-style port scanning (SYN, Connect, UDP, ACK)|
| **Domain Intelligence**|        |                                                  |
| `/dns/enumerate`       | POST   | DNS record enumeration (A, AAAA, MX, TXT, NS)    |
| `/ssl/analyze`         | POST   | SSL/TLS certificate analysis (simulated)         |
| `/subdomain/enumerate` | POST   | Subdomain discovery via wordlist (simulated)     |
| `/whois/lookup`        | POST   | WHOIS domain lookup (simulated)                  |
| **Email & Web Security**|       |                                                  |
| `/email/analyze-headers` | POST | Email header analysis for spoofing detection   |
| `/security/sql-injection-test` | POST | SQL injection vulnerability detection        |
| **Steganography**      |        |                                                  |
| `/steganography/encode` | POST  | Hide text in image using LSB encoding           |
| `/steganography/decode` | POST  | Extract hidden text from image                  |
| **Vulnerability Scanning**|     |                                                  |
| `/vulnerabilities/scan` | POST  | CVE lookup with severity ratings                |
| `/security/xss-test`   | POST   | XSS vulnerability detection with severity analysis|
| `/security/brute-force`| POST   | Password cracking simulation (dictionary/brute/hybrid)|
| `/mobile/security-check`| POST  | Mobile app security audit (Android/iOS)         |
| `/api/security-analyze`| POST   | API endpoint security analysis with OWASP mapping|
| `/security/csrf-token` | POST   | Generate CSRF protection tokens                 |
| `/security/analyze-logs`| POST  | Analyze logs for security threats and patterns  |
| `/security/check-url` | POST   | Check URLs for phishing and security risks      |
| **Analysis & Planning**|        |                                                  |
| `/phishing/analyze`    | POST   | Heuristic phishing message analysis (simulation) |
| `/recon/blueprint`     | POST   | Generate simulated recon checklist               |
| `/simulated-network`   | GET    | Returns fictional network topology               |

**All endpoints are educational simulations.** Responses are deterministic where appropriate and designed to emphasize ethics and best practices.

## ⚠️ Safety & Legal Disclaimer

- **Simulations only.** This project never interacts with external networks or systems.
- Running real port scans on networks without permission is illegal and unethical.
- Always seek written authorization before performing security testing on any system.
- Use this tool for learning in controlled environments only.

## 🧠 Learning Goals

- Understand the fundamentals of password hygiene, hashing, and encryption.
- Learn network reconnaissance techniques through safe simulations (Nmap, DNS, SSL, WHOIS).
- Practice identifying phishing and social engineering attacks.
- Explore ethical reconnaissance planning without touching real systems.
- Build awareness of legal and safety boundaries in cybersecurity work.
- Master OWASP Top 10 vulnerabilities through interactive learning.

## 🌐 Real-World Tools Simulated

This platform provides educational simulations of professional penetration testing tools:

- **Nmap** — Network mapper for port discovery and service enumeration
- **DNS Tools** — nslookup, dig, host alternatives for DNS reconnaissance
- **SSL Labs** — Certificate transparency and validation checking
- **Fierce/Sublist3r** — Subdomain discovery and enumeration
- **WHOIS Clients** — Domain registration information gathering

**All simulations return fictional but realistic data.** No external network connections are made.

## ✅ Next Steps

- Backend unit tests with pytest
- Docker containers for full-stack deployment
- Advanced web security labs (XSS, CSRF, XXE)
- More OWASP vulnerabilities coverage
- Mobile security concepts
- Cloud security scenarios
- API security testing
- Community leaderboard (backend database required)

---

Jayvik Labs — teaching cybersecurity the right way: safe, ethical, and hands-on.