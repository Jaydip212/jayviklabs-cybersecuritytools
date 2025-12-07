# Jayvik Labs — Cybersecurity Educational Tool

An interactive learning platform combining a React (Vite) frontend with a Python FastAPI backend. Everything runs locally and simulates cybersecurity concepts in a safe, legal environment — **no real networks or systems are touched.**

## ✨ Features (12 Interactive Tools)

### 🔐 Core Security Tools
- **Password Strength Analyzer** — Provides score, strength, and best-practice suggestions
- **Hashing Demonstrator** — MD5, SHA-1, and SHA-256 with security notes
- **Encryption & Encoding Lab** — AES encryption/decryption, Caesar cipher, Base64

### 🔍 Network & Domain Tools
- **Nmap Simulator** — Port scanning with SYN, Connect, UDP, ACK scan types (Educational)
- **DNS Enumeration** — A, AAAA, MX, TXT, NS record lookup with tabbed interface
- **SSL/TLS Certificate Analyzer** — Certificate details, validity checks, security ratings
- **Subdomain Enumerator** — Discover subdomains using wordlist simulation
- **WHOIS Lookup** — Domain registration info, registrar, dates, nameservers

### 🎯 Advanced Analysis
- **Port Scan Simulator** — Safe, deterministic port scan demonstration with ethical reminders
- **Phishing Email Analyzer** — Spot social engineering red flags safely
- **Recon Blueprint Planner** — Generate ethical recon checklists for penetration testing

### 📚 Learning & Awareness
- **Threat Detection Simulator** — Quiz-style incident response scenarios
- **Learn Mode** — OWASP Top 10 reference grid with interactive quiz
- **About Page** — Meet founder Jaydip Jadhav and learn about Jayvik Labs' ethical hacking mission

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
           ├── PortSimulator.jsx
           ├── HashDemo.jsx
           ├── CryptoLab.jsx
           ├── PhishingAnalyzer.jsx
           ├── ReconPlanner.jsx
           ├── ThreatSimulator.jsx
           ├── NmapSimulator.jsx
           ├── DnsEnumerator.jsx
           ├── SslAnalyzer.jsx
           ├── SubdomainEnumerator.jsx
           ├── WhoisLookup.jsx
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
| `/hashes`              | POST   | Return MD5, SHA-1, and SHA-256                   |
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

- Add backend unit tests (pytest)
- Introduce gamified achievement tracking (localStorage)
- Create Docker containers for full-stack deployment
- Integrate ESLint/Prettier for consistent frontend style

---

Jayvik Labs — teaching cybersecurity the right way: safe, ethical, and hands-on.