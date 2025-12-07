# Jayvik Labs — Cybersecurity Educational Tool

An interactive learning platform combining a React (Vite) frontend with a Python FastAPI backend. Everything runs locally and simulates cybersecurity concepts in a safe, legal environment — **no real networks or systems are touched.**

## ✨ Features

- **Password Strength Analyzer** — Provides score, strength, and best-practice suggestions
- **Port Scan Simulator** — Safe, deterministic port scan demonstration with ethical reminders
- **Hashing Demonstrator** — MD5, SHA-1, and SHA-256 with security notes
- **Encryption & Encoding Lab** — AES encryption/decryption, Caesar cipher, Base64
- **Phishing Email Analyzer** — Spot social engineering red flags safely
- **Recon Blueprint Planner** — Generate ethical recon checklists
- **Threat Detection Simulator** — Quiz-style incident response scenarios
- **Learn Mode** — Bite-size lessons and ethical cybersecurity guidance
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
│           ├── Navbar.jsx
│           ├── PasswordAnalyzer.jsx
│           ├── PortSimulator.jsx
│           ├── HashDemo.jsx
│           ├── CryptoLab.jsx
│           ├── PhishingAnalyzer.jsx
│           ├── ReconPlanner.jsx
│           ├── ThreatSimulator.jsx
│           ├── LearnMode.jsx
│           └── AboutPage.jsx
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

| Endpoint           | Method | Description                                      |
|-------------------|--------|--------------------------------------------------|
| `/`               | GET    | Health check                                     |
| `/password-strength` | POST | Analyze password strength                        |
| `/hashes`         | POST   | Return MD5, SHA-1, and SHA-256                   |
| `/encrypt/aes`    | POST   | AES encryption demo                              |
| `/decrypt/aes`    | POST   | AES decryption demo                              |
| `/encrypt/caesar` | POST   | Caesar cipher with customizable shift            |
| `/base64`         | POST   | Base64 encode/decode                             |
| `/port-scan`      | POST   | Safe simulated port scan (no real scanning)      |
| `/phishing/analyze` | POST | Heuristic phishing message analysis (simulation) |
| `/recon/blueprint` | POST | Generate simulated recon checklist               |
| `/simulated-network` | GET | Returns fictional network topology               |

All endpoints are educational examples. Responses are deterministic where required and designed to emphasize ethics and best practices.

## ⚠️ Safety & Legal Disclaimer

- **Simulations only.** This project never interacts with external networks or systems.
- Running real port scans on networks without permission is illegal and unethical.
- Always seek written authorization before performing security testing on any system.
- Use this tool for learning in controlled environments only.

## 🧠 Learning Goals

- Understand the fundamentals of password hygiene, hashing, and encryption.
- Practice ethical decision-making via threat detection simulations.
- Build awareness of legal and safety boundaries in cybersecurity work.

## ✅ Next Steps

- Add backend unit tests (pytest)
- Introduce gamified achievement tracking (localStorage)
- Create Docker containers for full-stack deployment
- Integrate ESLint/Prettier for consistent frontend style

---

Jayvik Labs — teaching cybersecurity the right way: safe, ethical, and hands-on.