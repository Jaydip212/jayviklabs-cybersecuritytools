# Jayvik Labs Backend

FastAPI backend powering the Jayvik Labs cybersecurity educational tool. All functionality operates on simulated data and never interacts with real networks.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate    # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

## Endpoints

- `GET /` — Health check
- `POST /password-strength` — Analyze password strength (educational feedback)
- `POST /hashes` — Generate MD5, SHA-1, and SHA-256 with security notes
- `POST /encrypt/aes` — AES encryption demo (random IV each time)
- `POST /decrypt/aes` — AES decryption demo using server-generated key
- `POST /encrypt/caesar` — Classical Caesar cipher demonstration
- `POST /base64` — Base64 encode/decode showcase
- `POST /port-scan` — Safe simulated port scan (no real scanning)
- `GET /simulated-network` — Fictional network topology for teaching

## Safety Notice

All security demonstrations are simulated. Real-world security testing must always follow legal and ethical guidelines.