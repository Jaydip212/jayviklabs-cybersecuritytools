from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict
from fastapi.middleware.cors import CORSMiddleware
from utils import (
    password_strength,
    generate_hashes,
    aes_encrypt,
    aes_decrypt,
    caesar_cipher,
    base64_encode_decode,
    simulated_port_scan,
    phishing_analyzer,
    recon_blueprint
)

app = FastAPI(title="Jayvik Labs — Cybersecurity Edu API")

# Allow CORS for production deployment
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://*.vercel.app",
    "https://*.netlify.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for simplicity in deployment
    allow_origin_regex=r"https://.*\.(vercel\.app|netlify\.app)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TextIn(BaseModel):
    text: str

class PasswordIn(BaseModel):
    password: str

class PortScanIn(BaseModel):
    target: str  # will be ignored — simulation ONLY

class ReconIn(BaseModel):
    target: str

@app.get('/')
@app.get('/api')
def read_root():
    """Health check endpoint."""
    return {"message": "Jayvik Labs Cybersecurity Educational API", "status": "active"}

@app.post('/api/password-strength')
def pw_strength(payload: PasswordIn):
    """Return password strength analysis (safe, no logs saved)."""
    return password_strength(payload.password)

@app.post('/api/hashes')
def hashes(payload: TextIn):
    """Generate MD5, SHA-1, and SHA-256 hashes for educational purposes."""
    return generate_hashes(payload.text)

@app.post('/api/encrypt/aes')
def encrypt_aes(payload: TextIn):
    """AES encryption demonstration with random IV."""
    ciphertext, iv = aes_encrypt(payload.text)
    return {"ciphertext": ciphertext, "iv": iv}

@app.post('/api/decrypt/aes')
def decrypt_aes(payload: Dict):
    """AES decryption demonstration."""
    plain = aes_decrypt(payload['ciphertext'], payload['iv'])
    return {"plaintext": plain}

@app.post('/api/encrypt/caesar')
def encrypt_caesar(payload: Dict):
    """Caesar cipher encryption with customizable shift."""
    text = payload['text']
    shift = int(payload.get('shift', 3))
    return {"ciphertext": caesar_cipher(text, shift)}

@app.post('/api/base64')
def base64_op(payload: Dict):
    """Base64 encode/decode demonstration."""
    return base64_encode_decode(payload['text'])

@app.post('/api/port-scan')
def port_scan(payload: PortScanIn):
    """
    IMPORTANT: This is a SIMULATION ONLY. 
    We DO NOT scan any real network interfaces or IP addresses.
    Returns deterministic fictional data for educational purposes.
    """
    return simulated_port_scan(payload.target)

@app.post('/api/phishing/analyze')
def analyze_phishing(payload: TextIn):
    """Heuristic phishing email analyzer (educational)."""
    return phishing_analyzer(payload.text)

@app.post('/api/recon/blueprint')
def recon_plan(payload: ReconIn):
    """Generate a simulated recon playbook for a given target."""
    return recon_blueprint(payload.target)

@app.get('/api/simulated-network')
def simulated_network():
    """Return the predefined virtual network model for demonstrations."""
    return {
        "network": "virtual_lab", 
        "description": "Simulated network for educational purposes only",
        "hosts": [
            {"ip": "192.168.100.10", "hostname": "web-server", "open_ports": [22, 80]},
            {"ip": "192.168.100.20", "hostname": "secure-server", "open_ports": [443]},
            {"ip": "192.168.100.30", "hostname": "workstation", "open_ports": []},
            {"ip": "192.168.100.40", "hostname": "database", "open_ports": [3306, 5432]}
        ]
    }

# Vercel serverless function handler
handler = app