# backend/app.py
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

# Allow local dev from frontend (default Vite dev port 5173)
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"http://192\.168\.\d+\.\d+:5173",
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
def read_root():
    """Health check endpoint."""
    return {"message": "Jayvik Labs Cybersecurity Educational API", "status": "active"}

@app.post('/password-strength')
def pw_strength(payload: PasswordIn):
    """Return password strength analysis (safe, no logs saved)."""
    return password_strength(payload.password)

@app.post('/hashes')
def hashes(payload: TextIn):
    """Generate MD5, SHA-1, and SHA-256 hashes for educational purposes."""
    return generate_hashes(payload.text)

@app.post('/encrypt/aes')
def encrypt_aes(payload: TextIn):
    """AES encryption demonstration with random IV."""
    ciphertext, iv = aes_encrypt(payload.text)
    return {"ciphertext": ciphertext, "iv": iv}

@app.post('/decrypt/aes')
def decrypt_aes(payload: Dict):
    """AES decryption demonstration."""
    plain = aes_decrypt(payload['ciphertext'], payload['iv'])
    return {"plaintext": plain}

@app.post('/encrypt/caesar')
def encrypt_caesar(payload: Dict):
    """Caesar cipher encryption with customizable shift."""
    text = payload['text']
    shift = int(payload.get('shift', 3))
    return {"ciphertext": caesar_cipher(text, shift)}

@app.post('/base64')
def base64_op(payload: Dict):
    """Base64 encode/decode demonstration."""
    return base64_encode_decode(payload['text'])

@app.post('/port-scan')
def port_scan(payload: PortScanIn):
    """
    IMPORTANT: This is a SIMULATION ONLY. 
    We DO NOT scan any real network interfaces or IP addresses.
    Returns deterministic fictional data for educational purposes.
    """
    return simulated_port_scan(payload.target)

@app.post('/phishing/analyze')
def analyze_phishing(payload: TextIn):
    """Heuristic phishing email analyzer (educational)."""
    return phishing_analyzer(payload.text)

@app.post('/recon/blueprint')
def recon_plan(payload: ReconIn):
    """Generate a simulated recon playbook for a given target."""
    return recon_blueprint(payload.target)

@app.get('/simulated-network')
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