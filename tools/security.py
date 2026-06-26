import os
import re
import base64
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ─────────────────── Encryption & Decryption ───────────────────

# Static/default salt for fallback derivation if user doesn't specify one
DEFAULT_SALT = b"\x89\xaa\xe3\x02\xfb\xcc\xdd\x01\x19\x28\x37\x46\x55\x66\x77\x88"

def derive_key(passphrase: str, salt: bytes = DEFAULT_SALT) -> bytes:
    """Derives a 256-bit key from a passphrase and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(data: str, passphrase: str) -> str:
    """Encrypts data using AES-256-GCM and returns a base64 encoded payload."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    
    # Combined payload: salt (16) + nonce (12) + ciphertext
    payload = salt + nonce + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt_data(encrypted_b64: str, passphrase: str) -> str:
    """Decrypts AES-256-GCM encrypted data from a base64 payload."""
    try:
        payload = base64.b64decode(encrypted_b64)
        if len(payload) < 28:
            raise ValueError("Payload too short to be valid ciphertext.")
            
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]
        
        key = derive_key(passphrase, salt)
        aesgcm = AESGCM(key)
        
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# ─────────────────── Input Validation ───────────────────

# Strict domain regex matching valid hostnames (like shop.apex-demo.com)
DOMAIN_REGEX = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
    r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$'
)

# Standard IPv4 Regex
IPV4_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def validate_target(target: str) -> bool:
    """Validates if the target domain/host is safe and syntactically correct."""
    target = target.strip()
    if not target or len(target) > 253:
        return False
    # Avoid local or private hostnames / loopbacks for safety
    if target in ("localhost", "127.0.0.1", "::1"):
        return True # Allowed for local testing
    if "." not in target:
        return False
    return bool(DOMAIN_REGEX.match(target))

def validate_ip(ip: str) -> bool:
    """Validates if the IP is a valid IPv4 address."""
    ip = ip.strip()
    if not IPV4_REGEX.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def validate_ports(ports: List[int]) -> bool:
    """Ensures ports are positive integers within standard boundaries (1-65535)."""
    if not isinstance(ports, list) or len(ports) == 0:
        return False
    for p in ports:
        if not isinstance(p, int) or p < 1 or p > 65535:
            return False
    return True

# ─────────────────── Rate Limiter ───────────────────

class TokenBucketRateLimiter:
    """A thread-safe in-memory rate limiter using the Token Bucket algorithm."""
    def __init__(self, rate: int, capacity: int):
        import threading
        self.rate = rate  # Tokens added per second
        self.capacity = capacity  # Maximum bucket capacity
        self.buckets = {}  # IP -> {"tokens": float, "last_updated": float}
        self.lock = threading.Lock()

    def check_request(self, ip: str) -> bool:
        """Returns True if request is allowed, False if rate-limited."""
        import time
        now = time.time()
        with self.lock:
            if ip not in self.buckets:
                self.buckets[ip] = {"tokens": float(self.capacity) - 1.0, "last_updated": now}
                return True
                
            bucket = self.buckets[ip]
            elapsed = now - bucket["last_updated"]
            bucket["last_updated"] = now
            
            # Replenish tokens
            new_tokens = elapsed * self.rate
            bucket["tokens"] = min(float(self.capacity), bucket["tokens"] + new_tokens)
            
            if bucket["tokens"] >= 1.0:
                bucket["tokens"] -= 1.0
                return True
            else:
                return False
