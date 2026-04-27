"""
OWASP A02:2021 - Cryptographic Failures
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import sqlite3
import hashlib
import base64
import os

# ============================================================
# VULNERABILITY 1: Weak password hashing (MD5, no salt)
# ============================================================

def store_password_vulnerable(username: str, password: str):
    """
    BUG: MD5 is cryptographically broken and has no salt.
    Rainbow table attacks trivially crack these hashes.
    """
    # MD5 is fast, broken, and has no salt — worst possible choice
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect("users.db")
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    conn.commit()


# ============================================================
# VULNERABILITY 2: Hardcoded secrets / keys
# ============================================================

SECRET_KEY = "hardcoded_secret_1234"          # BUG: in source code
DATABASE_PASSWORD = "admin123"                  # BUG: committed to git
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"         # BUG: credentials in code
ENCRYPTION_KEY = b"0123456789abcdef"            # BUG: static key


# ============================================================
# VULNERABILITY 3: Weak symmetric encryption (ECB mode)
# ============================================================

def encrypt_data_vulnerable(data: str) -> bytes:
    """
    BUG: AES-ECB mode reveals patterns in plaintext.
    Identical plaintext blocks produce identical ciphertext blocks.
    """
    from Crypto.Cipher import AES
    # ECB mode — never use for anything meaningful
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    padded = data.ljust(16)[:16].encode()
    return cipher.encrypt(padded)


# ============================================================
# VULNERABILITY 4: Sensitive data transmitted in plain HTTP
# ============================================================

def send_credentials_vulnerable(username: str, password: str):
    """
    BUG: Sending credentials over plain HTTP (no TLS).
    Data is exposed to any network observer.
    """
    import urllib.request
    import json
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        "http://api.example.com/login",   # BUG: http:// not https://
        data=data,
        method="POST"
    )
    return urllib.request.urlopen(req)


# ============================================================
# VULNERABILITY 5: Sensitive data stored in plaintext
# ============================================================

def save_sensitive_data_vulnerable(credit_card: str, ssn: str):
    """
    BUG: Storing sensitive PII and financial data in plaintext.
    A DB dump immediately exposes all user secrets.
    """
    conn = sqlite3.connect("users.db")
    conn.execute(
        "INSERT INTO payments (card_number, ssn) VALUES (?, ?)",
        (credit_card, ssn)   # BUG: should be encrypted at rest
    )
    conn.commit()


# ============================================================
# SECURE versions (for reference)
# ============================================================

def store_password_secure(username: str, password: str):
    """CORRECT: bcrypt with auto-generated salt."""
    import bcrypt
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    conn = sqlite3.connect("users.db")
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    conn.commit()


def get_secret_secure(key_name: str) -> str:
    """CORRECT: Read secrets from environment variables or a secrets manager."""
    value = os.environ.get(key_name)
    if value is None:
        raise EnvironmentError(f"Secret '{key_name}' not set in environment")
    return value
