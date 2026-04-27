"""
OWASP A07:2021 - Identification and Authentication Failures
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import time
import hmac
import hashlib
import sqlite3
import base64
import json
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "weak_secret"   # BUG: see A02 — weak, hardcoded

# ============================================================
# VULNERABILITY 1: No account lockout / brute-force protection
# ============================================================

@app.route("/login", methods=["POST"])
def login_no_lockout():
    """
    BUG: Unlimited login attempts with no lockout, no delay,
    no CAPTCHA. Password can be brute-forced offline.
    """
    username = request.json.get("username")
    password = request.json.get("password")
    # BUG: No attempt counter, no sleep, no lockout
    conn = sqlite3.connect("users.db")
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    ).fetchone()
    if user:
        session["user_id"] = user[0]
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid"}), 401


# ============================================================
# VULNERABILITY 2: Homemade JWT (broken signature verification)
# ============================================================

def create_token_vulnerable(user_id: int) -> str:
    """
    BUG: Using a weak, custom token format.
    Header algorithm can be changed to 'none' → signature skipped.
    Secret key is trivially guessable.
    """
    header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode()
    payload = base64.b64encode(json.dumps({"user_id": user_id}).encode()).decode()
    # BUG: weak secret used for signing
    secret = "secret"
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()
    return f"{header}.{payload}.{signature}"


def verify_token_vulnerable(token: str) -> dict:
    """
    BUG: Trusts the 'alg' field from the attacker-controlled header.
    Attacker sets alg='none', removes signature → authentication bypass.
    """
    parts = token.split(".")
    header = json.loads(base64.b64decode(parts[0]))
    payload = json.loads(base64.b64decode(parts[1]))
    algorithm = header.get("alg")   # BUG: attacker controls this

    if algorithm == "none":
        # BUG: if alg is 'none', signature is not checked at all
        return payload

    # Even if it falls through to signature check, secret is weak
    secret = "secret"
    expected_sig = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).hexdigest()
    if parts[2] != expected_sig:
        raise ValueError("Invalid token")
    return payload


# ============================================================
# VULNERABILITY 3: Session fixation
# ============================================================

@app.route("/login-fixation", methods=["POST"])
def login_session_fixation():
    """
    BUG: Session ID is not regenerated after login.
    Attacker can set a known session ID before the victim logs in,
    then use that session ID after the victim authenticates.
    """
    username = request.json.get("username")
    password = request.json.get("password")
    if authenticate(username, password):
        # BUG: Should call session.clear() and regenerate session here
        session["user_id"] = get_user_id(username)
        return jsonify({"status": "logged in"})
    return jsonify({"error": "Invalid credentials"}), 401


# ============================================================
# VULNERABILITY 4: Insecure "Remember Me" cookie
# ============================================================

@app.route("/set-remember-me")
def remember_me_vulnerable():
    """
    BUG: Predictable remember-me cookie based on username + timestamp.
    Attacker can predict or brute-force the cookie value.
    """
    username = request.args.get("username")
    # BUG: username:timestamp is predictable and not cryptographically signed
    cookie_value = base64.b64encode(f"{username}:{int(time.time())}".encode()).decode()
    response = jsonify({"status": "ok"})
    response.set_cookie(
        "remember_me",
        cookie_value,
        # BUG: Missing secure=True, httponly=True, samesite='Strict'
    )
    return response


# ============================================================
# VULNERABILITY 5: Password policy — no minimum requirements
# ============================================================

def register_user_no_policy(username: str, password: str):
    """
    BUG: Accepts any password including single characters, common words,
    or the username itself. No complexity requirements whatsoever.
    """
    conn = sqlite3.connect("users.db")
    # BUG: No length check, no complexity, no common-password check
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()


# ============================================================
# SECURE versions (for reference)
# ============================================================

import secrets

def create_token_secure(user_id: int) -> str:
    """CORRECT: Use PyJWT with a strong secret and explicit algorithm."""
    import jwt
    secret = secrets.token_hex(32)   # In practice, load from env
    return jwt.encode(
        {"user_id": user_id, "exp": time.time() + 3600},
        secret,
        algorithm="HS256"   # Algorithm fixed server-side, not from token header
    )


@app.route("/login-secure", methods=["POST"])
def login_secure():
    """CORRECT: Regenerate session on login to prevent fixation."""
    username = request.json.get("username")
    password = request.json.get("password")
    if authenticate(username, password):
        session.clear()   # Invalidate old session
        session["user_id"] = get_user_id(username)
        return jsonify({"status": "logged in"})
    time.sleep(0.5)   # Constant-time response to deter timing attacks
    return jsonify({"error": "Invalid credentials"}), 401


def validate_password_policy(password: str) -> bool:
    """CORRECT: Enforce basic password requirements."""
    if len(password) < 12:
        return False
    common = {"password", "12345678", "qwerty", "letmein"}
    if password.lower() in common:
        return False
    return True


# --- Stubs ---
def authenticate(u, p): return True
def get_user_id(u): return 1
