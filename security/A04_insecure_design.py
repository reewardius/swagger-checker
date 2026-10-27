"""
OWASP A04:2021 - Insecure Design
Missing security controls at the architecture/design level.
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import time
import random
import sqlite3
from flask import Flask, request, jsonify, session

app = Flask(__name__)

# ============================================================
# VULNERABILITY 1: No rate limiting on sensitive endpoints
# ============================================================

login_attempts: dict = {}   # in-memory only, trivially bypassed

@app.route("/api/login", methods=["POST"])
def login_no_rate_limit():
    """
    BUG: No rate limiting. An attacker can brute-force passwords
    at millions of attempts per second with no consequences.
    Design flaw: rate limiting was never considered.
    """
    username = request.json.get("username")
    password = request.json.get("password")
    # BUG: No lockout, no CAPTCHA, no exponential backoff
    user = authenticate(username, password)
    if user:
        return jsonify({"token": generate_token(user)})
    return jsonify({"error": "Invalid credentials"}), 401


# ============================================================
# VULNERABILITY 2: Insecure password reset flow
# ============================================================

@app.route("/api/reset-password", methods=["POST"])
def insecure_password_reset():
    """
    BUG: Password reset uses a predictable 4-digit PIN sent over email.
    - Only 10,000 possible values → trivially brute-forceable.
    - No expiry on the reset token.
    - Design flaw: security requirements were never specified.
    """
    email = request.json.get("email")
    # BUG: 4-digit PIN is way too short
    reset_pin = random.randint(1000, 9999)
    store_reset_pin(email, reset_pin)
    send_email(email, f"Your reset PIN is: {reset_pin}")
    return jsonify({"status": "PIN sent"})


@app.route("/api/confirm-reset", methods=["POST"])
def confirm_reset_no_expiry():
    """
    BUG: PIN has no expiry time. An attacker can brute-force it
    days or weeks after the fact with no time pressure.
    """
    email = request.json.get("email")
    pin = request.json.get("pin")
    stored_pin = get_stored_pin(email)   # Never expires!
    if str(stored_pin) == str(pin):
        new_password = request.json.get("new_password")
        update_password(email, new_password)
        return jsonify({"status": "Password updated"})
    return jsonify({"error": "Invalid PIN"}), 400


# ============================================================
# VULNERABILITY 3: Business logic flaw — negative quantities
# ============================================================

@app.route("/api/checkout", methods=["POST"])
def checkout_business_logic_flaw():
    """
    BUG: No validation of quantity. An attacker can pass negative
    quantity to get money credited to their account.
    Design flaw: trust user-supplied business data without validation.
    """
    items = request.json.get("items", [])
    total = 0
    for item in items:
        price = get_item_price(item["id"])
        quantity = item["quantity"]    # BUG: could be -100 → earns money
        total += price * quantity
    
    if total < 0:
        # Attacker gets a refund / credit for nothing
        credit_account(session["user_id"], abs(total))
    else:
        charge_account(session["user_id"], total)
    
    return jsonify({"total": total})


# ============================================================
# VULNERABILITY 4: Enumerable resource IDs expose structure
# ============================================================

@app.route("/api/order/<int:order_id>")
def get_order_enumerable(order_id):
    """
    BUG: Sequential integer IDs allow enumeration of all orders.
    Design flaw: predictable IDs with no ownership check.
    An attacker iterates order_id from 1 to N to scrape all orders.
    """
    conn = sqlite3.connect("orders.db")
    # Also missing access control (A01), but the design flaw is the sequential ID
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return jsonify(order)


# ============================================================
# SECURE versions (for reference)
# ============================================================

from functools import wraps

def rate_limit(max_attempts: int, window_seconds: int):
    """CORRECT: Decorator-based rate limiting."""
    store: dict = {}
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = request.remote_addr
            now = time.time()
            attempts = [t for t in store.get(key, []) if now - t < window_seconds]
            if len(attempts) >= max_attempts:
                return jsonify({"error": "Too many attempts"}), 429
            attempts.append(now)
            store[key] = attempts
            return fn(*args, **kwargs)
        return wrapper
    return decorator


import uuid

def generate_secure_reset_token(email: str) -> str:
    """CORRECT: Cryptographically random token with 1-hour expiry."""
    token = str(uuid.uuid4())
    expiry = time.time() + 3600   # 1 hour
    store_reset_token(email, token, expiry)
    return token


# --- Stubs so the file is importable ---
def authenticate(u, p): return None
def generate_token(u): return "tok"
def store_reset_pin(e, p): pass
def send_email(e, m): pass
def get_stored_pin(e): return None
def update_password(e, p): pass
def get_item_price(i): return 10.0
def charge_account(u, a): pass
def credit_account(u, a): pass
def store_reset_token(e, t, x): pass
