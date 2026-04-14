"""
OWASP A09:2021 - Security Logging and Monitoring Failures
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import logging
import sqlite3
from flask import Flask, request, jsonify, session

app = Flask(__name__)

# ============================================================
# VULNERABILITY 1: No logging of security events
# ============================================================

@app.route("/login", methods=["POST"])
def login_no_logging():
    """
    BUG: Failed and successful logins are never logged.
    An attacker conducting a brute-force attack leaves no trace.
    Incident responders have nothing to investigate.
    """
    username = request.json.get("username")
    password = request.json.get("password")
    user = authenticate(username, password)
    if user:
        # BUG: No log entry for successful login
        session["user_id"] = user["id"]
        return jsonify({"status": "ok"})
    # BUG: No log entry for failed login — brute force is invisible
    return jsonify({"error": "Invalid"}), 401


# ============================================================
# VULNERABILITY 2: Logging sensitive data (PII / secrets)
# ============================================================

# Basic logger — not configured for security
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route("/api/payment", methods=["POST"])
def process_payment_log_sensitive():
    """
    BUG: Full request body logged, exposing credit card numbers,
    CVVs, passwords, tokens — all persisted to log files.
    """
    data = request.json
    # BUG: Logs the ENTIRE request including card numbers and CVV
    logger.debug(f"Processing payment request: {data}")

    card_number = data.get("card_number")   # e.g., "4111111111111111"
    cvv = data.get("cvv")
    amount = data.get("amount")

    logger.info(f"Charging card {card_number} CVV {cvv} amount {amount}")  # BUG
    return jsonify({"status": "charged"})


@app.route("/api/change-password", methods=["POST"])
def change_password_logs_plaintext():
    """
    BUG: New password logged in plaintext.
    Anyone with log access can read all users' passwords.
    """
    username = request.json.get("username")
    new_password = request.json.get("new_password")
    logger.info(f"Password change for {username}: new_password={new_password}")  # BUG
    update_password(username, new_password)
    return jsonify({"status": "updated"})


# ============================================================
# VULNERABILITY 3: Log injection
# ============================================================

@app.route("/api/user-action")
def log_user_action_injectable():
    """
    BUG: User-supplied input inserted into log messages without sanitization.
    Attacker can inject newlines to forge log entries:
    action = "view\\n2024-01-01 WARN Admin logged in from 1.2.3.4"
    Makes audit logs untrustworthy.
    """
    action = request.args.get("action", "")
    user_id = request.args.get("user_id", "")
    # BUG: newline characters in 'action' create fake log lines
    logger.info(f"User {user_id} performed action: {action}")
    return jsonify({"status": "logged"})


# ============================================================
# VULNERABILITY 4: No alerting on critical security events
# ============================================================

failed_login_count = {}   # ephemeral, lost on restart

@app.route("/api/admin/delete-all-users", methods=["DELETE"])
def delete_all_users_no_alert():
    """
    BUG: Catastrophic action (deleting all users) performed with:
    - No alerting to security team
    - No anomaly detection
    - No out-of-band notification
    - Audit trail only in local logs (easily deleted by attacker)
    """
    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users")
    conn.commit()
    # BUG: No SIEM alert, no PagerDuty, no email to security team
    logger.info("All users deleted")   # Silent local log only
    return jsonify({"status": "done"})


# ============================================================
# VULNERABILITY 5: Logs not retained / rotated out too fast
# ============================================================

VULNERABLE_LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "app.log",
            "maxBytes": 1024,        # BUG: 1 KB — rotates after a few requests
            "backupCount": 1,        # BUG: only 1 backup — logs deleted after 2 KB
        }
    }
}
# An attacker who sends 2KB of traffic erases all prior log evidence.


# ============================================================
# SECURE versions (for reference)
# ============================================================

import re

def sanitize_for_log(value: str) -> str:
    """CORRECT: Remove newlines and control characters before logging."""
    return re.sub(r'[\r\n\t]', '_', str(value))[:200]


def mask_card_number(card: str) -> str:
    """CORRECT: Mask PAN for PCI-DSS compliance."""
    return f"****-****-****-{card[-4:]}" if card else "N/A"


@app.route("/api/payment-secure", methods=["POST"])
def process_payment_secure():
    """CORRECT: Log only non-sensitive metadata."""
    data = request.json
    card_masked = mask_card_number(data.get("card_number", ""))
    amount = data.get("amount")
    logger.info(
        "Payment processed",
        extra={
            "user_id": session.get("user_id"),
            "card_masked": card_masked,
            "amount": amount,
            "ip": request.remote_addr,
        }
    )
    return jsonify({"status": "charged"})


SECURE_LOGGING_CONFIG = {
    "version": 1,
    "handlers": {
        "file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": "/var/log/app/security.log",
            "when": "midnight",
            "backupCount": 365,   # 1 year retention for forensics
            "encoding": "utf-8",
        }
    }
}


# --- Stubs ---
def authenticate(u, p): return {"id": 1}
def update_password(u, p): pass
