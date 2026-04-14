"""
OWASP A10:2021 - Server-Side Request Forgery (SSRF)
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import urllib.request
import urllib.parse
import requests   # pip install requests
from flask import Flask, request, jsonify

app = Flask(__name__)


# ============================================================
# VULNERABILITY 1: Basic SSRF — user controls the URL
# ============================================================

@app.route("/api/fetch-url")
def fetch_url_vulnerable():
    """
    BUG: The server fetches an arbitrary URL provided by the user.
    Attacker payloads:
      - http://169.254.169.254/latest/meta-data/iam/security-credentials/
        → reads AWS instance metadata (cloud credentials)
      - http://localhost:6379/   → probes Redis on internal network
      - file:///etc/passwd       → reads local files (urllib allows this)
      - http://10.0.0.1/admin    → accesses internal admin panel
    """
    url = request.args.get("url")
    # BUG: No validation, no allowlist, no DNS rebinding protection
    response = urllib.request.urlopen(url)
    return response.read()


# ============================================================
# VULNERABILITY 2: SSRF via image/webhook URL parameter
# ============================================================

@app.route("/api/set-avatar", methods=["POST"])
def set_avatar_ssrf():
    """
    BUG: Avatar URL is fetched server-side without validation.
    Common attack vector: attacker provides an internal URL
    to scan internal services or steal cloud credentials.
    """
    avatar_url = request.json.get("avatar_url")
    # BUG: Fetches the URL from the server's perspective (internal network)
    resp = requests.get(avatar_url, timeout=5)
    with open("/static/avatars/user.jpg", "wb") as f:
        f.write(resp.content)
    return jsonify({"status": "avatar updated"})


@app.route("/api/webhook-test", methods=["POST"])
def test_webhook_ssrf():
    """
    BUG: Webhook URL is user-supplied and fetched server-side.
    Attacker sets webhook to http://192.168.1.1/ to probe LAN devices.
    """
    webhook_url = request.json.get("webhook_url")
    payload = {"event": "test", "timestamp": "2024-01-01"}
    # BUG: No blocklist for private IP ranges
    resp = requests.post(webhook_url, json=payload, timeout=5)
    return jsonify({"status": resp.status_code})


# ============================================================
# VULNERABILITY 3: PDF/HTML renderer SSRF
# ============================================================

@app.route("/api/generate-pdf", methods=["POST"])
def generate_pdf_ssrf():
    """
    BUG: HTML content is rendered server-side (e.g., wkhtmltopdf).
    Attacker injects an iframe or img tag pointing to internal services.

    Malicious HTML: <img src="http://169.254.169.254/latest/meta-data/">
    The renderer fetches the URL from inside the server's network.
    """
    html_content = request.json.get("html")
    # BUG: Content is not sanitized before being passed to headless browser
    import subprocess
    result = subprocess.run(
        ["wkhtmltopdf", "-", "/tmp/output.pdf"],
        input=html_content.encode(),
        capture_output=True
    )
    with open("/tmp/output.pdf", "rb") as f:
        return f.read()


# ============================================================
# VULNERABILITY 4: DNS rebinding via deferred resolution
# ============================================================

def validate_url_naive(url: str) -> bool:
    """
    BUG: Validates URL at check-time, but fetches at use-time.
    DNS rebinding attack: domain resolves to public IP at validation,
    then to 192.168.x.x at fetch time.
    """
    parsed = urllib.parse.urlparse(url)
    import socket
    ip = socket.gethostbyname(parsed.hostname)
    # Check-time: resolves to 1.2.3.4 (passes)
    if ip.startswith("192.168") or ip.startswith("10.") or ip == "127.0.0.1":
        return False
    return True   # ← passes validation


def fetch_validated_url_vulnerable(url: str):
    if validate_url_naive(url):
        # Use-time: DNS now resolves to 192.168.1.1 (bypassed!)
        return requests.get(url).text   # BUG: TOCTOU race
    raise ValueError("Blocked URL")


# ============================================================
# SECURE version (for reference)
# ============================================================

import ipaddress
import socket
import re

ALLOWED_SCHEMES = {"https"}

def is_private_ip(ip_str: str) -> bool:
    """Checks whether an IP address is in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True   # Treat unparseable IPs as unsafe


def fetch_url_secure(url: str) -> bytes:
    """
    CORRECT: Strict SSRF prevention:
    1. Allowlist of schemes (https only).
    2. Resolve DNS once and block private IPs.
    3. Connect using the resolved IP to prevent DNS rebinding.
    4. Allowlist of permitted domains.
    """
    ALLOWED_DOMAINS = {"api.trusted-partner.com", "cdn.example.com"}

    parsed = urllib.parse.urlparse(url)

    # 1. Scheme check
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme '{parsed.scheme}' not allowed")

    # 2. Domain allowlist
    hostname = parsed.hostname or ""
    if hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain '{hostname}' not in allowlist")

    # 3. Resolve and block private IPs
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

    if is_private_ip(ip):
        raise ValueError(f"Resolved IP {ip} is in a private/reserved range")

    # 4. Fetch using resolved IP to prevent DNS rebinding
    safe_url = url.replace(hostname, ip, 1)
    resp = requests.get(
        safe_url,
        headers={"Host": hostname},   # Preserve SNI
        timeout=5,
        allow_redirects=False,        # Don't follow redirects blindly
        verify=True,                  # TLS verification on
    )
    if resp.status_code in (301, 302, 307, 308):
        raise ValueError("Redirects are not followed (potential open redirect)")
    return resp.content
