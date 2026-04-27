"""
OWASP A05:2021 - Security Misconfiguration
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

from flask import Flask, jsonify, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

# ============================================================
# VULNERABILITY 1: Debug mode enabled in production
# ============================================================

# BUG: debug=True exposes an interactive debugger with code execution
# An attacker visiting /crash can run arbitrary Python in the browser
app.config["DEBUG"] = True
app.config["TESTING"] = True
app.config["PROPAGATE_EXCEPTIONS"] = True


@app.route("/crash")
def crash():
    raise Exception("Unhandled error — debugger now exposed!")


# ============================================================
# VULNERABILITY 2: Verbose error messages leak internals
# ============================================================

@app.errorhandler(500)
def internal_error_verbose(error):
    """
    BUG: Returns full stack trace and internal paths to the client.
    Leaks: file paths, library versions, DB schema, env vars.
    """
    import traceback
    return jsonify({
        "error": str(error),
        "traceback": traceback.format_exc(),       # BUG: never expose
        "python_path": __file__,                   # BUG: reveals server layout
        "environment": dict(__import__("os").environ)  # BUG: exposes secrets
    }), 500


# ============================================================
# VULNERABILITY 3: Security headers missing
# ============================================================

@app.after_request
def missing_security_headers(response):
    """
    BUG: None of the standard security headers are set.
    Missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.
    """
    # Should add but doesn't:
    # response.headers['Strict-Transport-Security'] = 'max-age=63072000'
    # response.headers['Content-Security-Policy'] = "default-src 'self'"
    # response.headers['X-Frame-Options'] = 'DENY'
    # response.headers['X-Content-Type-Options'] = 'nosniff'
    # response.headers['Referrer-Policy'] = 'no-referrer'
    return response


# ============================================================
# VULNERABILITY 4: XXE — XML External Entity Processing
# ============================================================

@app.route("/api/parse-xml", methods=["POST"])
def parse_xml_vulnerable():
    """
    BUG: Default XML parser allows external entity expansion.
    Attack payload can read /etc/passwd or perform SSRF.

    Malicious XML:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <user><name>&xxe;</name></user>
    """
    xml_data = request.data
    # BUG: ET.fromstring resolves external entities by default in some configs
    root = ET.fromstring(xml_data)
    return jsonify({"name": root.find("name").text})


# ============================================================
# VULNERABILITY 5: Directory listing / default credentials
# ============================================================

ADMIN_USERNAME = "admin"    # BUG: default credential, never changed
ADMIN_PASSWORD = "admin"    # BUG: default credential, never changed

@app.route("/admin")
def admin_panel():
    """
    BUG: Admin panel with default credentials, no lockout,
    and accessible from the public internet.
    """
    auth = request.authorization
    if auth and auth.username == ADMIN_USERNAME and auth.password == ADMIN_PASSWORD:
        return jsonify({"status": "Welcome, admin!", "users": list_all_users()})
    return jsonify({"error": "Unauthorized"}), 401


# ============================================================
# VULNERABILITY 6: CORS misconfiguration — wildcard origin
# ============================================================

@app.after_request
def cors_wildcard(response):
    """
    BUG: Allows ANY origin to make credentialed requests.
    Combined with session cookies this enables CSRF from any website.
    """
    response.headers["Access-Control-Allow-Origin"] = "*"           # BUG
    response.headers["Access-Control-Allow-Credentials"] = "true"   # BUG: contradicts *
    response.headers["Access-Control-Allow-Methods"] = "*"          # BUG
    return response


# ============================================================
# SECURE versions (for reference)
# ============================================================

def configure_secure_app(application: Flask):
    """CORRECT: Minimal, hardened Flask configuration."""
    application.config.update(
        DEBUG=False,
        TESTING=False,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    @application.after_request
    def add_security_headers(resp):
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp


def parse_xml_secure(xml_data: bytes):
    """CORRECT: Use defusedxml to block XXE attacks."""
    import defusedxml.ElementTree as SafeET
    root = SafeET.fromstring(xml_data)
    return root.find("name").text


# --- Stubs ---
def list_all_users(): return []
