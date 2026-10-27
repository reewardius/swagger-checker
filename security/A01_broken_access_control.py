"""
OWASP A01:2021 - Broken Access Control
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION
"""

from flask import Flask, request, jsonify, session
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecret"

# --- VULNERABLE: No access control check ---
@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    """
    VULNERABILITY: Any authenticated user can access ANY user's data.
    There's no check that the requesting user owns this resource (IDOR).
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # BUG: Should verify session['user_id'] == user_id
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return jsonify(user)


@app.route("/api/admin/delete_user", methods=["POST"])
def delete_user():
    """
    VULNERABILITY: No role check. Any user can call admin endpoints.
    """
    user_id = request.json.get("user_id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # BUG: Should check if session['role'] == 'admin'
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/files")
def list_files():
    """
    VULNERABILITY: Path traversal + no access control.
    User can read arbitrary files by manipulating 'path' param.
    """
    import os
    path = request.args.get("path", "/uploads")
    # BUG: Should sanitize path and restrict to allowed directories
    files = os.listdir(path)
    return jsonify(files)


# --- SECURE version (for reference) ---
def secure_get_user(user_id):
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    # Only allow users to access their own data
    if session["user_id"] != user_id and session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return jsonify(user)
