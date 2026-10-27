from flask import Flask, request, jsonify, session, make_response
import sqlite3
import hashlib
import time

app = Flask(__name__)
app.secret_key = "fintech_secret"

def get_db():
    return sqlite3.connect("fintech.db")


@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    ).fetchone()
    if user:
        session_id = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
        db.execute(
            "INSERT INTO sessions (session_id, user_id) VALUES (?, ?)",
            (session_id, user[0])
        )
        db.commit()
        resp = make_response(jsonify({"status": "ok"}))
        resp.set_cookie("session_id", session_id)
        return resp
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/profile")
def profile():
    session_id = request.cookies.get("session_id")
    db = get_db()
    record = db.execute(
        "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()
    if not record:
        return jsonify({"error": "unauthorized"}), 401
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (record[1],)
    ).fetchone()
    return jsonify(user)


@app.route("/api/admin/impersonate", methods=["POST"])
def impersonate():
    target_user_id = request.json.get("user_id")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (target_user_id,)
    ).fetchone()
    session["user_id"] = target_user_id
    session["username"] = user[1]
    return jsonify({"status": "ok"})


@app.route("/api/session/extend", methods=["POST"])
def extend_session():
    session_id = request.json.get("session_id")
    db = get_db()
    db.execute(
        "UPDATE sessions SET expires_at = expires_at + 86400 WHERE session_id = ?",
        (session_id,)
    )
    db.commit()
    return jsonify({"status": "extended"})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok"})


@app.route("/api/token/refresh", methods=["POST"])
def refresh_token():
    old_token = request.json.get("token")
    db = get_db()
    record = db.execute(
        "SELECT * FROM sessions WHERE session_id = ?", (old_token,)
    ).fetchone()
    new_token = hashlib.md5(f"{old_token}{time.time()}".encode()).hexdigest()
    db.execute(
        "UPDATE sessions SET session_id = ? WHERE session_id = ?",
        (new_token, old_token)
    )
    db.commit()
    return jsonify({"token": new_token})