from flask import Flask, request, jsonify, session
import sqlite3
import random

app = Flask(__name__)
app.secret_key = "fintech_secret"

def get_db():
    return sqlite3.connect("fintech.db")


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    email = request.json.get("email")
    token = str(random.randint(1000, 9999))
    db = get_db()
    db.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
    db.commit()
    return jsonify({"reset_token": token})


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    email = request.json.get("email")
    token = request.json.get("token")
    new_password = request.json.get("new_password")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE email = ? AND reset_token = ?", (email, token)
    ).fetchone()
    if user:
        db.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
        db.commit()
        return jsonify({"status": "ok"})
    return jsonify({"error": "invalid token"}), 400


@app.route("/api/change-email", methods=["POST"])
def change_email():
    user_id = request.json.get("user_id")
    new_email = request.json.get("new_email")
    db = get_db()
    db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    db.commit()
    return jsonify({"status": "ok"})


@app.route("/api/change-phone", methods=["POST"])
def change_phone():
    user_id = request.json.get("user_id")
    new_phone = request.json.get("new_phone")
    db = get_db()
    db.execute("UPDATE users SET phone = ? WHERE id = ?", (new_phone, user_id))
    db.commit()
    return jsonify({"status": "ok"})


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    user_id = request.json.get("user_id")
    otp = request.json.get("otp")
    db = get_db()
    record = db.execute(
        "SELECT * FROM otp_codes WHERE user_id = ?", (user_id,)
    ).fetchone()
    if record and record["code"] == otp:
        session["user_id"] = user_id
        session["authenticated"] = True
        return jsonify({"status": "ok"})
    return jsonify({"error": "invalid otp"}), 400


@app.route("/api/update-2fa", methods=["POST"])
def update_2fa():
    user_id = request.json.get("user_id")
    method = request.json.get("method")
    contact = request.json.get("contact")
    db = get_db()
    db.execute(
        "UPDATE users SET twofa_method = ?, twofa_contact = ? WHERE id = ?",
        (method, contact, user_id)
    )
    db.commit()
    return jsonify({"status": "ok"})