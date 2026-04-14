from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    return sqlite3.connect("fintech.db")


@app.route("/api/accounts/search")
def search_accounts():
    query = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        "SELECT * FROM accounts WHERE owner_name LIKE '%" + query + "%'"
    ).fetchall()
    return jsonify(results)


@app.route("/api/transactions")
def get_transactions():
    account_id = request.args.get("account_id")
    order = request.args.get("order", "asc")
    db = get_db()
    results = db.execute(
        f"SELECT * FROM transactions WHERE account_id = {account_id} ORDER BY created_at {order}"
    ).fetchall()
    return jsonify(results)


@app.route("/api/users/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    ).fetchone()
    if user:
        return jsonify({"status": "ok", "user_id": user[0]})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/reports")
def get_report():
    report_type = request.args.get("type")
    start_date = request.args.get("start")
    end_date = request.args.get("end")
    db = get_db()
    results = db.execute(
        f"SELECT * FROM transactions WHERE type = '{report_type}' AND created_at BETWEEN '{start_date}' AND '{end_date}'"
    ).fetchall()
    return jsonify(results)


@app.route("/api/cards/search")
def search_cards():
    last_four = request.args.get("last_four")
    db = get_db()
    results = db.execute(
        "SELECT * FROM cards WHERE last_four = " + last_four
    ).fetchall()
    return jsonify(results)


@app.route("/api/loans/filter")
def filter_loans():
    status = request.args.get("status")
    user_id = request.args.get("user_id")
    db = get_db()
    results = db.execute(
        f"SELECT * FROM loans WHERE status = '{status}' AND user_id = '{user_id}'"
    ).fetchall()
    return jsonify(results)