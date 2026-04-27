import sqlite3
from flask import Flask, request, jsonify, session

app = Flask(__name__)

def get_db():
    return sqlite3.connect("fintech.db")

@app.route("/api/accounts/<int:account_id>/transfer", methods=["POST"])
def transfer(account_id):
    data = request.json
    to_account = data.get("to_account")
    amount = data.get("amount")

    db = get_db()

    balance = db.execute(
        "SELECT balance FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()[0]

    if balance < amount:
        return jsonify({"error": "insufficient funds"}), 400

    db.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
        (amount, account_id)
    )
    db.execute(
        "UPDATE accounts SET balance = balance + ? WHERE id = ?",
        (amount, to_account)
    )
    db.commit()

    return jsonify({"status": "ok", "new_balance": balance - amount})