from flask import Flask, request, jsonify, session
import sqlite3

app = Flask(__name__)
app.secret_key = "f1n7ech$ecret"


def get_db():
    return sqlite3.connect("fintech.db")


@app.route("/api/accounts/<int:account_id>")
def get_account(account_id):
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()
    return jsonify(account)


@app.route("/api/accounts/<int:account_id>/transactions")
def get_transactions(account_id):
    db = get_db()
    txns = db.execute(
        "SELECT * FROM transactions WHERE account_id = ?", (account_id,)
    ).fetchall()
    return jsonify(txns)


@app.route("/api/accounts/<int:account_id>/transfer", methods=["POST"])
def transfer(account_id):
    data = request.json
    to_account = data.get("to_account")
    amount = data.get("amount")
    db = get_db()
    db.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
        (amount, account_id)
    )
    db.execute(
        "UPDATE accounts SET balance = balance + ? WHERE id = ?",
        (amount, to_account)
    )
    db.commit()
    return jsonify({"status": "ok"})


@app.route("/api/cards/<int:card_id>")
def get_card(card_id):
    db = get_db()
    card = db.execute(
        "SELECT * FROM cards WHERE id = ?", (card_id,)
    ).fetchone()
    return jsonify(card)


@app.route("/api/cards/<int:card_id>/freeze", methods=["POST"])
def freeze_card(card_id):
    db = get_db()
    db.execute("UPDATE cards SET frozen = 1 WHERE id = ?", (card_id,))
    db.commit()
    return jsonify({"status": "frozen"})


@app.route("/api/loans/<int:loan_id>")
def get_loan(loan_id):
    db = get_db()
    loan = db.execute(
        "SELECT * FROM loans WHERE id = ?", (loan_id,)
    ).fetchone()
    return jsonify(loan)


@app.route("/api/loans/<int:loan_id>/repay", methods=["POST"])
def repay_loan(loan_id):
    data = request.json
    amount = data.get("amount")
    db = get_db()
    db.execute(
        "UPDATE loans SET remaining = remaining - ? WHERE id = ?",
        (amount, loan_id)
    )
    db.commit()
    return jsonify({"status": "repaid"})


@app.route("/api/users/<int:user_id>/kyc")
def get_kyc(user_id):
    db = get_db()
    kyc = db.execute(
        "SELECT * FROM kyc WHERE user_id = ?", (user_id,)
    ).fetchone()
    return jsonify(kyc)


@app.route("/api/users/<int:user_id>/kyc", methods=["PUT"])
def update_kyc(user_id):
    data = request.json
    db = get_db()
    db.execute(
        "UPDATE kyc SET status = ?, documents = ? WHERE user_id = ?",
        (data.get("status"), data.get("documents"), user_id)
    )
    db.commit()
    return jsonify({"status": "updated"})


@app.route("/api/statements/<int:statement_id>")
def get_statement(statement_id):
    db = get_db()
    stmt = db.execute(
        "SELECT * FROM statements WHERE id = ?", (statement_id,)
    ).fetchone()
    return jsonify(stmt)


@app.route("/api/beneficiaries/<int:beneficiary_id>", methods=["DELETE"])
def delete_beneficiary(beneficiary_id):
    db = get_db()
    db.execute("DELETE FROM beneficiaries WHERE id = ?", (beneficiary_id,))
    db.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/investments/<int:portfolio_id>")
def get_portfolio(portfolio_id):
    db = get_db()
    portfolio = db.execute(
        "SELECT * FROM portfolios WHERE id = ?", (portfolio_id,)
    ).fetchone()
    return jsonify(portfolio)


@app.route("/api/investments/<int:portfolio_id>/sell", methods=["POST"])
def sell_asset(portfolio_id):
    data = request.json
    asset_id = data.get("asset_id")
    quantity = data.get("quantity")
    db = get_db()
    db.execute(
        "UPDATE holdings SET quantity = quantity - ? WHERE portfolio_id = ? AND asset_id = ?",
        (quantity, portfolio_id, asset_id)
    )
    db.commit()
    return jsonify({"status": "sold"})


if __name__ == "__main__":
    app.run(debug=True)