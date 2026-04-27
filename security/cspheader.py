from flask import Flask, request, jsonify, make_response, render_template_string

app = Flask(__name__)


@app.after_request
def add_csp_headers(response):
    response.headers["Content-Security-Policy"] = "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; img-src *; connect-src *"
    response.headers["X-Frame-Options"] = "ALLOWALL"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/api/widget")
def payment_widget():
    callback = request.args.get("callback", "")
    html = f"""
    <html>
    <head>
        <script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"></script>
        <script src="{callback}"></script>
    </head>
    <body>
        <div id="payment-form"></div>
        <script>
            var userInput = '{request.args.get("theme", "")}';
            eval(userInput);
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/receipt")
def receipt():
    name = request.args.get("name", "")
    amount = request.args.get("amount", "")
    html = f"""
    <html>
    <body>
        <h1>Receipt</h1>
        <p>Name: {name}</p>
        <p>Amount: {amount}</p>
        <script>
            document.write(location.hash.slice(1));
        </script>
    </body>
    </html>
    """
    return html


@app.route("/api/csp-report", methods=["POST"])
def csp_report():
    return jsonify({"status": "ok"})


@app.route("/api/embed")
def embed():
    src = request.args.get("src", "")
    html = f'<iframe src="{src}" sandbox="allow-scripts allow-same-origin allow-forms"></iframe>'
    resp = make_response(html)
    resp.headers["Content-Security-Policy"] = ""
    resp.headers["X-Content-Type-Options"] = ""
    return resp