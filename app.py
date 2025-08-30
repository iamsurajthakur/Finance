
import pyotp
import qrcode
import io
import base64

TOTP_ENABLED = True



from flask import jsonify
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# route to the main or home page


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get total shares of each stock the user owns
    stocks = db.execute("""
        SELECT symbol, SUM(shares) AS total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, session["user_id"])

    portfolio = []
    total_value = 0

    for stock in stocks:
        symbol = stock["symbol"]
        shares = stock["total_shares"]
        quote = lookup(symbol)  # Get current stock data
        if quote:
            current_price = quote["price"]
            total = shares * current_price
            total_value += total
            portfolio.append({
                "symbol": symbol,
                "name": quote["name"],
                "shares": shares,
                "price": f"{current_price:,.2f}",
                "total": f"{total:,.2f}"
            })

    # Get user's cash balance
    user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = user[0]["cash"]

    # Calculate total assets (stocks + cash)
    grand_total = total_value + cash

    # Show the portfolio page
    return render_template("index.html", portfolio=portfolio, cash=f"{cash:,.2f}", total=f"{grand_total:,.2f}")


# route to the two step authentication setup page


@app.route("/2fa/setup")
@login_required
def setup_2fa():
    if not TOTP_ENABLED:
        return apology("2FA is not supported in this environment")

    user = db.execute("SELECT otp_secret FROM users WHERE id = ?", session["user_id"])

    if user[0]["otp_secret"]:
        return render_template("2fa.html", twofa_enabled=True)

    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret)
    uri = totp.provisioning_uri(
        name=f"user{session['user_id']}@cs50finance", issuer_name="CS50 Finance")

    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()
    qr_url = f"data:image/png;base64,{qr_b64}"

    session["temp_otp_secret"] = otp_secret
    return render_template("2fa.html", twofa_enabled=False, otp_secret=otp_secret, qr_url=qr_url)

# route to check if the user have 2fa enable or not


@app.route("/check_2fa")
def check_2fa():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Missing username"}), 400

    user = db.execute("SELECT otp_secret FROM users WHERE username = ?", username)
    if len(user) != 1:
        return jsonify({"twofa": False})

    has_2fa = user[0]["otp_secret"] is not None
    return jsonify({"twofa": has_2fa})

# route to verify if 2fa is enabled


@app.route("/2fa/verify", methods=["POST"])
@login_required
def verify_2fa():
    if not TOTP_ENABLED:
        return apology("2FA is not supported in this environment")

    otp = request.form.get("otp")
    secret = session.get("temp_otp_secret")

    if not secret:
        return apology("Session expired. Try again.")

    totp = pyotp.TOTP(secret)
    if not totp.verify(otp):
        return apology("Invalid code. Try again.")

    db.execute("UPDATE users SET otp_secret = ? WHERE id = ?", secret, session["user_id"])
    session.pop("temp_otp_secret")

    return redirect("/")

# route to disable 2fa


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    if not TOTP_ENABLED:
        return apology("2FA is not supported in this environment")

    db.execute("UPDATE users SET otp_secret = NULL WHERE id = ?", session["user_id"])
    return redirect("/2fa/setup")

# route to buy stock


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not symbol:
            return apology("Please provide a symbol for the share.", 400)

        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Invalid number of share", 400)

        stock = lookup(symbol)
        if not stock:
            return apology("Invalid stock symbol", 400)

        shares = int(shares)
        price = stock["price"]
        cost = price * shares

        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = user[0]["cash"]

        if cost > cash:
            return apology("Not enough money.", 400)

        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"])

        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, type, time) VALUES (?, ?, ?, ?, 'BUY', datetime('now'))",
            session["user_id"], symbol, shares, price
        )

        return redirect("/")

    return render_template("buy.html")

# route to see the history of the stock


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get user's transaction history
    transactions = db.execute("""
        SELECT symbol, shares, price, type, time
        FROM transactions
        WHERE user_id = ?
        ORDER BY time DESC
    """, session["user_id"])

    return render_template("history.html", transactions=transactions)

# route to login in the page


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        token = request.form.get("token")  # 2FA token (optional)

        if not username or not password:
            return apology("must provide username and password", 403)

        # Check if user exists
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        # 2FA check (if enabled)
        otp_secret = rows[0]["otp_secret"]
        if otp_secret:
            if not token:
                return apology("2FA token required", 403)
            totp = pyotp.TOTP(otp_secret)
            if not totp.verify(token):
                return apology("Invalid 2FA token", 403)

        # Successful login
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")

# route to logout of the page


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# route to see the price of the stocks


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock = lookup(symbol)

        if not symbol:
            return apology("Please provide a symbol", 400)
        if stock is None:
            return apology("Invalid symbol", 400)
        return render_template("quoted.html", stock=stock)

    return render_template("quote.html")

# route to register in the web page


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmPassword = request.form.get("confirmation")

        if not username or not password or not confirmPassword:
            return apology("All feild are required", 400)

        if password != confirmPassword:
            return apology("Password doesn't match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 0:
            return apology("Username is already taken please user another username", 400)

        hash_pw = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_pw)

        user_id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
        session["user_id"] = user_id

        return redirect("/")

    return render_template("register.html")

# route to sell the stock


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Must choose a stock", 400)

        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Invalid share count", 400)

        shares = int(shares)

        # Get how many shares user owns of this stock
        result = db.execute("""
            SELECT SUM(shares) AS total_shares
            FROM transactions
            WHERE user_id = ? AND symbol = ?
            GROUP BY symbol
        """, user_id, symbol)

        if not result or result[0]["total_shares"] < shares:
            return apology("Not enough shares", 400)

        # Get current price
        stock = lookup(symbol)
        if not stock:
            return apology("Invalid stock", 400)

        price = stock["price"]
        total = price * shares

        # Add cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total, user_id)

        # Record the sale
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price, type, time)
            VALUES (?, ?, ?, ?, 'SELL', datetime('now'))
        """, user_id, symbol, -shares, price)

        return redirect("/")

    # If GET, show stocks the user owns
    owned = db.execute("""
        SELECT symbol
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING SUM(shares) > 0
    """, user_id)

    symbols = [row["symbol"] for row in owned]

    return render_template("sell.html", stocks=symbols)

# route to change the password


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not old_password or not new_password or not confirmation:
            return apology("All fields are required.", 400)

        user = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(user[0]["hash"], old_password):
            return apology("Incorrect current password.", 400)

        if new_password != confirmation:
            return apology("New passwords do not match.", 400)

        if check_password_hash(user[0]["hash"], new_password):
            return apology("New password cannot be the same as old password.", 400)

        db.execute("UPDATE users SET hash = ? WHERE id = ?",
                   generate_password_hash(new_password), session["user_id"])
        flash("Password changed successfully!")
        return redirect("/")

    return render_template("change_password.html")

# route to delete the account


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        user_id = session["user_id"]

        # Delete user's transactions
        db.execute("DELETE FROM transactions WHERE user_id = ?", user_id)

        # Delete user
        db.execute("DELETE FROM users WHERE id = ?", user_id)

        # Log the user out
        session.clear()

        # Redirect to homepage with success message
        return redirect("/")

    return render_template("delete.html")
