import os
import datetime
import pytz

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


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "POST":
        if not request.form.get("addmoney"):
            return apology("must provide an amount", 403)

        addcash = float(request.form.get("addmoney"))

        if addcash <= 0:
            return apology("must provide a positive number", 403)

        cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        new_cash = float(cash[0]["cash"]) + addcash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"]
        )
        return redirect("/")

    else:
        user_stocks = db.execute(
            "SELECT * FROM stocks WHERE user_id = ?", session["user_id"]
        )
        total = 0
        stocks = []
        for row in user_stocks:
            stock = {}
            thisshares = int(row["shares"])
            price = lookup(row["stock"])["price"]
            value = price * thisshares
            stock["name"] = row["stock"]
            stock["shares"] = thisshares
            stock["price"] = usd(price)
            stock["value"] = usd(value)
            total = total + value
            stocks.append(stock)

        cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        total = total + float(cash[0]["cash"])
        return render_template(
            "index.html", stocks=stocks, cash=usd(cash[0]["cash"]), total=usd(total)
        )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide a symbol", 400)

        elif not request.form.get("shares"):
            return apology("must provide number of shares", 400)

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            int(shares)
        except ValueError:
            return apology("must provide an integer number", 400)

        if int(shares) <= 0:
            return apology("must provide a positive number", 400)

        stock = lookup(symbol)

        if stock == None:
            return apology("must provide an existing stock symbol", 400)

        usermoney = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        if stock["price"] * int(shares) > usermoney[0]["cash"]:
            return apology("not enough balance", 400)

        else:
            date = datetime.datetime.now(pytz.timezone("US/Eastern"))
            new_cash = usermoney[0]["cash"] - (stock["price"] * int(shares))
            current_share = db.execute(
                "SELECT shares FROM stocks WHERE user_id = ? AND stock = ?",
                session["user_id"],
                stock["symbol"]
            )
            if len(current_share) == 0:
                db.execute(
                    "INSERT INTO stocks (user_id, stock, shares) VALUES (?, ?, ?)",
                    session["user_id"],
                    stock["symbol"],
                    shares
                )
            else:
                db.execute(
                    "UPDATE stocks SET shares = ? WHERE user_id = ? AND stock = ?",
                    int(current_share[0]["shares"]) + int(shares),
                    session["user_id"],
                    stock["symbol"]
                )

            db.execute(
                "INSERT INTO transactions (user_id,stock,shares,price,time,type, cash_before, cash_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"],
                stock["symbol"],
                int(shares),
                stock["price"],
                int(date.timestamp()),
                "buy",
                usermoney[0]["cash"],
                new_cash
            )
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"]
            )

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?", session["user_id"]
    )
    for row in transactions:
        date = datetime.datetime.fromtimestamp(row["time"])
        row["time"] = date
        row["type"] = row["type"].capitalize()
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide a valid symbol", 400)

        symbol = request.form.get("symbol")
        stock = lookup(symbol)

        if stock == None:
            return apology("must provide a valid symbol", 400)

        return render_template(
            "quoted.html",
            name=stock["name"],
            price=usd(stock["price"]),
            symbol=stock["symbol"]
        )
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure username is unique
        elif (
            len(
                db.execute(
                    "SELECT * FROM users WHERE username = ?",
                      request.form.get("username")
                )
            )
            != 0
        ):
            return apology("must provide unique username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password was submitted the second time
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password must match confirmation", 400)

        # Add user to database
        username = request.form.get("username")
        passhash = generate_password_hash(
            request.form.get("password"), method="pbkdf2", salt_length=16
        )
        db.execute(
            "INSERT INTO users (username,hash) VALUES (?, ?)", username, passhash
        )

        # Redirect user to login page
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_stocks = db.execute(
        "SELECT * FROM stocks WHERE user_id = ?", session["user_id"]
    )
    stocks = []
    for row in user_stocks:
        stocks.append(row["stock"])

    if request.method == "POST":
        if not request.form.get("shares"):
            return apology("must provide number of shares", 400)

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if symbol not in stocks:
            return apology("select available stock", 400)

        try:
            int(shares)
        except ValueError:
            return apology("must provide an integer number", 400)

        if int(shares) <= 0:
            return apology("must provide a positive number", 400)

        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        usershares = db.execute(
            "SELECT * FROM stocks WHERE user_id = ? AND stock = ?",
            session["user_id"],
            symbol
        )

        if int(shares) > int(usershares[0]["shares"]):
            return apology("not enough shares to sell", 400)

        else:
            stock = lookup(symbol)
            date = datetime.datetime.now(pytz.timezone("US/Eastern"))
            new_cash = user[0]["cash"] + (stock["price"] * int(shares))
            if int(usershares[0]["shares"]) == int(shares):
                db.execute("DELETE FROM stocks WHERE stock = ?", stock["symbol"])
            else:
                db.execute(
                    "UPDATE stocks SET shares = ? WHERE user_id = ? AND stock = ?",
                    int(usershares[0]["shares"]) - int(shares),
                    session["user_id"],
                    stock["symbol"]
                )

            db.execute(
                "INSERT INTO transactions (user_id,stock,shares,price,time,type, cash_before, cash_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"],
                stock["symbol"],
                int(shares),
                stock["price"],
                int(date.timestamp()),
                "sell",
                user[0]["cash"],
                new_cash
            )
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"]
            )

        return redirect("/")
    else:
        return render_template("sell.html", stocks=stocks)
