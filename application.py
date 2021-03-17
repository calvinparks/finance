import os
import requests

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# used to access a variable outside of a local block
app.jinja_env.add_extension('jinja2.ext.do')
app.jinja_env.globals.update(
    usd=usd,
)


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

""" This is a reminder for me during development only of the api key value """
""" export API_KEY=pk_14b821d66e7f40d59728cf8600ac4222 """


@app.route("/")
@login_required
def index():
    """ Show portfolio of stocks """

    rows = db.execute(
        "SELECT users.username, users.cash, userstocks.symbol, userstocks.quantity FROM users JOIN userstocks on users.id = userstocks.user_id  WHERE users.id = ?", session["user_id"])
    newrows = []
    
    # prep object for realtime template use. This appends realtime prices dictionary from "lookup function" to dictionary from the database
    for i in range(len(rows)):
        newrows.append(rows[i-1].copy())
        for key, value in rows[i-1].items():
            if key == "symbol":
                print(value)
                newrows[i]["realtimedata"] = lookup(value)
                
    return render_template("index.html", userinfo=newrows)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        errorMessage = ""
        purchasequantity = request.form.get("shares")
        symbol = request.form.get("symbol")
        symbol = symbol.upper()
        if symbol == "" or purchasequantity == "" or not purchasequantity.isdigit():
            errorMessage = "YOU must input a Symbol and a positive amount of Shares"
            return apology(errorMessage, 400)
        
        stockDict = lookup(symbol)
        if stockDict != None:
            lookup(symbol)
            companyName = stockDict['name']
            latestPrice = stockDict['price']
        else:
            errorMessage = "No Information Found for: " + request.form.get("symbol")
            return apology(errorMessage, 400)
            
        if errorMessage == "":
            rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            cash = rows[0]['cash']
            if (float(latestPrice) * float(purchasequantity)) < cash:
                # check to see if the user already own any of this stock
                rows = db.execute("SELECT * FROM userstocks WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
                if len(rows) == 1:
                    newquantity = int(rows[0]['quantity']) + int(float(purchasequantity))
                    result = db.execute("UPDATE userstocks SET quantity = ? WHERE user_id = ? and symbol = ?", 
                                        newquantity, session["user_id"], symbol) 
                else:
                    result = db.execute("INSERT INTO userstocks (user_id, symbol, quantity) VALUES (?, ?, ?)",
                                        session["user_id"], symbol, purchasequantity)
                    
                result = db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                                    session["user_id"], symbol, purchasequantity, latestPrice)

                cashamount = cash - (float(latestPrice) * float(purchasequantity))
                result = db.execute("UPDATE users SET cash = ? WHERE id = ?", round(cashamount, 2), session["user_id"])
                # return render_template("/", symbol = symbol, companyName = companyName, latestPrice = latestPrice, purchasequantity = purchasequantity, errorMessage = errorMessage)
                return redirect("/")
            else:
                errorMessage = "You do not have enough cash to purchase stock. Your current cash total is:" + str(cash)
                return apology(errorMessage, 400)
                
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute(
        "SELECT symbol, shares, price, transactiondate FROM history  WHERE user_id = ?  ORDER BY transactiondate", session["user_id"])
    return render_template("history.html", userinfo=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
        errorMessage = ""
        stockDict = lookup(request.form.get("symbol"))
        if stockDict != None:
            lookup(request.form.get("symbol"))
            symbol = stockDict['symbol']
            companyName = stockDict['name']
            latestPrice = stockDict['price']
        else:
            errorMessage = "Invalid symbol " + request.form.get("symbol")
            symbol = ""
            companyName = ""
            latestPrice = ""
            return apology(errorMessage, 400)
        return render_template("quote.html", symbol=symbol, companyName=companyName, latestPrice=latestPrice, errorMessage=errorMessage)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    error_message = ""

    if request.method == "POST":
        if not request.form.get("username") or not request.form.get("username") or not request.form.get("confirmation"):
            return apology("username  or password or confirmation can not be blank", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if password != confirmation:
            return apology("Passwords Do Not Match", 400)
        if len(password) < 8:
            #error_message = "Passwords too short"
            return apology("Passwords too short", 400)
        if len(username) < 1 or len(password) < 1:
            return apology("Username and/or Password is empty", 400)

        result = db.execute("Select * From users Where username = ?", username)
        if len(result) > 0:
            return apology("user name exists", 400)
        hashed_p = generate_password_hash(password)    
        result = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed_p)

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    errorMessage = ""
    
    if request.method == "POST":
        stocksymbol = request.form.get("symbol")
        tosellamount = request.form.get("shares")
        if stocksymbol == "" or tosellamount == "" or int(tosellamount) < 1:
            errorMessage = "YOU must input a Symbol and a positive amount of Shares"
            return apology(errorMessage, 400)
        tosellamount = int(request.form.get("shares"))
        
        rows = db.execute(
            "SELECT users.username, users.cash, userstocks.symbol, userstocks.quantity FROM users JOIN userstocks on users.id = userstocks.user_id  WHERE users.id = ? AND userstocks.symbol = ?", session["user_id"], stocksymbol)
        
        # if the user has enough stocks to sell then do the following
        if tosellamount <= rows[0]['quantity']:
            postsaleremainder = rows[0]['quantity'] - tosellamount 
            stockDict = lookup(stocksymbol)
            
            # Calculate the users new cash balance after the sale of the stock
            newcashamount = (float(tosellamount) * stockDict['price']) + rows[0]['cash'] 
            result = db.execute("UPDATE userstocks SET quantity = ? WHERE user_id = ? and symbol = ?",
                                postsaleremainder, session["user_id"], stocksymbol) 
            result = db.execute("UPDATE users SET cash = ? WHERE id = ?", newcashamount, session["user_id"])
            # if the stock just sold left the user with zero of that stock left then delete this stock record 
            result = db.execute("DELETE FROM userstocks WHERE quantity = 0 and user_id = ?", session["user_id"])
            totalsold = tosellamount * -1
            result = db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                                session["user_id"], stocksymbol, totalsold, stockDict['price'])
            return redirect("/")
            rows = db.execute(
                "SELECT users.username, users.cash, userstocks.symbol, userstocks.quantity FROM users JOIN userstocks on users.id = userstocks.user_id  WHERE users.id = ?", session["user_id"])
            newrows = []
            
            # Prep Dictionary to send to index.html
            for i in range(len(rows)):
                newrows.append(rows[i-1].copy())
                for key, value in rows[i-1].items():
                    if key == "symbol":
                        print(value)
                        newrows[i]["realtimedata"] = lookup(value)

            return render_template("sell.html", userinfo=newrows)
        else:
            errorMessage = 'You do not own enough of those stocks to sell that amount.'
            return apology(errorMessage, 400)
            
    rows = db.execute(
        "SELECT users.username, users.cash, userstocks.symbol, userstocks.quantity FROM users JOIN userstocks on users.id = userstocks.user_id  WHERE users.id = ?", session["user_id"])
    return render_template("/sell.html", rows=rows, errorMessage=errorMessage)
    

@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    """SHOW curent balance of Cash"""
    errorMessage = ""
    rows = db.execute("SELECT cash FROM users WHERE users.id = ?", session["user_id"])
    balance = rows[0]['cash']
    
    if request.method == "POST":
        cashamount = request.form.get("amount")
        
        try:
            "{:.2f}".format(float(cashamount))
        except:
            errorMessage = "Please enter a proper Currency Amount"
        
        if errorMessage == "":
            balance = round(float(cashamount) + balance, 2)
            result = db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
    return render_template("cash.html", balance=balance, errorMessage=errorMessage)
    

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
