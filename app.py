import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

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

from config import API_KEY
os.environ["API_KEY"]=API_KEY
# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":

        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        hash = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])

        #print(check_password_hash(hash[0]["hash"], old_password))
        if  check_password_hash(hash[0]["hash"], old_password) != True:
            return apology("Old password invalid", 403)

        if not old_password or not new_password or not confirmation:
            return render_template("changepassword.html")

        if new_password != confirmation:
            return apology("Новий пароль не збігаються")

        hash = generate_password_hash(confirmation)

        db.execute("UPDATE users SET hash=? WHERE id=?", hash, session["user_id"])

        return render_template("changepasswordsucc.html", success=1)

    else:
        return render_template("changepassword.html")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    avail = db.execute("SELECT * FROM avail WHERE user_id = :user_id ORDER BY symbol", user_id=session["user_id"])
    user = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])
    grand_total = 0.0
    t = 0

    for i in range(len(avail)):
        ava = lookup(avail[i]["symbol"])
        avail[i]["company"] = ava["name"]
        avail[i]["cur_price"] = "%.2f"%(ava["price"])
        avail[i]["cur_total"] = "%.2f"%(float(ava["price"]) * float(avail[i]["shares"]))
        avail[i]["profit"] = "%.2f"%(float(avail[i]["cur_total"]) - float(avail[i]["all_price"]))
        grand_total += avail[i]["all_price"]
        avail[i]["total"] = "%.2f"%(avail[i]["all_price"])
        t += float(avail[i]["total"])

    grand_total += float(user[0]["cash"])

    return render_template("index.html", avail=avail, cash=usd(user[0]["cash"]), grand_total=usd(grand_total), t=usd(t))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # якщо користувач натисне на кнопку в формі
    if request.method == "POST":

        # перевіряємо чи користувач надіслав символ та кількість, яка більша ніж 1
        if not request.form.get("symbol") or not request.form.get("shares") or int(request.form.get("shares")) < 1:
            return render_template("buy.html")

        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        user_id = session["user_id"]

        # здійснюємо пошук символа
        ava = lookup(symbol)

        # якщо символ не знайдено
        if not ava:
            return apology("Символ не знайдено")

        # підраховуємо ціну
        total_price = float(ava["price"]) * float(shares)

        user = db.execute("SELECT * FROM users WHERE id = :id", id=user_id)
        funds = float(user[0]["cash"])

        # перевіряємо чи достатньо у користувача грошей для здійснення покупки
        if funds < total_price:
            return apology("Недростатньо грошей. В наяності: " + str("%.2f"%funds))

        funds_left = funds - total_price

        avail_db = db.execute("SELECT * FROM avail WHERE user_id = :user_id AND symbol = :symbol",
                            user_id=user_id, symbol=symbol)

        # оновлюємо ціну, якщо у користувача є ця акція
        if len(avail_db) == 1:

            new_shares = int(avail_db[0]["shares"]) + int(shares)
            new_total = float(avail_db[0]["all_price"]) + total_price
            new_alone = "%.2f"%(new_total / float(new_shares))

            db.execute("UPDATE avail SET shares = :shares, all_price = :total, alone = :alone WHERE user_id = :user_id AND symbol = :symbol",
                        shares=new_shares, total=new_total, alone=new_alone, user_id=user_id, symbol=symbol)

        # інакше створюємо новий рядок у бд
        else:

            db.execute("INSERT INTO avail (user_id, symbol, shares, all_price, alone) VALUES (:user_id, :symbol, :shares, :all_price, :alone)",
                        user_id=user_id, symbol=symbol, shares=shares, all_price=total_price, alone=ava["price"])

        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=funds_left, id=user_id)

        db.execute("INSERT INTO history (user_id, action, symbol, shares, alone) VALUES (:user_id, :action, :symbol, :shares, :alone)",
                    user_id=user_id, action=1, symbol=symbol, shares=shares, alone=ava["price"])

        # повертаємо дані про успішне завершення до succ.html
        return render_template("succ.html", action="покупку", shares=shares,
                                name=ava["name"], total=usd(total_price), funds=usd(funds_left))

    # якщо користувач не натиснув кнопку на формі, а ввів команду в пошуковому рядку
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # витягуємо історію з бд
    avail = db.execute("SELECT * FROM history WHERE user_id = :user_id ORDER BY date DESC", user_id=session["user_id"])

    # підраховуємо ціну
    for i in range(len(avail)):
        avail[i]["all_price"] = "%.2f"%(float(avail[i]["shares"]) * float(avail[i]["alone"]))

    # передаємо дані у history.html
    return render_template("history.html", avail=avail)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # очищаємо сесію
    session.clear()

    if request.method == "POST":

        # Якщо користувач не ввів ім'я
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Якщо користувач не ввів пароль
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Перевірка чи користувач вірно ввід дані
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        # Повернути користувача на головну
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Стирання минулих даних з сесій
    session.clear()

    # Повернення на головну
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":


        # перевірка чи ввів користувач хоча б 1 символ
        if not request.form.get("symbol"):
            return apology("You must enter a symbol")

        ava = lookup(request.form.get("symbol"))

        if ava == None:
            return apology("Stock symbol not valid, please try again")

        return render_template("quoted.html", ava=ava)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Перевірка чи було залишене поле логіна пустим
        if username == '':
            return apology("You must provide a username", 403)

        # Перевірка чи було залишене поле пароля пустим
        elif password == '':
            return apology("You must provide a password", 403)

        # Перевірка чи було залишене поле підтвердження пустим
        elif confirmation == '':
            return apology("You must confirm your password", 403)

        # Перевірка чи збігаютсья паролі
        elif password != confirmation:
            return apology("Your passwords much match!", 403)

        # хешування паролю
        hash = generate_password_hash(password)


        # Добавлення користувача
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=hash)

        # Перевірка чи нікнейм унікальний
        if not result:
            return apology("username is already registered")

        session["user_id"] = result

        return redirect("/")


    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock."""
    avail = db.execute("SELECT * FROM avail WHERE user_id = :user_id", user_id=session["user_id"])

    if request.method == "POST":

        if not request.form.get("shares") or int(request.form.get("shares")) < 1:
            return render_template("sell.html", avail=avail)

        user_id = session["user_id"]
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        avail_db = db.execute("SELECT * FROM avail WHERE user_id = :user_id AND symbol = :symbol",
                            user_id=user_id, symbol=symbol)
        if avail_db:
            avail_db = avail_db[0]
        else:
            return render_template("sell.html", avail=avail)

        user = db.execute("SELECT * FROM users WHERE id = :id", id=user_id)


        if int(shares) > avail_db["shares"]:
            return apology("There are not enough shares")

        ava = lookup(symbol)

        total_price = float(ava["price"]) * float(shares)

        # Перевірка чи змінювати кількість акцій
        if int(shares) == avail_db["shares"]:
            db.execute("DELETE FROM avail WHERE user_id = :user_id AND symbol = :symbol", user_id=user_id, symbol=symbol)
        else:
            new_shares = int(avail_db["shares"]) - int(shares)
            new_total = float(new_shares) * float(avail_db["alone"])
            db.execute("UPDATE avail SET shares = :shares, all_price = :all_price WHERE user_id = :user_id AND symbol = :symbol",
                        shares=new_shares, all_price=new_total, user_id=user_id, symbol=symbol)

        funds_available = float(user[0]["cash"]) + total_price
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=funds_available, id=user_id)

        db.execute("INSERT INTO history (user_id, action, symbol, shares, alone) VALUES (:user_id, :action, :symbol, :shares, :alone)",
                    user_id=user_id, action=0, symbol=symbol, shares=shares, alone=ava["price"])

        return render_template("succ.html", action="продаж", shares=shares,
                                name=ava["name"], total=usd(total_price), funds=usd(funds_available))

    else:
        return render_template("sell.html", avail=avail)
