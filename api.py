import datetime
import sqlite3
import threading
import time
import uuid
from sqlite3 import Connection, Cursor
from typing import Any

import bcrypt
import flask
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

# Initiate app with CORS
app = Flask(__name__)
CORS(app, origins=["https://army-login.onrender.com"])


# SQLite users connection
def connect_users() -> tuple[Connection, Cursor]:
    users_con = sqlite3.connect("db/users.db")
    users_con.row_factory = sqlite3.Row
    users_cur = users_con.cursor()
    return users_con, users_cur


# SQLite tokens connection
def connect_tokens() -> tuple[Connection, Cursor]:
    tokens_con = sqlite3.connect("db/tokens.db")
    tokens_con.row_factory = sqlite3.Row
    tokens_cur = tokens_con.cursor()
    return tokens_con, tokens_cur


# SQL queries
def run_query(db: str, query: str, params: tuple = ()) -> list[Any]:
    with sqlite3.connect(db) as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(query, params)
        con.commit()
        return cur.fetchall()


admin_passw = b"$2b$12$63yU9pT5PqmE.kfVbhiwVuDavrEB1g.9X17uY5N4tyKSJtm3cf66W"  # hello


# Create Token
def create_token(role: str) -> str:
    token_con, _ = connect_tokens()
    token = str(uuid.uuid4())
    with token_con as con:
        con.execute(
            """
        INSERT INTO tokens (token, expiry, role)
        VALUES
            (?, ?, ?)
        """,
            (
                token,
                (
                    datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15)
                ).isoformat(),
                role,
            ),
        )
        con.commit()
    return token


# User exists function
def user_exists(username: str) -> bool:
    res: list[Any] = run_query(
        "db/users.db", "SELECT * FROM users WHERE name = ?", (username,)
    )
    return res != list()


# Token exists function
def token_exists(token: str) -> bool:
    res = run_query("db/token.db", "SELECT * FROM tokens WHERE token = ?", (token,))
    return res != list()


# Return True if any of the arguements are '' or None
def AnyEmpty(*args: str) -> bool:
    return any(arg in ("", None) for arg in args)


# isAdmin function
# Assumes token exists
def isAdmin(token: str) -> bool:
    res = run_query("db/token.db", "SELECT * FROM tokens WHERE token = ?", (token,))
    return res[0]["role"] == "admin"


# Ping function
def ping() -> None:
    while True:
        try:
            requests.get("https://army-api.onrender.com/health", timeout=10)
        except Exception as e:
            print(e)
            pass
        time.sleep(600)


threading.Thread(target=ping, daemon=True).start()


# Health Endpoint
@app.route("/health", methods=["POST", "GET"])
def health() -> flask.Response:
    return jsonify({"online": True})


# Login route
@app.route("/login", methods=["POST"])
def login() -> flask.Response | tuple[flask.Response, int]:
    # Test requests body type
    json: dict[str, str] = request.get_json()
    if json is None:
        return jsonify({"IsSuccess": False, "Error": "No JSON data sent"})
    # Get requests JSON
    username: str = json.get("user", "")
    passw: str = json.get("password", "")
    if AnyEmpty(username, passw):
        return jsonify({"IsSuccess": False, "Error": "User or Password field missing"})
    # Logic
    if not (username and user_exists(username)):
        return jsonify({"IsSuccess": False, "Error": "User doesn't exist"}), 404
    # Get user from db
    user = run_query("db/users.db", "SELECT * FROM users WHERE name = ?", (username,))[
        0
    ]
    if not bcrypt.checkpw(passw.encode("utf-8"), user["hashpw"].encode()):
        return jsonify({"IsSuccess": False, "Error": "Unauthorised"}), 403
    else:
        if user["role"] == "admin":
            return jsonify(
                {
                    "IsSuccess": True,
                    "Message": f"User {username} authorised, type admin",
                    "Token": create_token("admin"),
                }
            )
        else:
            return jsonify(
                {
                    "IsSuccess": True,
                    "Message": f"User {username} authorised, type normal",
                    "Token": create_token("user"),
                }
            )


@app.route("/register", methods=["POST"])
def register() -> flask.Response | tuple[flask.Response, int]:
    # Test requests body type
    json: dict[str, str] = request.get_json()
    if json is None:
        return jsonify({"IsSuccess": False, "Error": "No JSON data sent"})
    # Get requests JSON
    username: str = json.get("user", "")
    passw: str = json.get("password", "")
    user_class: str = json.get("class", "")
    register_passw: str = json.get("reg_password", "")
    if AnyEmpty(username, passw, user_class, register_passw):
        return jsonify({"IsSuccess": False, "Error": "One or more field(s) missing"})
    # Logic
    if not bcrypt.checkpw(register_passw.encode(), admin_passw):
        return jsonify({"IsSuccess": False, "Error": "Unauthorised"}), 403
    elif user_exists(username):
        return jsonify({"IsSuccess": False, "Error": "User already exists"}), 400
    else:
        # Register if the logic was succesful
        users_con, _ = connect_users()
        with users_con as con:
            con.execute(
                """
            INSERT INTO users(name, hashpw, role)
            VALUES
                (?, ?, ?)
            """,
                (
                    username,
                    bcrypt.hashpw(passw.encode(), bcrypt.gensalt()).decode(),
                    user_class,
                ),
            )
            con.commit()
        return jsonify(
            {
                "IsSuccess": True,
                "Message": f"User {username}, class {user_class}, registered",
            }
        )


@app.route("/check-token", methods=["POST"])
def check_token() -> flask.Response | tuple[flask.Response, int]:
    # Test requests body type
    json: dict[str, str] = request.get_json()
    if json is None:
        return jsonify({"IsSuccess": False, "Error": "No JSON data sent"})
    # Get requests JSON
    token: str = json.get("token", "")
    if AnyEmpty(token):
        return jsonify({"IsSuccess": False, "Error": "Token Field missing"})
    # Check if token exists
    if token_exists(token):
        token_con, _ = connect_tokens()
        with token_con as con:
            res = con.execute("SELECT * FROM tokens WHERE token = ?", (token,))
            tokenSQL = res.fetchone()
            if datetime.datetime.fromisoformat(
                tokenSQL["expiry"]
            ) > datetime.datetime.now(datetime.UTC):
                con.execute(
                    "UPDATE tokens SET expiry = ? WHERE token = ?",
                    (
                        (
                            datetime.datetime.now(datetime.UTC)
                            + datetime.timedelta(minutes=15)
                        ).isoformat(),
                        token,
                    ),
                )
                con.commit()
                return jsonify({"IsSuccess": True, "Role": tokenSQL["role"]})
            else:
                con.execute("DELETE FROM tokens WHERE token = ?", (token,))
                con.commit()
                return jsonify({"IsSuccess": False, "Error": f"Token {token} expired"})
    return jsonify({"IsSuccess": False, "Error": "Token Not Recognized"}), 403


# Delete Token
@app.route("/delete-token", methods=["POST"])
def delete_token() -> flask.Response | tuple[flask.Response, int]:
    # Test requests body type
    json: dict[str, str] = request.get_json()
    if json is None:
        return jsonify({"IsSuccess": False, "Error": "No JSON data sent"})
    # Get requests JSON
    token: str = json.get("token", "")
    if AnyEmpty(token):
        return jsonify({"IsSuccess": False, "Error": "Token field missing"})
    # Confirm token exists
    check_token: list[Any] = run_query(
        "db/tokens.db", "SELECT * FROM tokens WHERE token = ?", (token,)
    )
    if check_token == []:
        return jsonify({"IsSuccess": False, "Error": "Token not found"})
    # Delete token
    token_con, _ = connect_tokens()
    with token_con as con:
        con.execute(
            """
        DELETE FROM tokens WHERE token = ?
        """,
            (token,),
        )
        con.commit()
        return jsonify({"IsSuccess": True, "Message": f"Token {token} deleted"})


# Delete user
@app.route("/delete-user", methods=["POST"])
def delete_user() -> flask.Response | tuple[flask.Response, int]:
    # Test requests body type
    json: dict[str, str] = request.get_json()
    if json is None:
        return jsonify({"IsSuccess": False, "Error": "No JSON data sent"})
    # Get requests JSON
    user: str = json.get("user", "")
    if AnyEmpty(user):
        return jsonify({"IsSuccess": False, "Error": "User field missing"})
    # Confirm user exists
    check_user: list[Any] = run_query(
        "db/users.db", "SELECT * FROM users WHERE name = ?", (user,)
    )
    if check_user == []:
        return jsonify({"IsSuccess": False, "Error": "User not found"})
    # Delete user
    user_con, _ = connect_users()
    with user_con as con:
        con.execute(
            """
        DELETE FROM users WHERE name = ?
        """,
            (user,),
        )
        con.commit()
        return jsonify({"IsSuccess": True, "Message": f"User {user} deleted"})
