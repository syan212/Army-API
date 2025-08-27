from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlite3 import Connection, Cursor
import bcrypt
import uuid
import datetime
import sqlite3
import threading
import requests
import time

# Initiate app with CORS
app = Flask(__name__)
CORS(app, origins=['https://army-login.onrender.com'])

# SQLite users connection
def connect_users() -> tuple[Connection, Cursor]:
    users_con = sqlite3.connect('db/users.db')
    users_con.row_factory = sqlite3.Row
    users_cur = users_con.cursor()
    return users_con, users_cur

# SQLite tokens connection
def connect_tokens() -> tuple[Connection, Cursor]:
    tokens_con = sqlite3.connect('db/tokens.db')
    tokens_con.row_factory = sqlite3.Row
    tokens_cur = tokens_con.cursor()
    return tokens_con, tokens_cur

# SQL queries
def run_query(db, query, params=()):
    with sqlite3.connect(db) as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(query, params)
        con.commit()
        return cur.fetchall()

admin_passw = b'$2b$12$63yU9pT5PqmE.kfVbhiwVuDavrEB1g.9X17uY5N4tyKSJtm3cf66W' # hello

# Create Token
def create_token(role: str) -> str:
    token_con, token_cur = connect_tokens()
    token = str(uuid.uuid4())
    with token_con as con:
        con.execute(F'''
        INSERT INTO tokens (token, expiry, role)
        VALUES
            ("{token}", "{str(datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15))}", "{role}")
        ''')
        con.commit()
    return token

# User exists function
def user_exists(username: str) -> bool:
    res = run_query('db/users.db', 'SELECT * FROM users WHERE name = ?', (username,))
    return not(res == list())

# Is String function
def isString(string: str) -> None:
    assert isinstance(string, str)

# Ping function
def ping():
    while True:
        try:
            requests.get("https://army-api.onrender.com/health")
        except Exception as e:
            print(e)
            pass
        time.sleep(600)

threading.Thread(target=ping, daemon=True).start()

# Health Endpoint
@app.route('/health', methods=['POST', 'GET'])
def health():
    return jsonify({'online': True})

# Login route
@app.route('/login', methods = ['POST'])
def login():
    # Test requests body type
    request.get_json()
    # Get requests JSON
    username: str = request.json.get('user')
    passw: str = request.json.get('password')
    # Logic
    if not (username and user_exists(username)):
        return jsonify({'IsSuccess': False, 'Error': "User doesn't exist"}), 404
    # Get user from db
    user = dict(run_query('db/users.db', 'SELECT * FROM users WHERE name = ?', (username,))[0])
    if not bcrypt.checkpw(passw.encode('utf-8'), user['hashpw'].encode()):
        return jsonify({'IsSuccess': False, 'Error': "Unauthorised"}), 403
    else:
        if user['role'] == 'admin':
            return jsonify({'IsSuccess': True, 'Message': f'User {username} authorised, type admin', 'Token': create_token('admin')})
        else:
            return jsonify({'IsSuccess': True, 'Message': f'User {username} authorised, type normal', 'Token': create_token('user')})

@app.route('/register', methods = ['POST'])
def register():
    # Test requests body type
    request.get_json()
    # Get requests JSON
    username: str = request.json.get('user')
    passw: str = request.json.get('password')
    user_class: str = request.json.get('class')
    register_passw: str = request.json.get('reg_password')
    # Logic
    if not bcrypt.checkpw(register_passw.encode(), admin_passw):
        return jsonify({'IsSuccess': False, 'Error': 'Unauthorised'}), 403
    elif user_exists(username):
        return jsonify({'IsSuccess': False, 'Error': 'User already exists'}), 400
    else:
        # Register if the logic was succesful
        users_con, _ = connect_users()
        with users_con as con:
            con.execute(f'''
            INSERT INTO users(name, hashpw, role)
            VALUES
                ("{username}", "{bcrypt.hashpw(passw.encode(), bcrypt.gensalt()).decode()}", "{user_class}")
            ''')
            con.commit()
        return jsonify({'IsSuccess': True, 'Message': f'User {username}, class {user_class}, registered'})

@app.route('/check-token', methods=['POST'])
def check_token():
    # Get requests JSON
    token: str = request.json.get('token')
    # Check if token exists
    id = run_query('db/tokens.db', 'SELECT id FROM tokens WHERE token = ?', (token,))
    if id != list():
        id = dict(id[0])['id']
        token_con, _ = connect_tokens()
        with token_con as con:
            res = con.execute('SELECT * FROM tokens WHERE id = ?', (id,))
            tokenSQL = res.fetchone()
            if datetime.datetime.fromisoformat(tokenSQL['expiry']) > datetime.datetime.now(datetime.UTC):
                con.execute('UPDATE tokens SET expiry = ? WHERE id = ?', 
                              ((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)).isoformat(), 
                                id))
                con.commit()
                return jsonify({'IsSuccess': True, 'Role': tokenSQL['role']})
            else:
                con.execute('DELETE FROM tokens WHERE id = ?', (id,))
                con.commit()
                return jsonify({'IsSuccess': False, 'Error': f'Token {tokenSQL['token']} expired'})
    return jsonify({'IsSuccess': False, 'Error': 'Token Not Recognized'}), 403