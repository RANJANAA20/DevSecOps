"""Deliberately vulnerable lab app. For local, authorised testing only."""
import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Fake credential planted so the secret scanner has something to find.
AWS_ACCESS_KEY_ID = "AKIAZ7XQ4M2PBVN5T3KD"  # fake, random-looking
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    return conn


@app.route("/")
def index():
    return "Lab app up. Try /user?name=alice and /ping?host=127.0.0.1"


@app.route("/user")
def user():
    name = request.args.get("name", "")
    query = "SELECT id, name FROM users WHERE name = '%s'" % name  # SQL injection
    return str(db().execute(query).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -n 1 " + host, shell=True)  # command injection


if __name__ == "__main__":
    app.run(host=os.environ.get("APP_HOST", "127.0.0.1"), port=5000, debug=True)  # debug console exposed
