"""Remediated version of the lab app."""
import ipaddress
import os
import sqlite3
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)

# Secrets come from the environment (injected by the platform's secret manager).
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")


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
    rows = db().execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    try:
        host = str(ipaddress.ip_address(request.args.get("host", "127.0.0.1")))
    except ValueError:
        abort(400, "host must be an IP address")
    return subprocess.check_output(["ping", "-n", "1", host])


if __name__ == "__main__":
    app.run(host=os.environ.get("APP_HOST", "127.0.0.1"), port=5000, debug=False)
