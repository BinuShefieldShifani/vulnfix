from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn

def format_user(row):
    return {"id": row["id"], "name": row["name"]}

@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = get_db()
    # VULNERABLE (line 19): SQL injection via string concat
    row = conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchone()
    return jsonify(format_user(row)) if row else ("not found", 404)

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(port=5000)
