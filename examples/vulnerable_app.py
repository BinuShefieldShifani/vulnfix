import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    # VULNERABLE: SQL injection via string formatting (CWE-89)
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)
    return cur.fetchone()
