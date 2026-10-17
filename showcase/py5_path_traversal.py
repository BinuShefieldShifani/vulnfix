from flask import Flask, request, send_file
import os

app = Flask(__name__)
BASE = "/srv/files"

def log_access(path):
    print("access:", path)

@app.route("/download")
def download():
    fname = request.args.get("file", "")
    log_access(fname)
    # VULNERABLE (line 14): path traversal
    return send_file(os.path.join(BASE, fname))

@app.route("/list")
def listing():
    return str(os.listdir(BASE))
