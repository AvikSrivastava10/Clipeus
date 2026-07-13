import os
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args["cmd"]
    os.system(cmd)  # tainted variable -> command sink
    return "ok"


@app.route("/direct")
def direct():
    os.system(request.args["x"])  # source flows directly into sink
    return "ok"


@app.route("/safe")
def safe():
    cmd = shlex.quote(request.args["cmd"])
    os.system(cmd)  # sanitized -> not flagged
    return "ok"
