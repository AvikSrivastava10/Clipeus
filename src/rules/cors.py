from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# ruleid: patronus-cors-wildcard-origin-python
CORS(app, origins="*")

# ruleid: patronus-cors-wildcard-origin-python
CORS(app)


def add_header(resp):
    # ruleid: patronus-cors-wildcard-origin-python
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


# ok: patronus-cors-wildcard-origin-python
CORS(app, origins=["https://app.example.com"])


def safe_header(resp):
    # ok: patronus-cors-wildcard-origin-python
    resp.headers["Access-Control-Allow-Origin"] = "https://app.example.com"
    return resp
