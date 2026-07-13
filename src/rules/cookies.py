from flask import Flask

app = Flask(__name__)


def set_cookies(resp):
    # ruleid: patronus-insecure-cookie-flask
    resp.set_cookie("sid", token, httponly=False)

    # ruleid: patronus-insecure-cookie-flask
    resp.set_cookie("sid", token, secure=False)

    # ok: patronus-insecure-cookie-flask
    resp.set_cookie("sid", token, httponly=True, secure=True, samesite="Strict")


# ruleid: patronus-insecure-cookie-flask
app.config['SESSION_COOKIE_HTTPONLY'] = False

# ruleid: patronus-insecure-cookie-flask
app.config['SESSION_COOKIE_SECURE'] = False

# ok: patronus-insecure-cookie-flask
app.config['SESSION_COOKIE_HTTPONLY'] = True
