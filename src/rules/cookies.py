from flask import Flask

app = Flask(__name__)


def set_cookies(resp):
    # ruleid: clipeus-insecure-cookie-flask
    resp.set_cookie("sid", token, httponly=False)

    # ruleid: clipeus-insecure-cookie-flask
    resp.set_cookie("sid", token, secure=False)

    # ok: clipeus-insecure-cookie-flask
    resp.set_cookie("sid", token, httponly=True, secure=True, samesite="Strict")


# ruleid: clipeus-insecure-cookie-flask
app.config['SESSION_COOKIE_HTTPONLY'] = False

# ruleid: clipeus-insecure-cookie-flask
app.config['SESSION_COOKIE_SECURE'] = False

# ok: clipeus-insecure-cookie-flask
app.config['SESSION_COOKIE_HTTPONLY'] = True
