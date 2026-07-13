import os
from flask import Flask

app = Flask(__name__)

# ruleid: patronus-django-debug-true
DEBUG = True

# ok: patronus-django-debug-true
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


def run_debug():
    # ruleid: patronus-flask-debug-true
    app.run(host="0.0.0.0", debug=True)


def enable_debug():
    # ruleid: patronus-flask-debug-true
    app.debug = True


def run_safe():
    # ok: patronus-flask-debug-true
    app.run(host="0.0.0.0", debug=(os.environ.get("FLASK_DEBUG") == "1"))
