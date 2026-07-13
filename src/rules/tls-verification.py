import ssl
import requests


def fetch_insecure(url):
    # ruleid: patronus-requests-verify-false
    return requests.get(url, verify=False)


def post_insecure(url, data):
    # ruleid: patronus-requests-verify-false
    return requests.post(url, data=data, verify=False)


def unverified_ctx():
    # ruleid: patronus-ssl-unverified-context
    return ssl._create_unverified_context()


def fetch_secure(url):
    # ok: patronus-requests-verify-false
    return requests.get(url, verify=True)


def verified_ctx():
    # ok: patronus-ssl-unverified-context
    return ssl.create_default_context()
