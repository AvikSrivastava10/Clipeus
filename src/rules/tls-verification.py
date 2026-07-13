import ssl
import requests


def fetch_insecure(url):
    # ruleid: clipeus-requests-verify-false
    return requests.get(url, verify=False)


def post_insecure(url, data):
    # ruleid: clipeus-requests-verify-false
    return requests.post(url, data=data, verify=False)


def unverified_ctx():
    # ruleid: clipeus-ssl-unverified-context
    return ssl._create_unverified_context()


def fetch_secure(url):
    # ok: clipeus-requests-verify-false
    return requests.get(url, verify=True)


def verified_ctx():
    # ok: clipeus-ssl-unverified-context
    return ssl.create_default_context()
