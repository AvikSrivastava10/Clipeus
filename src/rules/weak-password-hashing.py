import hashlib


def hash_password_md5(password):
    # ruleid: patronus-weak-password-hash-python
    return hashlib.md5(password).hexdigest()


def hash_pwd_sha256(pwd):
    # ruleid: patronus-weak-password-hash-python
    return hashlib.sha256(pwd).hexdigest()


def checksum(file_data):
    # ok: patronus-weak-password-hash-python
    return hashlib.sha256(file_data).hexdigest()
