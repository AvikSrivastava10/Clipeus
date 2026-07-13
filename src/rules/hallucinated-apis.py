import jwt
import bcrypt


def check_token(token):
    # ruleid: clipeus-hallucinated-security-api-python
    return jwt.validate(token)


def check_password(pw, hashed):
    # ruleid: clipeus-hallucinated-security-api-python
    return bcrypt.verify(pw, hashed)


def check_password_real(pw, hashed):
    # ok: clipeus-hallucinated-security-api-python
    return bcrypt.checkpw(pw, hashed)
