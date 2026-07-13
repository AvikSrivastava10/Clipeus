import jwt


def decode_no_verify(token, key):
    # ruleid: patronus-jwt-verify-disabled-python
    return jwt.decode(token, key, verify=False)


def decode_options_off(token, key):
    # ruleid: patronus-jwt-verify-disabled-python
    return jwt.decode(token, key, options={"verify_signature": False})


def decode_alg_none(token, key):
    # ruleid: patronus-jwt-algorithm-none-python
    return jwt.decode(token, key, algorithms=["none"])


def decode_safe(token, key):
    # ok: patronus-jwt-verify-disabled-python
    # ok: patronus-jwt-algorithm-none-python
    return jwt.decode(token, key, algorithms=["RS256"])
