from __future__ import annotations

import hmac
from hashlib import sha256
from json import loads, dumps
from time import time
from base64 import b64encode as _b64encode, b64decode as _b64decode


def b64decode(data: str) -> bytes:
    data = data.encode("utf8")
    data += b"=" * (-len(data) % 4)
    for search, replace in ((b'-', b'+'), (b'_', b'/'), (b',', b'')):
        data = data.replace(search, replace)
    return _b64decode(data)


def b64encode(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf8")
    data = _b64encode(data).decode("utf8")
    for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
        data = data.replace(search, replace)
    return data


class JWT:
    @staticmethod
    def decode(token: str, secret: bytes) -> dict | None:
        try:
            header, payload, signature = token.split(".")
            header_dict = loads(b64decode(header).decode("utf8"))
            assert header_dict.get("alg") == "HS256"
            assert header_dict.get("typ") == "JWT"
            assert (exp := header_dict.get("exp", 0)) > time() or exp == 0
            signature = b64decode(signature)
        except (IndexError, AssertionError, ValueError):
            return

        sig = f"{header}.{payload}".encode("utf8")
        sig = hmac.new(secret, sig, sha256).digest()
        if sig == signature:
            payload = b64decode(payload).decode("utf8")
            return loads(payload)

    @staticmethod
    def encode(payload: dict, secret: bytes) -> str:
        header = {
            "alg": "HS256",
            "typ": "JWT",
            "exp": 0
        }
        header = b64encode(dumps(header, separators=(',', ':')))
        payload = b64encode(dumps(payload, separators=(',', ':')))

        signature = f"{header}.{payload}".encode("utf8")
        signature = hmac.new(secret, signature, sha256).digest()
        signature = b64encode(signature)

        return f"{header}.{payload}.{signature}"
