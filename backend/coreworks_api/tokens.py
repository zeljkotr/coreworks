import base64
import hashlib
import hmac
import json
import time

from coreworks_api.config import settings


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_access_token(user_id: int) -> str:
    payload = _b64(json.dumps({
        "sub": str(user_id),
        "exp": int(time.time()) + 1800,
    }, separators=(",", ":")).encode())
    body = f"v1.{payload}"
    signature = hmac.new(
        settings.auth_secret.encode(), body.encode(), hashlib.sha256
    ).digest()
    return f"{body}.{_b64(signature)}"


def read_access_token(token: str) -> int | None:
    try:
        version, payload, signature = token.split(".")
        body = f"{version}.{payload}"
        expected = hmac.new(
            settings.auth_secret.encode(), body.encode(), hashlib.sha256
        ).digest()
        supplied = base64.urlsafe_b64decode(
            signature + "=" * (-len(signature) % 4)
        )
        if version != "v1" or not hmac.compare_digest(expected, supplied):
            return None
        data = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        if int(data["exp"]) <= int(time.time()):
            return None
        return int(data["sub"])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None
