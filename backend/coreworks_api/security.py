import hashlib
import hmac
import secrets


_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, _ITERATIONS
    )
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split("$")

        if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
            _, iterations, salt_hex, digest_hex = parts
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt_hex),
                int(iterations),
            )
            return hmac.compare_digest(actual.hex(), digest_hex)

        if len(parts) != 3:
            return False

        method, salt, digest_hex = parts
        expected = bytes.fromhex(digest_hex)

        if method.startswith("scrypt:"):
            _, n, r, p = method.split(":")
            actual = hashlib.scrypt(
                password.encode(), salt=salt.encode(),
                n=int(n), r=int(r), p=int(p), dklen=len(expected),
            )
        elif method.startswith("pbkdf2:"):
            components = method.split(":")
            algorithm = components[1]
            iterations = int(components[2]) if len(components) > 2 else 600_000
            actual = hashlib.pbkdf2_hmac(
                algorithm, password.encode(), salt.encode(), iterations,
                dklen=len(expected),
            )
        else:
            return False

        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, OverflowError):
        return False
