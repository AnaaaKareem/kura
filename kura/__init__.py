"""
Kura package initialization.

Monkeypatch python-jose JWT decode to use cryptography instead,
avoiding CVE-2026-85394 (python-jose) and CVE-2024-23342 (ecdsa).
django-mfa2 imports jose.jwt at runtime for passkey verification.
"""
import sys as _sys

if "jose" not in _sys.modules:
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    import base64 as _base64
    import json as _json

    def _b64url_decode(data):
        padding = "=" * (4 - len(data) % 4)
        return _base64.urlsafe_b64decode(data + padding)

    def _b64url_encode(data):
        return _base64.urlsafe_b64encode(data).decode().rstrip("=")

    def _load_key(key, algorithm):
        if isinstance(key, str):
            key = key.encode()
        if algorithm.startswith("RS"):
            return _serialization.load_pem_public_key(key)
        if algorithm.startswith("ES"):
            return _serialization.load_pem_public_key(key)
        return key

    def jwt_decode(token, key, algorithms=None, audience=None, issuer=None, options=None):
        """Minimal JWT decode using cryptography, compatible with django-mfa2's usage."""
        if algorithms is None:
            algorithms = ["RS256"]
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        header = _json.loads(_b64url_decode(parts[0]))
        payload = _json.loads(_b64url_decode(parts[1]))
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = _b64url_decode(parts[2])

        alg = header.get("alg", "RS256")
        if alg not in algorithms:
            raise ValueError(f"Algorithm {alg} not allowed")

        pub_key = _load_key(key, alg)
        if alg.startswith("RS"):
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            hash_alg = hashes.SHA256() if alg == "RS256" else hashes.SHA384() if alg == "RS384" else hashes.SHA512()
            pub_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
        elif alg.startswith("ES"):
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            hash_alg = hashes.SHA256() if alg == "ES256" else hashes.SHA384() if alg == "ES384" else hashes.SHA512()
            r, s = decode_dss_signature(signature)
            pub_key.verify(signature, signing_input, _ec.ECDSA(hash_alg))
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

        if audience and payload.get("aud") != audience:
            raise ValueError("Invalid audience")
        if issuer and payload.get("iss") != issuer:
            raise ValueError("Invalid issuer")
        return payload

    class _JoseModule:
        jwt = type("JWT", (), {"decode": staticmethod(jwt_decode)})()

    _sys.modules["jose"] = _JoseModule()
    _sys.modules["jose.jwt"] = _JoseModule().jwt
    _sys.modules["jose.exceptions"] = type("Exceptions", (), {
        "JWTError": ValueError,
        "ExpiredSignatureError": ValueError,
        "JWTClaimsError": ValueError,
    })()

default_app_config = "kura.apps.KuraConfig"