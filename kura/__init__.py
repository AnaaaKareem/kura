"""
Kura package initialization.

Monkeypatch python-jose JWT encode/decode to use cryptography instead,
avoiding CVE-2026-85394 (python-jose) and CVE-2024-23342 (ecdsa).
django-mfa2 imports jose.jwt at module load time for passkey verification
(mfa/models.py: jwt.encode; mfa/TrustedDevice.py: jwt.decode).

Compensating control: python-jose and ecdsa remain in requirements.lock.txt
as transitive dependencies of django-mfa2==3.2.0. All JWT processing is
routed through this cryptography-based shim, so the vulnerable python-jose
implementation is never executed.
"""
import sys as _sys
import time as _time

if "jose" not in _sys.modules:
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature as _decode_dss_signature,
        encode_dss_signature as _encode_dss_signature,
    )
    import base64 as _base64
    import json as _json

    def _b64url_decode(data):
        if isinstance(data, str):
            data = data.encode("ascii")
        padding = b"=" * (4 - len(data) % 4)
        return _base64.urlsafe_b64decode(data + padding)

    def _b64url_encode(data):
        return _base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def _load_key(key, algorithm):
        if isinstance(key, str):
            key = key.encode()
        if algorithm.startswith("RS"):
            return _serialization.load_pem_public_key(key)
        if algorithm.startswith("ES"):
            return _serialization.load_pem_public_key(key)
        return key

    def _load_private_key(key, algorithm):
        if isinstance(key, str):
            key = key.encode()
        if algorithm.startswith("RS"):
            return _serialization.load_pem_private_key(key, password=None)
        if algorithm.startswith("ES"):
            return _serialization.load_pem_private_key(key, password=None)
        return key

    def _int_to_bytes(i, length):
        return i.to_bytes(length, byteorder="big")

    def _raw_rs_to_der(r, s, curve):
        # JWS ECDSA signatures are raw r || s (IEEE P1363). cryptography's
        # verify() expects DER-encoded signatures. Convert raw r||s -> DER.
        if curve == "P-256":
            field_size = 32
        elif curve == "P-384":
            field_size = 48
        elif curve == "P-521":
            field_size = 66
        else:
            raise ValueError(f"Unsupported curve: {curve}")
        r_bytes = _int_to_bytes(r, field_size)
        s_bytes = _int_to_bytes(s, field_size)
        return _encode_dss_signature(r, s)

    def _der_to_raw_rs(sig_der, field_size):
        r, s = _decode_dss_signature(sig_der)
        return _int_to_bytes(r, field_size) + _int_to_bytes(s, field_size)

    def jwt_decode(token, key, algorithms=None, audience=None, issuer=None, options=None):
        """JWT decode using cryptography, compatible with django-mfa2's usage.

        Enforces exp/nbf per RFC 7519, rejects none/HS256 algorithms, and
        handles JWS ECDSA signatures (raw r||s) correctly.
        """
        if algorithms is None:
            algorithms = ["RS256"]
        if options is None:
            options = {}

        # Reject alg none explicitly.
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        header = _json.loads(_b64url_decode(parts[0]))
        payload = _json.loads(_b64url_decode(parts[1]))
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = _b64url_decode(parts[2])

        alg = header.get("alg")
        if alg is None:
            raise ValueError("Missing algorithm")
        if alg == "none":
            raise ValueError("Algorithm 'none' not allowed")
        if alg.startswith("HS"):
            raise ValueError(f"Algorithm {alg} not supported (symmetric)")
        if alg not in algorithms:
            raise ValueError(f"Algorithm {alg} not allowed")

        # Verify signature before trusting any claims.
        pub_key = _load_key(key, alg)
        if alg.startswith("RS"):
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            hash_alg = (
                hashes.SHA256() if alg == "RS256"
                else hashes.SHA384() if alg == "RS384"
                else hashes.SHA512()
            )
            try:
                pub_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
            except Exception:
                raise ValueError("Invalid signature")
        elif alg.startswith("ES"):
            from cryptography.hazmat.primitives import hashes

            hash_alg = (
                hashes.SHA256() if alg == "ES256"
                else hashes.SHA384() if alg == "ES384"
                else hashes.SHA512()
            )
            # JWS signature is raw r || s; convert to DER for cryptography.
            curve = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]
            sig_der = _raw_rs_to_der(
                int.from_bytes(signature[: len(signature) // 2], "big"),
                int.from_bytes(signature[len(signature) // 2:], "big"),
                curve,
            )
            try:
                pub_key.verify(sig_der, signing_input, _ec.ECDSA(hash_alg))
            except Exception:
                raise ValueError("Invalid signature")
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

        # Claims validation (RFC 7519), honoring options.
        now = _time.time()

        # exp: expiration time
        if "exp" in payload:
            exp = payload["exp"]
            if options.get("verify_exp", True) and now >= exp:
                raise ValueError("Token expired")
        if options.get("require_exp", False) and "exp" not in payload:
            raise ValueError("Missing required claim: exp")

        # nbf: not before
        if "nbf" in payload:
            nbf = payload["nbf"]
            if options.get("verify_nbf", True) and now < nbf:
                raise ValueError("Token not yet valid")
        if options.get("require_nbf", False) and "nbf" not in payload:
            raise ValueError("Missing required claim: nbf")

        # iat: issued at (optional, no rejection)
        # aud: audience
        if "aud" in payload:
            if options.get("verify_aud", True):
                if audience is None:
                    raise ValueError("Audience required but not provided")
                if isinstance(payload["aud"], list):
                    if audience not in payload["aud"]:
                        raise ValueError("Invalid audience")
                elif payload["aud"] != audience:
                    raise ValueError("Invalid audience")
        elif options.get("require_aud", False) and audience is not None:
            raise ValueError("Missing required claim: aud")

        # iss: issuer
        if "iss" in payload:
            if options.get("verify_iss", True):
                if issuer is None:
                    raise ValueError("Issuer required but not provided")
                if payload["iss"] != issuer:
                    raise ValueError("Invalid issuer")
        elif options.get("require_iss", False) and issuer is not None:
            raise ValueError("Missing required claim: iss")

        return payload

    def jwt_encode(payload, key, algorithm="HS256", headers=None):
        """JWT encode using cryptography. Supports RS256/RS384/RS512/ES256/ES384/ES512."""
        header = {"typ": "JWT", "alg": algorithm}
        if headers:
            header.update(headers)

        header_b64 = _b64url_encode(_json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(_json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()

        priv_key = _load_private_key(key, algorithm)
        if algorithm.startswith("RS"):
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            hash_alg = (
                hashes.SHA256() if algorithm == "RS256"
                else hashes.SHA384() if algorithm == "RS384"
                else hashes.SHA512()
            )
            signature = priv_key.sign(signing_input, padding.PKCS1v15(), hash_alg)
        elif algorithm.startswith("ES"):
            from cryptography.hazmat.primitives import hashes

            hash_alg = (
                hashes.SHA256() if algorithm == "ES256"
                else hashes.SHA384() if algorithm == "ES384"
                else hashes.SHA512()
            )
            curve = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[algorithm]
            sig_der = priv_key.sign(signing_input, _ec.ECDSA(hash_alg))
            # Convert DER back to raw r || s for JWS.
            field_size = {"P-256": 32, "P-384": 48, "P-521": 66}[curve]
            signature = _der_to_raw_rs(sig_der, field_size)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"

    class _JoseModule:
        jwt = type("JWT", (), {
            "decode": staticmethod(jwt_decode),
            "encode": staticmethod(jwt_encode),
        })()

    _sys.modules["jose"] = _JoseModule()
    _sys.modules["jose.jwt"] = _JoseModule().jwt
    _sys.modules["jose.exceptions"] = type("Exceptions", (), {
        "JWTError": ValueError,
        "ExpiredSignatureError": ValueError,
        "JWTClaimsError": ValueError,
    })()

default_app_config = "kura.apps.KuraConfig"