"""SciToken signing / verification helpers.

Ported from the Flask app's issueToken / Verify / Certs logic, kept on the
Python ``scitokens`` library.  The one change required to run on the Cloudflare
Workers (Pyodide) runtime is that verification passes the issuer public key
directly to ``SciToken.deserialize(..., public_key=...)`` instead of letting the
library fetch the issuer JWKS over the network (the runtime has no synchronous
sockets, and the library's on-disk key cache is unavailable).
"""

import base64
import binascii
import json
import time

import cryptography.utils
import scitokens
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

ISSUER = "https://demo.scitokens.org"
DEFAULT_AUDIENCE = "https://demo.scitokens.org"

KEY_IDS = {"RS256": "key-rs256", "ES256": "key-es256"}


def _load_private(pem):
    """Load a PEM private key (str or bytes) into a cryptography key object."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())


def _private_for(algorithm, rsa_pem, ec_pem):
    if algorithm == "ES256":
        return _load_private(ec_pem), KEY_IDS["ES256"]
    return _load_private(rsa_pem), KEY_IDS["RS256"]


def issue_token(payload, algorithm, rsa_pem, ec_pem):
    """Sign and serialize a SciToken.  Returns the compact token as ``str``.

    Mirrors ``issueToken`` from the original ``app.py``.
    """
    if algorithm not in KEY_IDS:
        algorithm = "RS256"
    private_key, key_id = _private_for(algorithm, rsa_pem, ec_pem)

    token = scitokens.SciToken(key=private_key, algorithm=algorithm, key_id=key_id)
    for key, value in (payload or {}).items():
        token.update_claims({key: value})

    if "ver" not in token:
        token["ver"] = "scitoken:2.0"

    # If exp was supplied honor it (no less than a 10 minute lifetime).
    lifetime = 600
    if "exp" in token and (token["exp"] - time.time()) > 600:
        lifetime = int(token["exp"]) - int(time.time())

    if token.get("ver") == "scitoken:2.0" and "aud" not in token:
        token["aud"] = DEFAULT_AUDIENCE

    serialized = token.serialize(issuer=ISSUER, lifetime=lifetime)
    if isinstance(serialized, bytes):
        serialized = serialized.decode("utf-8")
    return serialized


def _decode_segment(segment):
    """base64url-decode a JWT segment to a dict."""
    if isinstance(segment, bytes):
        segment = segment.decode("ascii")
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _public_pem_for_token(serialized, rsa_pem, ec_pem):
    """Pick the local public key matching the token header's algorithm."""
    header = _decode_segment(serialized.split(".")[0])
    algorithm = header.get("alg", "RS256")
    private_key, _ = _private_for(algorithm, rsa_pem, ec_pem)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_token(serialized, rsa_pem, ec_pem, audience=DEFAULT_AUDIENCE):
    """Deserialize/verify a token with the local public key.

    Returns the validated :class:`scitokens.SciToken`.  Raises on failure.
    """
    public_key = _public_pem_for_token(serialized, rsa_pem, ec_pem)
    return scitokens.SciToken.deserialize(serialized, public_key=public_key, audience=audience)


def enforce(serialized, audience, scope, issuers, rsa_pem, ec_pem):
    """Authorize a token against a scope, mirroring ``scitokens_protect.protect``.

    Returns ``(token, None)`` on success or ``(None, failure_message)``.
    """
    token = verify_token(serialized, rsa_pem, ec_pem, audience=audience)
    if not isinstance(issuers, list):
        issuers = [issuers]
    authz, path = scope.split(":")
    last_failure = None
    for issuer in issuers:
        enforcer = scitokens.Enforcer(issuer, audience=audience)
        if enforcer.test(token, authz, path):
            return token, None
        last_failure = enforcer.last_failure
    return None, last_failure


def _string_from_long(value):
    return base64.urlsafe_b64encode(cryptography.utils.int_to_bytes(value)).decode("ascii")


def jwks(rsa_pem, ec_pem):
    """Build the JWKS document, mirroring the ``/oauth2/certs`` route."""
    keys = []

    rsa_numbers = _load_private(rsa_pem).public_key().public_numbers()
    keys.append(
        {
            "alg": "RS256",
            "n": _string_from_long(rsa_numbers.n),
            "e": _string_from_long(rsa_numbers.e),
            "kty": "RSA",
            "use": "sig",
            "kid": "key-rs256",
        }
    )

    ec_numbers = _load_private(ec_pem).public_key().public_numbers()
    keys.append(
        {
            "alg": "ES256",
            "x": _string_from_long(ec_numbers.x),
            "y": _string_from_long(ec_numbers.y),
            "kty": "EC",
            "use": "sig",
            "kid": "key-es256",
        }
    )

    return {"keys": keys}
