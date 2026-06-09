"""Cloudflare Python Worker for the SciTokens demo.

Replaces the original Flask ``app.py``.  Serves the JSON API (token issuing,
verification, JWKS, the OAuth2 device-code flow, ``/protected`` and ``/secret``)
while the static site is served alongside via Workers Static Assets.
"""

import base64
import json
import time
import uuid
from urllib.parse import urlparse, parse_qs

from workers import WorkerEntrypoint
from js import Response, Object
from pyodide.ffi import to_js

import tokens
import badgr

ISSUER = "https://demo.scitokens.org"
# The device-code flow is a stateless demo: it always issues a token, so the
# codes are constant rather than tracked in a datastore.
DEMO_USER_CODE = "SCITOKENS"
DEMO_DEVICE_CODE = "00000000-0000-0000-0000-000000000000"


def _js(obj):
    return to_js(obj, dict_converter=Object.fromEntries)


def _response(body, status=200, content_type="text/plain", extra_headers=None):
    headers = {"content-type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    return Response.new(body, _js({"status": status, "headers": headers}))


def _json(obj, status=200):
    return _response(json.dumps(obj), status=status, content_type="application/json")


def _decode_key(value):
    """Env keys are base64-encoded PEM (as in the original app); be tolerant."""
    raw = str(value)
    try:
        decoded = base64.b64decode(raw)
        if b"BEGIN" in decoded:
            return decoded
    except Exception:
        pass
    return raw.encode("utf-8")


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        env = self.env
        path = urlparse(request.url).path
        method = request.method

        try:
            if path == "/issue":
                return await self._issue(request)
            if path == "/verify" and method == "POST":
                return await self._verify(request)
            if path == "/oauth2/certs":
                return self._certs()
            if path == "/.well-known/openid-configuration":
                return self._openid_configuration()
            if path == "/oauth2/oidc-cm" and method == "POST":
                return await self._client_register(request)
            if path == "/oauth2/device_authorization" and method == "POST":
                return self._device_authorization()
            if path == "/submit-code" and method == "POST":
                return _response("", status=302, extra_headers={"Location": "/"})
            if path == "/oauth2/token" and method == "POST":
                return await self._oauth_token(request)
            if path == "/protected":
                return self._protected(request)
            if path == "/secret":
                return await self._secret(request)
        except Exception as exc:  # surface errors as 500 instead of opaque crashes
            return _response("Internal error: %s" % exc, status=500)

        # Anything else is a static asset (or not found).
        return await env.ASSETS.fetch(request)

    # --- keys -----------------------------------------------------------------

    def _keys(self):
        return _decode_key(self.env.PRIVATE_KEY), _decode_key(self.env.EC_PRIVATE_KEY)

    # --- token issuing / verification ----------------------------------------

    async def _issue(self, request):
        algorithm = "RS256"
        payload = {}
        if request.method == "POST":
            try:
                data = json.loads(await request.text())
                payload = data.get("payload", {})
                algorithm = data.get("algorithm", "RS256")
            except (ValueError, TypeError):
                return _response("", status=400)
        rsa_pem, ec_pem = self._keys()
        return _response(tokens.issue_token(payload, algorithm, rsa_pem, ec_pem))

    async def _verify(self, request):
        try:
            data = json.loads(await request.text())
            token = data["token"]
        except (ValueError, KeyError, TypeError):
            return _json({"Success": False, "Error": "Invalid request"}, status=400)
        rsa_pem, ec_pem = self._keys()
        try:
            tokens.verify_token(token, rsa_pem, ec_pem)
            return _json({"Success": True, "Error": "Signature Verified"})
        except Exception as exc:
            return _json({"Success": False, "Error": str(exc)})

    def _certs(self):
        rsa_pem, ec_pem = self._keys()
        return _json(tokens.jwks(rsa_pem, ec_pem))

    # --- OAuth2 discovery / device-code flow ---------------------------------

    def _openid_configuration(self):
        return _json(
            {
                "issuer": ISSUER,
                "jwks_uri": ISSUER + "/oauth2/certs",
                "device_authorization_endpoint": ISSUER + "/oauth2/device_authorization",
                "registration_endpoint": ISSUER + "/oauth2/oidc-cm",
                "token_endpoint": ISSUER + "/oauth2/token",
                "response_types_supported": ["code", "id_token"],
                "response_modes_supported": ["query", "fragment", "form_post"],
                "grant_types_supported": [
                    "authorization_code",
                    "refresh_token",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
                "scopes_supported": ["read:/", "write:/"],
                "claims_supported": ["aud", "exp", "iat", "iss", "sub"],
            }
        )

    async def _client_register(self, request):
        try:
            data = json.loads(await request.text())
            scope = data.get("scope", "read:/")
        except (ValueError, TypeError):
            scope = "read:/"
        return _json(
            {
                "client_id": "test-client",
                "grant_types": ["refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
                "scope": scope,
            }
        )

    def _device_authorization(self):
        return _json(
            {
                "user_code": DEMO_USER_CODE,
                "verification_url": ISSUER + "/device-code",
                "device_code": DEMO_DEVICE_CODE,
                "expires_in": 3600,
            }
        )

    async def _oauth_token(self, request):
        form = parse_qs(await request.text())

        def field(name):
            values = form.get(name)
            return values[0] if values else None

        grant_type = field("grant_type")
        rsa_pem, ec_pem = self._keys()

        if grant_type == "refresh_token":
            current_refresh = field("refresh_token")
            refresh_obj = tokens.verify_token(current_refresh, rsa_pem, ec_pem)
            new_scope = field("scope") or refresh_obj["orig_scope"]
            new_aud = field("audience") or refresh_obj["orig_aud"]
            new_sub = refresh_obj.get("sub", str(uuid.uuid4()))
        else:
            # Stateless device-code grant: always issue.
            new_scope = "read:/protected"
            new_aud = ISSUER
            new_sub = field("device_code") or DEMO_DEVICE_CODE

        access_token = tokens.issue_token(
            {"scope": new_scope, "aud": new_aud, "sub": new_sub}, "ES256", rsa_pem, ec_pem
        )
        refresh_token = tokens.issue_token(
            {
                "scope": "refresh",
                "orig_scope": new_scope,
                "orig_aud": new_aud,
                "sub": new_sub,
                "exp": int(time.time()) + 31 * 86400,
            },
            "ES256",
            rsa_pem,
            ec_pem,
        )
        return _json(
            {
                "access_token": access_token,
                "expires_in": 20 * 60,
                "token_type": "Bearer",
                "refresh_token": refresh_token,
            }
        )

    # --- protected resources --------------------------------------------------

    def _bearer(self, request):
        header = request.headers.get("Authorization")
        if not header:
            return None, _response(
                "No Authentication Header", status=401, extra_headers={"WWW-Authenticate": "Bearer"}
            )
        parts = header.split()
        if len(parts) != 2:
            return None, _response(
                "Authentication header incorrect format",
                status=401,
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
        return parts[1], None

    def _protected(self, request):
        serialized, err = self._bearer(request)
        if err:
            return err
        rsa_pem, ec_pem = self._keys()
        try:
            token, failure = tokens.enforce(
                serialized, ISSUER, "read:/protected", [ISSUER, "https://cilogon.org"], rsa_pem, ec_pem
            )
        except Exception as exc:
            return _response(
                "Unable to deserialize: %s" % exc, status=401, extra_headers={"WWW-Authenticate": "Bearer"}
            )
        if token is None:
            return _response("Validation incorrect: %s" % failure, status=403)
        return _response("Succesfully accessed the protected resource!")

    async def _secret(self, request):
        serialized, err = self._bearer(request)
        if err:
            return err
        rsa_pem, ec_pem = self._keys()
        try:
            token, failure = tokens.enforce(serialized, ISSUER, "read:/secret", [ISSUER], rsa_pem, ec_pem)
        except Exception as exc:
            return _response(
                "Unable to deserialize: %s" % exc, status=401, extra_headers={"WWW-Authenticate": "Bearer"}
            )
        if token is None:
            return _response("Validation incorrect: %s" % failure, status=403)
        return _response(await badgr.issue_badge(token, self.env))
