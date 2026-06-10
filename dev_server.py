"""Local development server for the static frontend + token API.

This is a convenience for testing the frontend without the Cloudflare toolchain
(`wrangler`/`pywrangler`), which require a modern Node.js. It reuses the very
same ``src/tokens.py`` logic the Worker uses, reading the local PEM key files.

    python3 dev_server.py            # serves http://localhost:8787

The production backend is the Cloudflare Python Worker in ``src/`` — see README.
"""

import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import tokens  # noqa: E402

PUBLIC = os.path.join(os.path.dirname(__file__), "public")
ISSUER = "https://demo.scitokens.org"

RSA_PEM = open("private.pem", "rb").read()
EC_PEM = open("ec_private.pem", "rb").read()

CONTENT_TYPES = {
    ".html": "text/html", ".svg": "image/svg+xml", ".png": "image/png",
    ".css": "text/css", ".js": "application/javascript", ".json": "application/json",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, status=200, content_type="text/plain", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj), status, "application/json")

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8") if length else ""

    def _serve_static(self, path):
        if path == "/":
            path = "/index.html"
        rel = path.lstrip("/")
        full = os.path.join(PUBLIC, rel)
        if os.path.isdir(full):
            full = os.path.join(full, "index.html")
        if not os.path.isfile(full):
            # try directory index for paths like /device-code
            alt = os.path.join(PUBLIC, rel, "index.html")
            full = alt if os.path.isfile(alt) else full
        if not os.path.isfile(full):
            self._send("Not Found", 404)
            return
        ext = os.path.splitext(full)[1]
        with open(full, "rb") as fh:
            self._send(fh.read(), 200, CONTENT_TYPES.get(ext, "application/octet-stream"))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/issue":
            self._send(tokens.issue_token({}, "RS256", RSA_PEM, EC_PEM))
        elif path == "/oauth2/certs":
            self._json(tokens.jwks(RSA_PEM, EC_PEM))
        elif path == "/protected":
            self._protected("read:/protected")
        else:
            self._serve_static(path)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/issue":
            try:
                data = json.loads(self._body())
                self._send(tokens.issue_token(data.get("payload", {}), data.get("algorithm", "RS256"), RSA_PEM, EC_PEM))
            except Exception:
                self._send("", 400)
        elif path == "/verify":
            try:
                token = json.loads(self._body())["token"]
                tokens.verify_token(token, RSA_PEM, EC_PEM)
                self._json({"Success": True, "Error": "Signature Verified"})
            except Exception as exc:
                self._json({"Success": False, "Error": str(exc)})
        elif path == "/submit-code":
            self._send("", 302, headers={"Location": "/"})
        elif path == "/oauth2/device_authorization":
            self._json({"user_code": "SCITOKENS", "verification_url": ISSUER + "/device-code",
                        "device_code": "00000000-0000-0000-0000-000000000000", "expires_in": 3600})
        elif path == "/oauth2/token":
            self._token()
        else:
            self._send("Not Found", 404)

    def _token(self):
        form = parse_qs(self._body())

        def g(k):
            return form.get(k, [None])[0]

        if g("grant_type") == "refresh_token":
            refresh = tokens.verify_token(g("refresh_token"), RSA_PEM, EC_PEM)
            scope = g("scope") or refresh["orig_scope"]
            aud = g("audience") or refresh["orig_aud"]
            sub = refresh.get("sub", str(uuid.uuid4()))
        else:
            scope, aud, sub = "read:/protected", ISSUER, g("device_code") or "demo"
        access = tokens.issue_token({"scope": scope, "aud": aud, "sub": sub}, "ES256", RSA_PEM, EC_PEM)
        refresh = tokens.issue_token({"scope": "refresh", "orig_scope": scope, "orig_aud": aud,
                                      "sub": sub, "exp": int(time.time()) + 31 * 86400}, "ES256", RSA_PEM, EC_PEM)
        self._json({"access_token": access, "expires_in": 1200, "token_type": "Bearer", "refresh_token": refresh})

    def _protected(self, scope):
        auth = self.headers.get("Authorization")
        if not auth or len(auth.split()) != 2:
            self._send("No Authentication Header", 401, headers={"WWW-Authenticate": "Bearer"})
            return
        token, failure = tokens.enforce(auth.split()[1], ISSUER, scope, [ISSUER], RSA_PEM, EC_PEM)
        if token is None:
            self._send("Validation incorrect: %s" % failure, 403)
        else:
            self._send("Succesfully accessed the protected resource!")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8787))
    print("SciTokens dev server on http://localhost:%d" % port)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
