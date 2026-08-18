#!/usr/bin/env node
/**
 * Generate the two constant discovery endpoints as static assets:
 *
 *   public/oauth2/certs                       (JWKS)
 *   public/.well-known/openid-configuration
 *
 * Both responses are fixed for a given key pair, so there is no reason to boot
 * the Python Worker (and pay a Pyodide cold start) for every fetch of them.
 * Workers Static Assets are matched before the Worker runs, so once these files
 * exist the Worker is never invoked for those paths.
 *
 * Run via `npm run build:endpoints`; CI regenerates and fails if the committed
 * copies are stale, exactly like public/app.css.
 */

import { createPublicKey } from "node:crypto";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ISSUER = "https://demo.scitokens.org";

// Public halves of the Worker's PRIVATE_KEY / EC_PRIVATE_KEY secrets. They are
// public by definition — this is the exact material /oauth2/certs publishes.
const RSA_PUBLIC_PEM = join(ROOT, "public.pem");
const EC_PUBLIC_PEM = join(ROOT, "ec_public.pem");

/**
 * src/tokens.py builds the JWKS with `base64.urlsafe_b64encode(...)`, which
 * keeps the '=' padding that base64url normally omits. Node's JWK export drops
 * it, so pad it back and keep the published document byte-for-byte what the
 * Worker has been serving.
 */
function pad(b64url) {
  return b64url + "=".repeat((4 - (b64url.length % 4)) % 4);
}

function jwk(pemPath) {
  return createPublicKey(readFileSync(pemPath)).export({ format: "jwk" });
}

function jwks() {
  const rsa = jwk(RSA_PUBLIC_PEM);
  const ec = jwk(EC_PUBLIC_PEM);
  return {
    keys: [
      {
        alg: "RS256",
        n: pad(rsa.n),
        e: pad(rsa.e),
        kty: "RSA",
        use: "sig",
        kid: "key-rs256",
      },
      {
        alg: "ES256",
        x: pad(ec.x),
        y: pad(ec.y),
        kty: "EC",
        use: "sig",
        kid: "key-es256",
      },
    ],
  };
}

// Mirrors the document src/entry.py used to build for this route.
const openidConfiguration = {
  issuer: ISSUER,
  jwks_uri: ISSUER + "/oauth2/certs",
  device_authorization_endpoint: ISSUER + "/oauth2/device_authorization",
  registration_endpoint: ISSUER + "/oauth2/oidc-cm",
  token_endpoint: ISSUER + "/oauth2/token",
  response_types_supported: ["code", "id_token"],
  response_modes_supported: ["query", "fragment", "form_post"],
  grant_types_supported: [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:device_code",
  ],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256", "RS384", "RS512"],
  scopes_supported: ["read:/", "write:/"],
  claims_supported: ["aud", "exp", "iat", "iss", "sub"],
};

function write(relPath, doc) {
  const full = join(ROOT, "public", relPath);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, JSON.stringify(doc, null, 2) + "\n");
  console.log("wrote public/" + relPath);
}

write("oauth2/certs", jwks());
write(".well-known/openid-configuration", openidConfiguration);
