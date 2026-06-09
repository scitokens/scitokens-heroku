# SciTokens Demo

`demo.scitokens.org` — decode, verify and generate [SciTokens](https://scitokens.org/).

This is a **static frontend + a single Cloudflare Python Worker**:

- **Frontend** (`public/`): one `index.html` (precompiled TailwindCSS + CodeMirror 5 from a
  CDN) — a jwt.io-style debugger with the algorithm selector (RS256 / ES256),
  colour-coded encoded token, syntax-highlighted decoded JSON, hover tooltips that render
  epoch-timestamp claims (`exp`/`iat`/`nbf`) as locale-accurate dates, live signature
  verification, a claim-level validation panel, copy buttons, a dark/light theme toggle
  (system default + manual override), a responsive mobile nav, and the "known libraries"
  section. Served via Workers Static Assets. Tailwind is compiled to `public/app.css` from
  `styles/input.css` (`npm run build:css`) — no runtime CDN.
- **Backend** (`src/`): a Python Worker that signs/verifies tokens with the Python
  [`scitokens`](https://github.com/scitokens/scitokens) library and implements the
  OAuth2 device-code flow, `/protected`, and `/secret` (Badgr badge).

## Architecture

```
public/                  static site (served by Workers Static Assets)
  index.html             single-page debugger UI
  app.css                compiled Tailwind (built from styles/input.css)
  device-code/index.html device-code submission page
  img/                   favicon + library icons
styles/input.css         Tailwind source (@tailwind directives + custom CSS)
tailwind.config.js       Tailwind config (class dark mode, scans public/**/*.html)
src/
  entry.py               async on_fetch router (the Worker entry point)
  tokens.py              issue / verify / enforce / JWKS  (scitokens)
  badgr.py               Badgr badge issuance for /secret  (async fetch + KV)
pyproject.toml           Python deps (scitokens, PyJWT, cryptography)
wrangler.jsonc           Worker config (assets, KV, secrets)
dev_server.py            local-only dev server (no Cloudflare toolchain needed)
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET/POST | `/issue` | Sign a SciToken (`{payload, algorithm}`) |
| POST | `/verify` | Verify a token → `{Success, Error}` |
| GET | `/oauth2/certs` | JWKS (RS256 + ES256 public keys) |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| POST | `/oauth2/oidc-cm` | Client registration |
| POST | `/oauth2/device_authorization` | Device-code start (stateless) |
| POST | `/submit-code` | Device-code submission (no-op → redirect) |
| POST | `/oauth2/token` | Issue access + refresh tokens (always issues) |
| GET | `/protected` | Resource requiring `read:/protected` |
| GET | `/secret` | Issues a Badgr badge to the token's `sub` |

## Configuration

Keys are supplied as **Worker secrets** (base64-encoded PEM, same as the old app):

```sh
base64 -i private.pem    | npx wrangler secret put PRIVATE_KEY
base64 -i ec_private.pem | npx wrangler secret put EC_PRIVATE_KEY
npx wrangler secret put BADGR_REFRESH      # only for /secret
```

Create the KV namespace used to cache the Badgr access token and paste its id into
`wrangler.jsonc`:

```sh
npx wrangler kv namespace create BADGR_CACHE
```

## Develop & deploy (Cloudflare)

Uses the uv-first Python Workers workflow.

> **Node version:** use Node **20–22** (LTS). `workers-py`'s Pyodide shim passes
> `--experimental-wasm-stack-switching`, which was removed in Node 24+, so the very
> latest Node fails at venv creation. `compatibility_date` is set to `2025-11-02` in
> `wrangler.jsonc` so the Pyodide runtime provides `cryptography` (with its OpenSSL)
> as a built-in — older dates vendor a broken copy that can't find `libssl`.

```sh
uv tool install workers-py
npm install                      # installs wrangler + tailwindcss (dev dependencies)
npm run build:css                # compile public/app.css (rerun after editing markup/styles)
cp .dev.vars.example .dev.vars   # fill in base64 keys
uv run pywrangler dev            # local: http://localhost:8787
uv run pywrangler deploy
```

> **CSS build:** `public/app.css` is committed, but rebuild it with `npm run build:css`
> whenever you change Tailwind classes in `public/index.html` or edit `styles/input.css`
> (use `npm run watch:css` while developing). Tailwind only emits classes it finds while
> scanning `public/**/*.html`, including those built dynamically in the inline `<script>`.

## Continuous deployment (GitHub Actions)

Two workflows live in `.github/workflows/`:

- **`ci.yml`** (on every PR + push to `master`): `npm ci`, builds the CSS, fails if
  `public/app.css` is stale, then runs `pywrangler deploy --dry-run` to confirm the Worker
  bundles. Needs no Cloudflare credentials.
- **`deploy.yml`** (on push to `master` + manual `workflow_dispatch`): builds the CSS and
  runs `uv run pywrangler deploy`. Merging a PR to `master` ships it.

**One-time setup before the first deploy works:**

1. **Create a Cloudflare API token** (My Profile → API Tokens → *Edit Cloudflare Workers*
   template, scoped to this account/zone) and add it as a repo secret
   **`CLOUDFLARE_API_TOKEN`**. Optionally add **`CLOUDFLARE_ACCOUNT_ID`** (only needed if the
   token can see more than one account). Settings → Secrets and variables → Actions.
   `deploy.yml` uses a `production` GitHub Environment — either create that environment
   (and put the secrets there, where you can also require reviewers) or remove the
   `environment: production` line.
2. **Replace `REPLACE_WITH_KV_NAMESPACE_ID`** in `wrangler.jsonc` with the id printed by
   `npx wrangler kv namespace create BADGR_CACHE` — a real deploy fails with a placeholder id.
3. **Set the Worker secrets once** (they persist in Cloudflare, so the Action doesn't carry
   them): `PRIVATE_KEY`, `EC_PRIVATE_KEY`, and `BADGR_REFRESH` via `npx wrangler secret put …`
   (see [Configuration](#configuration)).

## Local frontend dev (no Cloudflare toolchain)

`dev_server.py` reuses the exact `src/tokens.py` logic and the local `*.pem` files, so
you can iterate on the UI without `wrangler`/Node:

```sh
uv venv && uv pip install scitokens PyJWT cryptography
python3 dev_server.py            # http://localhost:8787
```

The committed `public/app.css` is served as-is, so this needs no Node. If you change
Tailwind classes, rebuild it with `npm run build:css` (or run `npm run watch:css` alongside).

## Notes & limitations

- **Verification uses the local public key.** The `scitokens` library normally fetches
  the issuer JWKS over the network and caches it in on-disk sqlite — neither is available
  on the Workers (Pyodide) runtime. Instead the Worker reads the token header's
  `alg`/`kid` and passes the matching local public key to
  `SciToken.deserialize(..., public_key=...)`. As a result only the demo issuer
  (`https://demo.scitokens.org`) is verifiable; external issuers (e.g. `cilogon.org`) are
  not.
- **The device-code flow is stateless.** Because this is a demo whose only job is to sign
  tokens, `/oauth2/token` always issues and the codes are constant — no Redis/KV needed.
- **`cryptography`** is provided by the Pyodide runtime; `scitokens` and `PyJWT` are
  pure-Python and vendored automatically on deploy.

This project is forked from <https://jwt.io/>.
