# Automated Canvas token retrieval (PennKey + Duo)

By default Canvas MCP needs a `CANVAS_API_TOKEN` you create by hand in the
Canvas web UI. With `CANVAS_AUTH_MODE=pennkey`, the server gets and maintains
that token itself, which makes it usable in a container on a server.

## How it works

1. **First start:** a headless Chromium opens `https://canvas.upenn.edu/login/saml`,
   signs in to Penn WebLogin with your PennKey, and triggers **Duo Push**.
   If your account defaults to a security key, it switches to Duo Push via
   "Other options" (a server has no security key). With Duo Verified Push,
   the code to type into Duo Mobile is printed in the log, in the `--login`
   terminal, and in the notification webhook. You approve the push on your
   phone. Nothing bypasses or auto-approves Duo.
2. With the resulting Canvas session, the server creates a personal access
   token (`POST /api/v1/users/self/tokens`, default 90-day expiry) and saves it
   to `CANVAS_AUTH_STATE_DIR/canvas_token.json` (mode 0600).
3. **Refresh:** when the token is within `CANVAS_TOKEN_REFRESH_MARGIN_HOURS` of
   expiring, the server rotates it via Canvas' regenerate API using the token
   itself, so **no Duo prompt** is needed. A background thread checks hourly,
   so an idle server still rotates on time.
4. A full PennKey + Duo login only happens again if there's no usable token
   (revoked, deleted, or expired while the server was down).

Safeguards:

- A wrong PennKey password stops automatic logins until restart, so the
  account can't be locked out by retries.
- Any other failed login (push denied or not answered) pauses logins for
  `PENNKEY_LOGIN_COOLDOWN_SEC` (default 15 min), so your phone isn't spammed.
- A Canvas 401 only triggers a new token if `/users/self` also rejects the
  token. Canvas also returns 401 for ordinary permission errors.
- In HTTP mode, the server refuses to start unless `MCP_HTTP_AUTH_TOKEN` is set,
  because every caller would otherwise act as you in Canvas.

## Docker (recommended)

```bash
mkdir -p secrets
printf '%s' 'your-pennkey'  > secrets/pennkey_username
printf '%s' 'your-password' > secrets/pennkey_password
openssl rand -hex 32        > secrets/mcp_http_auth_token
docker compose -f docker-compose.pennkey.yml up -d --build
docker compose -f docker-compose.pennkey.yml logs -f   # approve the Duo Push
```

The MCP endpoint is `http://127.0.0.1:8819/mcp`. Clients send
`Authorization: Bearer <contents of secrets/mcp_http_auth_token>`.
Put a TLS reverse proxy in front before exposing it beyond localhost.

The `canvas-auth` volume keeps the token and browser cookies, including Duo's
"remember this device", across restarts.

## Without Docker

```bash
pip install 'canvas-mcp[pennkey]'
playwright install chromium
export CANVAS_AUTH_MODE=pennkey PENNKEY_USERNAME=... PENNKEY_PASSWORD=...
canvas-mcp-server --login     # one-time: approve Duo, token saved
canvas-mcp-server             # reuses and rotates the saved token
canvas-mcp-server --config    # shows auth mode and token expiry
```

`--login` prompts for anything missing when run in a terminal. With
`DUO_FACTOR=passcode`, it prompts for a Duo passcode instead of sending a push.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `CANVAS_AUTH_MODE` | `token` | `pennkey` enables automated login |
| `PENNKEY_USERNAME` / `_FILE` | | PennKey |
| `PENNKEY_PASSWORD` / `_FILE` | | PennKey password (use a secret file in containers) |
| `CANVAS_API_URL` | `https://canvas.upenn.edu/api/v1` | Canvas instance |
| `CANVAS_LOGIN_PATH` | `/login/saml` | SSO entry point |
| `CANVAS_AUTH_STATE_DIR` | `~/.canvas-mcp` (`/data` in Docker) | Token + cookie storage |
| `CANVAS_TOKEN_LIFETIME_DAYS` | `90` | 1 to 120 (Canvas caps student tokens at 120) |
| `CANVAS_TOKEN_REFRESH_MARGIN_HOURS` | `72` | Rotate this long before expiry |
| `CANVAS_TOKEN_REFRESH_CHECK_SEC` | `3600` | Background check interval |
| `DUO_FACTOR` | `push` | `push` or `passcode` |
| `DUO_PASSCODE` / `_FILE` | | One-time passcode for `passcode` mode |
| `DUO_TIMEOUT_SEC` | `90` | Wait per push |
| `DUO_MAX_PUSH_ATTEMPTS` | `2` | Pushes per login before giving up |
| `DUO_TRUST_BROWSER` | `true` | Answer "Yes, this is my device" |
| `PENNKEY_DEBUG` | `false` | Save a screenshot (and Duo page HTML) at every Duo step |
| `PENNKEY_LOGIN_COOLDOWN_SEC` | `900` | Pause after a failed login |
| `AUTH_NOTIFY_WEBHOOK_URL` / `_FILE` | | Optional ping when a push is waiting or login fails |
| `MCP_HTTP_AUTH_TOKEN` / `_FILE` | | Bearer key required for HTTP transport |

## Troubleshooting

- After Duo, the browser answers "Yes, this is my device" and saves its
  cookies to `browser_state.json` immediately, so later logins can skip Duo
  for as long as Penn's Duo policy remembers the device.
- On a failed login, a screenshot is saved to `CANVAS_AUTH_STATE_DIR/debug/`.
  No page HTML is saved, since it could contain credentials.
- "Canvas refused to create an access token" means your Canvas account isn't
  allowed to create personal access tokens. That is an institution setting.
- Duo occasionally changes its page markup. If the push step stops working,
  the screenshot shows which screen it stopped on. The selectors are in
  `src/canvas_mcp/auth/pennkey.py`.
