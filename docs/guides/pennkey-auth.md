# Automated Canvas sign-in (PennKey + Duo)

By default Canvas MCP needs a `CANVAS_API_TOKEN` you create by hand in the
Canvas web UI. Penn accounts can't create personal access tokens, so with
`CANVAS_AUTH_MODE=pennkey` the server signs in like a browser does and calls
the Canvas API with that web session. It does this headlessly, so it runs in
a container on a server.

## How it works

1. **Sign-in:** a headless Chromium opens `https://canvas.upenn.edu/login/saml`,
   signs in to Penn WebLogin with your PennKey, and triggers **Duo Push**.
   If your account defaults to a security key, it switches to Duo Push via
   "Other options" (a server has no security key). With Duo Verified Push,
   the code to type into Duo Mobile is printed in the log, in the `--login`
   terminal, and in the notification webhook. You approve the push on your
   phone. Nothing bypasses or auto-approves Duo.
2. **Session:** after sign-in, the Canvas session cookies are saved to
   `CANVAS_AUTH_STATE_DIR/canvas_session.json` (mode 0600). Every API call
   sends them. Writes (POST/PUT/DELETE) also send the `X-CSRF-Token` header
   Canvas requires for session-authenticated requests.
3. **Staying signed in:** Canvas refreshes its session cookie as it's used,
   and the server saves those updates. A background check every
   `CANVAS_SESSION_CHECK_SEC` (default 15 min) keeps an idle session active.
4. **Re-login:** when Canvas no longer accepts the session, the server signs
   in again on its own. While Penn's SSO session and Duo's "remember this
   device" are still valid, that needs no Duo prompt. Otherwise you get a new
   push, with the code shown as above.

Safeguards:

- A wrong PennKey password stops automatic logins until restart, so the
  account can't be locked out by retries.
- Any other failed login (push denied or not answered) pauses logins for
  `PENNKEY_LOGIN_COOLDOWN_SEC` (default 15 min), so your phone isn't spammed.
- A Canvas 401 only triggers a re-login if `/users/self` also rejects the
  session. Canvas also returns 401 for ordinary permission errors.
- In HTTP mode, the server refuses to start unless `MCP_HTTP_AUTH_TOKEN` is set,
  because every caller would otherwise act as you in Canvas.

Limits:

- Unattended re-login after Penn's SSO and Duo memory expire needs your
  password available to the server (`PENNKEY_PASSWORD` or `PENNKEY_PASSWORD_FILE`).
  Without it, the server can only use the saved session until it ends.
- `execute_typescript` isn't available in this mode, because the TypeScript
  sandbox needs a bearer token.

## Docker (recommended)

```bash
mkdir -p secrets
printf '%s' 'your-pennkey'  > secrets/pennkey_username
printf '%s' 'your-password' > secrets/pennkey_password
openssl rand -hex 32        > secrets/mcp_http_auth_token
docker compose -f docker-compose.pennkey.yml up -d --build
docker compose -f docker-compose.pennkey.yml logs -f   # shows the Duo code to enter
```

The MCP endpoint is `http://127.0.0.1:8819/mcp`. Clients send
`Authorization: Bearer <contents of secrets/mcp_http_auth_token>`.
Put a TLS reverse proxy in front before exposing it beyond localhost.

The `canvas-auth` volume keeps the session and browser cookies, including
Duo's "remember this device", across restarts.

## Without Docker

```bash
pip install 'canvas-mcp[pennkey]'
playwright install chromium
export CANVAS_AUTH_MODE=pennkey PENNKEY_USERNAME=... PENNKEY_PASSWORD=...
canvas-mcp-server --login     # one-time: approve Duo, session saved
canvas-mcp-server             # reuses the saved session, re-logs in when needed
canvas-mcp-server --config    # shows auth mode and whether a session is saved
```

`--login` prompts for anything missing when run in a terminal. With
`DUO_FACTOR=passcode`, it prompts for a Duo passcode instead of sending a push.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `CANVAS_AUTH_MODE` | `token` | `pennkey` enables automated sign-in |
| `PENNKEY_USERNAME` / `_FILE` | | PennKey |
| `PENNKEY_PASSWORD` / `_FILE` | | PennKey password (use a secret file in containers) |
| `CANVAS_API_URL` | `https://canvas.upenn.edu/api/v1` | Canvas instance |
| `CANVAS_LOGIN_PATH` | `/login/saml` | SSO entry point |
| `CANVAS_AUTH_STATE_DIR` | `~/.canvas-mcp` (`/data` in Docker) | Session + browser cookie storage |
| `CANVAS_SESSION_CHECK_SEC` | `900` | Background session check interval (min 60) |
| `DUO_FACTOR` | `push` | `push` or `passcode` |
| `DUO_PASSCODE` / `_FILE` | | One-time passcode for `passcode` mode |
| `DUO_TIMEOUT_SEC` | `90` | Wait per push |
| `DUO_MAX_PUSH_ATTEMPTS` | `2` | Pushes per login before giving up |
| `DUO_TRUST_BROWSER` | `true` | Answer "Yes, this is my device" |
| `PENNKEY_HEADLESS` | `true` | `false` shows the browser window (local debugging) |
| `PENNKEY_DEBUG` | `false` | Save a screenshot (and Duo page HTML) at every Duo step |
| `PENNKEY_LOGIN_COOLDOWN_SEC` | `900` | Pause after a failed login |
| `AUTH_NOTIFY_WEBHOOK_URL` / `_FILE` | | Optional ping when a push is waiting or login fails |
| `MCP_HTTP_AUTH_TOKEN` / `_FILE` | | Bearer key required for HTTP transport |

## Troubleshooting

- After Duo, the browser answers "Yes, this is my device" and saves its
  cookies to `browser_state.json` immediately, so later logins can skip Duo
  for as long as Penn's Duo policy remembers the device.
- On a failed login, a screenshot is saved to `CANVAS_AUTH_STATE_DIR/debug/`.
  No WebLogin page HTML is saved, since it could contain credentials.
- Duo occasionally changes its page markup. If the push step stops working,
  run with `PENNKEY_HEADLESS=false PENNKEY_DEBUG=true` and check the
  screenshots. The selectors are in `src/canvas_mcp/auth/pennkey.py`.
