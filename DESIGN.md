# login — MCP server for human-assisted website login

Status: **design draft, no code yet.** Module: `github.com/LeafAI/login`.
Install: `go install github.com/LeafAI/login@latest` (binary `login`, `main.go` at repo root).

## 1. Goal

An AI agent calls the MCP tool `login(url)`. The server gets a human to type the
credential on a web page reached through an SSH reverse tunnel, logs in to the
target site with its real login flow, and returns the cookie/token to the agent.
The agent never sees the password. Sites are pluggable; phase 1 ships skywalking,
kibana, kubesphere, nightingale, archery, gitlab.

## 2. End-to-end flow

```
Agent ──login(url)──▶ MCP server (stdio)
  0. cache hit & still valid? ──yes──▶ return cached session
  1. resolve site driver from URL (host match / explicit `site` arg)
  2. take a GPG key from the pool (each key: <= 8 uses and <= 24 h, then retired)
  3. start a one-shot JSON API server on 127.0.0.1:<random port> (serves NO html)
  4. start SSH tunnel (provider chain, first one that yields an https URL wins)
  5. DingTalk robot ──▶ human: for the current round, a "connection string" = full submit URL
     (tunnel + per-round token + mode) + armored PUBLIC KEY, plus the address of the trusted static
     page (never served through the tunnel)
Human opens the trusted static page (hosted by us / saved locally) and PASTES the connection string
  6. page reads the mode from the pasted string, renders the matching form itself; browser
     PGP-encrypts {fields, nonce, ts, mode, round} to the pasted key; POST <submit URL>
     (the page then polls <status URL>)
  If the site needs another factor (e.g. TOTP), the driver starts a NEW round: a new token and a
  new DingTalk message, handled exactly like step 5-6 with mode=totp.
  7. server decrypts, validates nonce/ts/token, answers 200, shuts down tunnel+server
  8. site driver runs the real login flow (CSRF, 2FA, ...) with a cookie-jar client
  9. result {cookies, headers, token, expires_at} ──▶ agent
```

Steps 3–7 happen at most once per request: first valid submission wins, then the
listener closes. TTL (default 10 min) closes it too.

## 3. Repo layout

```
main.go                      # package main: flags/config, wire everything, serve MCP on stdio
internal/
  mcpserver/                 # tool registration (login, login_sessions, logout, archery_*)
  keyring/                   # GPG key pool (≤8), generate/reuse, armored export, decrypt
  api/                       # one-shot JSON API behind the tunnel: /mode, /submit, /status (no HTML)
  web/                       # static login.html + vendored openpgp.min.js (go:embed; see 4.3)
  tunnel/                    # Provider interface, built-ins, custom providers, ssh runner, fallback
  notify/                    # DingTalk robot client (HMAC-SHA256 signed webhook)
  site/                      # Driver interface + registry
    gitlab/ kibana/ kubesphere/ nightingale/ archery/ skywalking/
    generic/                 # declarative form/JSON login driven by YAML (any other site)
  session/                   # cache, singleflight per host, validity probe
  config/                    # ~/.config/login/config.yaml + env overrides
```

Dependencies: `modelcontextprotocol/go-sdk` (MCP), `ProtonMail/go-crypto/openpgp`
(pure Go, no `gpg` binary needed), `golang.org/x/net/html` (CSRF scraping),
`gopkg.in/yaml.v3`. Browser side: vendored `openpgp.js` embedded in the binary
(no CDN, works offline from the tunnel's point of view).

## 4. Key components

### 4.1 Key pool (`keyring`)
- Dir `~/.config/login/keys/` (0700), one armored private key per file plus a small metadata
  record `{created_at, uses}`; private key mode 0600, no passphrase (it only protects short-lived
  transport; see section 8).
- A key pair may be used **at most 8 times and for at most 24 h**, whichever comes first
  (`max_uses: 8`, `max_age: 24h`, configurable). `Acquire()` returns a live key with the fewest
  remaining uses and increments `uses` atomically (file lock, safe across processes), or generates a
  new one when none is live. Retired keys are deleted on the next acquire.
- Key type: Curve25519 (ed25519 + cv25519). The armored public key is ~400 bytes, practical to
  copy/paste from DingTalk (RSA keys are 2-4x longer).

### 4.2 Tunnel providers (`tunnel`)
```go
type Provider interface {
    Name() string
    Kind() Kind                       // HTTP (usable for the web page) | TCP
    Args(localPort int) []string      // ssh arguments
    ParseURL(line string) (string, bool) // extract the public https URL from ssh output
}
```
Runner: `exec.CommandContext("ssh", args...)` with
`-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ExitOnForwardFailure=yes -o BatchMode=yes`,
reads stdout+stderr, regex-matches the URL, waits ≤ 20 s. Providers tried in configured order
(default: pinggy → localhost.run → serveo → tunnl); first success wins, failures logged and skipped.

| Provider | Args |
|---|---|
| pinggy | `-R 80:localhost:P pinggy.io` (also `-p 443 -R0:localhost:P free.pinggy.io` variant) |
| localhost.run | `-R 80:localhost:P nokey@localhost.run` |
| serveo | `-R 80:localhost:P serveo.net` (optional custom subdomain) |
| tunnl.gg | `-t -R 80:localhost:P proxy.tunnl.gg` |
| ssh-j | `-R alias:22:localhost:22 ssh-j.com` — **TCP kind, see open question 2** |
| custom | from config: `command` template with `{{port}}`, `url_regex`, optional `identity_file` |

Custom example:
```yaml
tunnel:
  order: [mycorp, pinggy, serveo]
  providers:
    - name: mycorp
      command: ssh -i ~/.ssh/id_ed25519 -R 0.0.0.0:{{port}}:localhost:{{port}} jump.corp.example
      url: https://jump.corp.example:{{port}}
```
(`url` for fixed-address servers, `url_regex` for ones that print a random URL.)

### 4.3 Static page + one-shot API (`web`, `api`)
The tunnel carries **only JSON**. All JavaScript comes from a static page that does not travel
through the tunnel, so a malicious provider has no script to tamper with.

**Rounds.** Each authentication step (`login`, `totp`, ...) is an independent *round* with its own
random 128-bit token, own URL, own DingTalk message and own single accepted submission. Rounds are
equal peers; nothing in the API distinguishes "first" from "second". The mode is part of the URL
the human receives, not something the API tells the page.

Connection string (one copy-paste from DingTalk):
`login1.<base64url{ "submit": "https://x.pinggy.link/<token>/submit?mode=totp&round=2",
"status": ".../<token>/status", "site": "gitlab.corp.example", "pubkey": "-----BEGIN PGP...", "fpr": "..."}>`

Static page (`web/login.html`, single file with vendored `openpgp.js`, no external requests):
- Obtained from a trusted origin, in order of preference: (a) `login page` subcommand writes it
  to disk (embedded in the installed binary) and the user opens it as a local file; (b) a
  version-pinned copy on GitHub Pages for the repo/tag, address + SHA-256 given in the DingTalk message.
- Parses the pasted string; shows site, mode, API host and key fingerprint for the human to check.
- Renders the form for the mode from a **built-in whitelist**: `login` = username+password,
  `totp` = code, `custom` = a list of `{name,label,secret?}` text inputs carried in the pasted string.
  Nothing is fetched from the tunnel to decide what to render; text is written with `textContent`.
- Encrypts to the pasted key only, POSTs the armored message, then polls `status`.

API (bound to 127.0.0.1, reachable only via the tunnel; two routes per round):
- `POST /<t>/submit?mode=<m>&round=<n>` -> body is an armored PGP message; plaintext JSON
  `{fields, nonce, ts, mode, round}`. Rejected on wrong token, mismatched mode/round (inside vs.
  URL), reused nonce, ts skew > 2 min, or a second submission. The token is single-round.
- `GET  /<t>/status` -> `{state: waiting|working|done|failed|next_round, message}`; `next_round`
  tells the page to wait for the next DingTalk message.
- CORS: `Access-Control-Allow-Origin: *` (no cookies/credentials; needed for `file://`),
  `Cache-Control: no-store`, no HTML served, other paths 404.
- One tunnel and one key serve all rounds of a login request; the whole request ends on
  `done`/`failed`/TTL (default 10 min) and tears the tunnel down. Key `uses` is counted once per
  login request, not per round.

### 4.4 DingTalk robot (`notify`)
Custom-robot webhook `https://oapi.dingtalk.com/robot/send?access_token=…`, with optional
signing secret (`timestamp\nsecret` HMAC-SHA256, base64, url-encoded) and keyword/IP-allowlist
compatible text. Sends a markdown message: site, requester ("agent asked for login"), the static page address (+ its
SHA-256), the **connection string in a code block** (to be copied), the key fingerprint, expiry
time. `@mobiles` configurable.

### 4.5 Site drivers (`site`)
```go
type Driver interface {
    Name() string
    Match(u *url.URL) bool
    Fields() []Field                                   // what the page asks for
    Login(ctx context.Context, base *url.URL, c Credentials, hc *http.Client) (*Session, error)
    Probe(ctx context.Context, base *url.URL, s *Session) error   // is it still valid?
}
type Session struct {
    Cookies   []*http.Cookie
    Headers   map[string]string   // e.g. Authorization: Bearer …
    Tokens    map[string]string
    ExpiresAt time.Time
}
```
Drivers self-register in `init()`; `main.go` blank-imports them. Adding a site = one package
or one YAML file. `generic` driver covers simple cases declaratively:
```yaml
sites:
  - name: grafana
    match_host: grafana.corp.example
    steps:
      - {method: POST, path: /login, json: {user: "{{username}}", password: "{{password}}"}}
    collect: {cookies: [grafana_session]}
    probe: {path: /api/user, expect_status: 200}
```

Phase-1 flows (to be verified against real instances during implementation):

| Site | Flow |
|---|---|
| GitLab | GET `/users/sign_in`, scrape `authenticity_token`, POST `user[login]`, `user[password]` (+ `user[otp_attempt]` on 2FA). Collect `_gitlab_session` |
| Kibana | POST `/internal/security/login` (`kbn-xsrf: true`, provider basic). Collect `sid`. Fallback to legacy `/api/security/v1/login` |
| KubeSphere | POST `/oauth/token` (password grant) → `access_token`/`refresh_token`; also v4 `/login` cookie path. Return bearer header |
| Nightingale (v7) | POST `/api/n9e/auth/login` → `access_token`/`refresh_token`; return bearer header |
| Archery | GET `/login/` for `csrftoken`, POST `/authenticate/` (+2FA if enabled). Collect `sessionid`, `csrftoken` |
| SkyWalking | No login needed today → `noauth` driver: `login` probes the URL, returns an empty session with `auth: none`, never prompts. `generic` can add basic/form auth later |

### 4.6 Sessions (`session`)
In-memory cache keyed by `scheme://host`, TTL from driver; on `login` call, run `Probe` first and
only prompt the human if invalid (avoids DingTalk spam). `singleflight` per host so parallel agent
calls trigger one prompt. Optional `persist: true` stores sessions encrypted to the pool key on disk.
`force_refresh` arg bypasses cache.

## 5. MCP tools

| Tool | Input | Output |
|---|---|---|
| `login` | `url`, `site?`, `force_refresh?`, `timeout_s?` | `{site, cookies[], cookie_header, headers, tokens, expires_at}` |
| `login_sessions` | – | cached hosts + expiry (no secrets) |
| `logout` | `url` | drops cache |
| `archery_query` | `url`, `instance`, `db`, `sql`, `limit` | rows (read-only query endpoint, no approval) |
| `archery_run_sql` | `url`, `instance`, `db`, `sql`, `remark`, `wait_timeout_s?` | execution result (sync) |
| `archery_workflow_status` / `archery_wait` | `workflow_id` | status / continue waiting & execute |

Long-running calls emit MCP progress notifications (“waiting for human login”, “waiting for approval”).

### Archery async approval → sync SQL
`archery_run_sql` does:
1. `login` (cached or prompted).
2. `POST /simplecheck/` / `/sql/check/` — syntax and auto-review; abort on level-2 errors.
3. `POST /autoreview/` to submit the workflow → `workflow_id`.
4. DingTalk message to the human/approvers with workflow link and SQL summary (reuses `notify`).
5. Poll `workflow detail` every 5–10 s until status ∈ {approved, rejected, aborted, timeout}
   (honouring `wait_timeout_s`, default 30 min).
6. On approved → `POST /execute/` (immediate), poll until `finish`/`exception`.
7. Return rows-affected / error / backup info.
If the wait exceeds the MCP client's patience, return `{status: "pending", workflow_id}` and the
agent resumes with `archery_wait(workflow_id)` — the call is idempotent, never double-executes
(guarded by workflow status + a local lock file).
Execution after approval is **automatic** (decided). Safeguards: never auto-approves; executes only
after Archery reports the workflow approved. DDL is allowed by default; set `archery.allow_ddl: false`
in the config to refuse it.

## 6. Configuration

`~/.config/login/config.yaml`, env overrides `LOGIN_DINGTALK_WEBHOOK`, `LOGIN_DINGTALK_SECRET`,
`LOGIN_TUNNEL_ORDER`. Sections: `dingtalk`, `tunnel`, `keys`, `sessions`, `sites`, `archery`.
MCP registration: `claude mcp add login -- login`.

## 7. Testing

- Unit: key pool cap (8) & LRU reuse; PGP round-trip (Go encrypt ⇔ server decrypt, plus openpgp.js
  fixture); provider URL parsing from captured real banners; DingTalk signature vector.
- Site drivers: `httptest` fakes reproducing each login flow (CSRF, 2FA, bad password).
- Integration: fake `ssh` script on `PATH` that prints a URL and proxies to the port; full flow with
  an in-process "human" posting an encrypted credential.
- Archery: fake workflow state machine (pending → approved → executing → finished).

## 8. Threat model & caveats

- **Tunnel provider sees only API traffic.** It terminates TLS but serves no script and no key.
  Credentials are encrypted in the browser, by trusted JavaScript, to a key delivered over DingTalk;
  the provider can log or tamper with ciphertext but cannot read it or substitute a key.
- **What a malicious provider can still do:** drop/delay requests (DoS), return a lying `/status`
  message (shown as plain text only), or learn that a login happened. It cannot change which form
  is shown (mode comes from the DingTalk string) nor read anything submitted. The page shows site,
  mode, API host and key fingerprint for the human to check against DingTalk.
- **Residual trust:** the static page's origin. A local file from the installed binary is the
  strongest; the Pages copy relies on GitHub + the SHA-256 in the DingTalk message.
  DingTalk is trusted to deliver the connection string unmodified.
- Private key stays local, 0600; plaintext password zeroed after use, never logged; MCP responses
  contain only cookies/tokens. Replay protection via nonce+ts+round; token compared constant-time.
- Returned cookies are secrets handed to the agent by design; `login_sessions` never prints them.
- SSH host keys: `accept-new` trust-on-first-use.

## 9. Milestones

1. Skeleton: module, MCP stdio server, config, `login` returning a stub.
2. keyring + static page + one-shot JSON API (local only) + PGP round-trip, multiple rounds (login, then totp).
3. tunnel providers + DingTalk notify → full human loop.
4. Drivers: gitlab, kibana, kubesphere, nightingale, archery, skywalking, generic.
5. Session cache/probe/singleflight.
6. Archery approval→sync tools.
7. Docs, CI (`go vet`, tests), release tag.

## 10. Decisions

1. SkyWalking: no login for now -> `noauth` driver.
2. SSH-J: TCP-kind provider, excluded from the web fallback chain.
3. Nightingale v7.
4. Key pair limit: <= 8 uses or <= 24 h per key pair (not a pool-size cap).
5. DingTalk: signed custom-robot webhook, one-way.
6. Archery: execute automatically after approval; DDL allowed by default, `archery.allow_ddl: false`
   disables it.
7. Tunnel serves a JSON API only (no `/mode`); the login/TOTP form comes from a trusted static page
   where the user pastes the connection string (full per-round submit URL incl. mode + public key).
   Login and TOTP are equal, independent rounds, each with its own URL, token and DingTalk message.
8. Repo has a `master` branch (created); it is the PR base.

Still open: where the trusted static page is hosted besides the local file (GitHub Pages under the
repo is assumed; needs Pages enabled on `master`).
