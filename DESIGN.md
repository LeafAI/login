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
  2. take a GPG key from the pool (≤ 8 keys, reuse)
  3. start one-shot HTTP server on 127.0.0.1:<random port>
  4. start SSH tunnel (provider chain, first one that yields an https URL wins)
  5. DingTalk robot ──▶ human: "login to <site>: https://xxx.pinggy.link/<token>"
Human opens page ─▶ page loads openpgp.js (embedded) + public key
  6. human types credential; browser PGP-encrypts {fields, nonce, ts}; POST /submit/<token>
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
  webui/                     # one-shot server + embedded login.html, openpgp.min.js (go:embed)
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
- Dir `~/.config/login/keys/` (0700), one armored private key per file, no passphrase
  but file mode 0600 (key only protects one-shot, short-lived transport; see §8).
- Cap = 8 (`max_keys`). Policy: if pool < 8 and no unused key → generate (ed25519+cv25519 or RSA-3072
  for broad openpgp.js compatibility); else reuse the least-recently-used key. Never exceeds 8.
- Optional expiry (30d) → expired keys are replaced in place, preserving the cap.

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

### 4.3 Web page (`webui`)
- Route is `/<128-bit random token>`; everything else 404. Bound to 127.0.0.1 only; reachable
  solely through the tunnel. CSP `default-src 'self'`, no external requests, `no-store`.
- `GET /<t>` → page showing site name, fingerprint of the key, and fields requested by the
  driver (`username`, `password`, optional `otp`/`captcha`).
- `POST /<t>/submit` → body is an armored PGP message. Plaintext = JSON
  `{fields, nonce, ts}`; server rejects wrong nonce, ts skew > 2 min, second submission.
- Driver can request a second round (e.g. OTP needed after password) by returning
  `NeedMore{fields}`; the same one-shot server serves one more round, still token-bound.

### 4.4 DingTalk robot (`notify`)
Custom-robot webhook `https://oapi.dingtalk.com/robot/send?access_token=…`, with optional
signing secret (`timestamp\nsecret` HMAC-SHA256, base64, url-encoded) and keyword/IP-allowlist
compatible text. Sends a markdown message: site, requester ("agent asked for login"), link,
key fingerprint (short), expiry time. `@mobiles` configurable.

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
| Nightingale | POST `/api/n9e/auth/login` → `access_token`/`refresh_token`; return bearer header |
| Archery | GET `/login/` for `csrftoken`, POST `/authenticate/` (+2FA if enabled). Collect `sessionid`, `csrftoken` |
| SkyWalking | UI has no built-in auth → depends on gateway; see open question 1 |

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
Safeguards: refuses multi-statement DDL unless `allow_ddl`; never auto-approves; execution only
after Archery reports approval.

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

- **Tunnel provider can see TLS-terminated traffic.** PGP encryption in the browser protects the
  credential against passive logging/at-rest storage at the provider, but an *active* malicious
  provider could swap the page's JavaScript. Mitigations: random unguessable path + one-shot + short TTL;
  fingerprint shown in both DingTalk and page for human comparison; self-hosted/custom
  provider recommended for production. This cannot be fully eliminated with a third-party tunnel.
- Private key stays local, 0600; plaintext password zeroed after use, never logged; MCP responses
  contain only cookies/tokens. Replay protection via nonce+ts; token compared constant-time.
- Returned cookies are secrets handed to the agent by design; `login_sessions` never prints them.
- SSH host keys: `accept-new` trust-on-first-use.

## 9. Milestones

1. Skeleton: module, MCP stdio server, config, `login` returning a stub.
2. keyring + webui + one-shot server (local only) + PGP round-trip.
3. tunnel providers + DingTalk notify → full human loop.
4. Drivers: gitlab, kibana, kubesphere, nightingale, archery, skywalking, generic.
5. Session cache/probe/singleflight.
6. Archery approval→sync tools.
7. Docs, CI (`go vet`, tests), release tag.

## 10. Open questions (need your decision)

1. **SkyWalking auth**: the UI/OAP have no login. Which is it in your environment — nginx basic auth,
   an SSO/OAuth2-proxy in front, or Apache APISIX/gateway? Default plan: HTTP Basic + form-login via `generic`.
2. **SSH-J** forwards raw TCP, not HTTP, so it can't host the login page. Plan: include it as a
   `TCP`-kind provider (exposed for custom use) but exclude it from the web fallback chain. OK?
3. **"nightingare"** is assumed to be **Nightingale (n9e)**. Confirm, and which major version (v5/v6/v7)?
4. **GPG limit of 8**: interpreted as "at most 8 key pairs on disk, reused afterwards". Correct?
5. **DingTalk**: custom robot webhook (+ secret signing, one-way) is enough — no interactive callbacks. OK?
6. **Archery**: can the agent also be allowed to execute after approval automatically (as designed), and should DDL be blocked by default?
