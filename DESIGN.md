# login — MCP server for human-assisted website login

Status: **implemented (stdio MCP server)**; later stages are tracked in `docs/ROADMAP.md`. Module: `github.com/LeafAI/login`.
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
  5. DingTalk robot ──▶ human: for the current round, ONE link to the trusted static page (GitHub
     Pages) whose URL *fragment* carries everything: submit URL (tunnel + per-round token), mode,
     round, site and the PUBLIC KEY. Nothing is copied by hand.
Human clicks the link; the page (served by GitHub Pages, never by the tunnel) parses the fragment
  6. page reads mode/key/URL from the fragment, renders the matching form itself; browser
     PGP-encrypts {fields, nonce, ts, mode, round} to the key from the link; POST <submit URL>
     (the page then polls <status URL>)
  The human may instead press **Reject** (with an optional reason); the page sends an encrypted
  `{action:"reject", reason}` through the same API and the agent gets `user_rejected` + the reason.
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
  mcpserver/                 # tool registration (login, login_sessions, logout, archery_*), resources, audit hooks
  audit/                     # append-only JSON-lines activity log (metadata only)
  ratelimit/                 # per-site / overall request limits and the cool-down after a Reject
  configedit/ configcli/     # `login config`: validated, comment-preserving edits and the guided wizards
  keyring/                   # GPG key pool (≤8), generate/reuse, armored export, decrypt
  api/                       # one-shot JSON API behind the tunnel: /submit, /status per round (no HTML)
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
  fit in a link fragment (RSA keys are 2-4x longer).

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

#### Tunnel lifecycle: one-shot

A tunnel serves exactly one login and nothing of it may outlive that login.

- **Checked before use.** A new tunnel is asked, from outside, for a path that does not exist; our API answers 404.
  Anything else (the provider's own 502 "no tunnel", a timeout) means the public name is not routed to us, so the
  tunnel is closed and replaced (up to 4 per attempt). No link is ever sent for a tunnel that did not answer; when
  none does the login fails with `tunnel_unavailable`. The audit log records the provider that carried the link and
  how many tunnels it took (`tunnel` event, `attempts`).
- **Closed at the end, however it ends.** Success, a refusal by the site, wrong password, Reject, timeout, cancel
  (`logout`), notification failure and server shutdown all close it. When a page is waiting it stays only until the
  page has read the final state, plus a short flush delay (`FlushDelay`, 3 s) so that the answer is delivered; if the
  page never reads it, `OutcomeCap` (10 s) closes it.
- **The whole process tree.** The tunnel runs in its own process group and closing it kills the group, so a wrapper
  script of a custom provider cannot leave the real `ssh` behind holding the public name and the forwarded port.

### 4.2a Layers around the credential (`seal`, `totp`)

What the person types passes through these layers, in this order. Each one is independent of the others.

```
browser:  credential -> AES-256-GCM seal (one-shot password [+ sealing code]) -> envelope -> OpenPGP encrypt -> POST
server :  OpenPGP decrypt -> envelope -> AES-256-GCM open (same password [+ code], same context) -> validate -> use
DingTalk: the link's secret parameters are AES-256-GCM encrypted under the unlock code (when that factor is on)
```

**1. OpenPGP** (the key only the local machine holds) is the layer that keeps the credential from the tunnel and from
everybody else. It is unchanged and remains the main protection.

**2. The seal** (`internal/seal`, always on). Every round has its own random 256-bit one-shot password, generated by the
server and carried in the link. The page derives an AES-256 key from it with HKDF-SHA256 and seals the credential with
AES-256-GCM under a fresh random 12-byte IV. The site, step, round and a nonce are bound twice (into the key and as GCM
additional data), so a sealed value cannot be replayed into another round, site or step. The server refuses any
submission that is not sealed (no silent fall back to the older single-layer protocol) and answers every failure with
the same words, so a probe learns nothing about which layer refused it. The password is wiped once the round is used.

**3. The sealing code** (`security.seal_totp`, optional). A 30 second TOTP code from the person's authenticator is
stretched (PBKDF2-HMAC-SHA256, 200000 iterations, salted with the one-shot password) and mixed into the AES key
(`v2.` seals). The code is typed in the page and never sent: the server computes the codes valid between the moment the
link was made and now and tries them as keys. When this factor is on, plain seals are refused, and the other way round.

**4. The unlock code** (`security.link_totp`, optional). A long-period TOTP code (default 10 minutes, the longest period
1Password supports) protects the link itself: the site name, the tunnel address and the one-shot password are encrypted in
the DingTalk message (`e` in the fragment), so the message alone does not say where the answer goes. The page shows only
the key code until the person types the unlock code; it makes no network request while locked. The key fingerprint, step
and round stay readable on purpose: the person compares the key code with the message before typing anything, which is the
check against a forged link. Because a link can be opened minutes after it was made, the blob carries one wrapped copy of
a random link key per candidate code (a slot of 60 bytes, at most 4); the page tries them with the code it was given.

**What this does and does not give.** A TOTP code is short: an 8-digit code has about 27 bits, 6 digits about 20. They are
second factors in the person's authenticator and in no message, stretched with PBKDF2 to make every guess cost real work,
and always combined with the 256-bit one-shot password; they are never the only protection of anything. Someone who
sees only the DingTalk message cannot read the details of the login (unlock code) and, even with the details, cannot make
or read a submission (sealing code). Someone who has the message AND the blob AND offline time could still guess a short
code, which is why what the blob hides is useless without the GPG private key that stays on the local machine. These
layers add depth and bind data to its round; they do not replace OpenPGP and do not defend against malware on the person's
machine.

Both secrets are 160-bit random values kept in separate 0600 files; `login config totp init` creates them, refuses to
replace an existing one (that would lock people out) and prints each as a secret and an `otpauth://` URI. If a factor is on
and its secret is missing or readable by others, the server does not start.

### 4.3 Static page + one-shot API (`web`, `api`)
The tunnel carries **only JSON**. All JavaScript comes from a static page that does not travel
through the tunnel, so a malicious provider has no script to tamper with.

**Rounds.** Each authentication step (`login`, `totp`, ...) is an independent *round* with its own
random 128-bit token, own URL, own DingTalk message and own single accepted submission. Rounds are
equal peers; nothing in the API distinguishes "first" from "second". The mode is part of the URL
the human receives, not something the API tells the page.

Round link (sent in DingTalk, clicked by the human):
```
https://leafai.github.io/login/#v=1&site=gitlab.corp.example&mode=totp&round=2
  &u=<urlenc https://x.pinggy.link/<token>>&k=<base64url binary OpenPGP public key>&f=<fingerprint>
```
- Parameters live in the **fragment (`#`), not the query (`?`)**: fragments are never sent to any
  server, so neither GitHub Pages nor DingTalk's link-preview crawler ever sees the tunnel URL,
  token or key. (Query parameters would land in GitHub's access logs.)
- The key is the binary packet in base64url (~300 bytes for Curve25519), not the armored text, to keep
  the link short; the page reads it with `openpgp.readKey({binaryKey})`.
- Optional `custom` field list is carried as `fields=<base64url JSON>`.
- The page is version-pinned in the path (`/v0.1.0/`), so a link keeps working with the page it was
  generated for. Base address is configurable (`web.page_url`) for self-hosted copies.

Static page (`web/login.html`, single file with vendored `openpgp.js`, no external requests):
- Primary: the version-pinned copy published from this repo to GitHub Pages (built in CI from the
  tagged source, embedded `openpgp.js` included). Fallbacks: a self-hosted copy via `web.page_url`,
  or `login page` writing the embedded copy to disk to open locally with a "paste link" box.
- Parses the fragment; shows site, mode, API host and key fingerprint for the human to check, and
  clears the fragment from the address bar (`history.replaceState`) after reading it.
- Renders the form for the mode from a **built-in whitelist**: `login` = username+password,
  `totp` = code, `custom` = a list of `{name,label,secret?}` text inputs carried in the link fragment.
  Nothing is fetched from the tunnel to decide what to render; text is written with `textContent`.
- Encrypts to the key from the link fragment only, POSTs the armored message, then polls `status`.

API (bound to 127.0.0.1, reachable only via the tunnel; two routes per round):
- `POST /<t>/submit?mode=<m>&round=<n>` -> body is an armored PGP message; plaintext JSON
  `{action: submit|reject, fields, reason, nonce, ts, mode, round}`. Rejected on wrong token, mismatched mode/round (inside vs.
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
compatible text. Sends a markdown message: site, requester ("agent asked for login"), the **round link** (one
click), the key fingerprint, expiry time. `@mobiles` configurable. One message per round.

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

### 5.1 Resources and server instructions

Besides tools the server exposes three read-only resources and sends instructions at connect time:

| URI | Content |
|---|---|
| `login://sites` | supported sites (same data as `login_sites`) |
| `login://sessions` | which sites are logged in; never the cookies or tokens |
| `login://policy` | allowed hosts, blocking time, request limits, DDL switch, audit on/off; no secrets |

The instructions tell the agent the call pattern (`login` -> `login_wait`), how to react to each error code
(`user_rejected`, `rate_limited`, `host_not_allowed`, `session_expired`) and that cookies are secrets. Every
tool carries a title and a generated output schema; results are validated against them in the tests.

### 5.2 Audit log and request limits

* **Audit** (`audit:`). One JSON line per tool call (`tool_call`), per login request that reaches a person
  (`human_request`), per message sent to a person (`human_round`, with `mode` and `round`: a login with TOTP
  shows `login:1` then `totp:2`) and per refusal (`rate_limited`): time, tool, MCP client name/version, site, host, the
  reason the agent gave, result or error code, duration. For SQL only the length and a 12-character SHA-256
  prefix are kept. Cookies, tokens, passwords and SQL text never appear. File mode 0600; a write failure is
  reported on stderr and never fails the call. On by default, file next to the config.
* **Limits** (`limits:`). Only requests that actually reach a person count; a cached session is free and a
  caller joining a running flow is not counted again. Defaults: 6 per site and 20 overall per hour, and a
  10-minute pause for a site after the person pressed Reject. A refused request returns `rate_limited`
  (retryable, with a hint not to loop) and sends no message.

### 5.3 `login config`

Editing YAML by hand is easy to get wrong, so the CLI does it: `init` (DingTalk and safety), `site add`
(driver detection, path prefix and the driver's own options), `site custom` (describe any login form by
answering questions), `set/get/unset/show/path`. Each driver declares its options (`site.Optioned`), so the
wizard asks exactly what that driver needs. Every change is parsed strictly (unknown keys are errors), checked
the way the server will use it, written atomically (0600), and the previous file is kept as `.bak`. Comments
and key order in the user's file survive. Secrets are asked without echo and masked when displayed.

## 6. Configuration

`~/.config/login/config.yaml`, env overrides `LOGIN_DINGTALK_WEBHOOK`, `LOGIN_DINGTALK_SECRET`,
`LOGIN_TUNNEL_ORDER`. Sections: `dingtalk`, `tunnel`, `keys`, `web`, `mcp`, `sessions`, `security`, `audit`, `limits`, `site_options`, `aliases`, `roots`, `sites`, `archery`. `login config` edits them.
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
- **Residual trust:** the static page's origin (GitHub Pages for this repo, pinned to a release
  path; a compromised repo/release would compromise users) and DingTalk delivering the link
  unmodified. For stricter setups, self-host the page (`web.page_url`) or use the local copy from
  `login page`.
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
   opened via a round link (full per-round submit URL incl. mode + public key in the fragment).
   Login and TOTP are equal, independent rounds, each with its own URL, token and DingTalk message.
   The per-round parameters (mode, key, URL) are carried in the **fragment** of a GitHub Pages link,
   so the human just clicks it; no manual copy/paste.
8. Repo has a `master` branch (created); it is the PR base.
9. The form has a Reject button with an optional reason (encrypted like a submission) -> `user_rejected` error.
10. Every driver detects a second-factor requirement and launches another round (`totp`).

11. Audit log and request limits are on by default; they protect people and give an accountability trail
    (section 5.2). The agent-facing contract is described by resources and instructions (section 5.1).

Still open: publishing the static page needs GitHub Pages enabled for the repo (source: GitHub
Actions, deploying `web/` on each release tag). That is a repo setting for the owner.
