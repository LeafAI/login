# securl

A secure URL requestor for AI agents: an MCP server that gets an agent into sites that need a human to type credentials
(GitLab, Jenkins, Kibana, KubeSphere, Nightingale v7, Archery, SkyWalking, and any site you describe in YAML). A person
types the credential once, on a page opened from a DingTalk link, and the agent never sees the password.

Secrets are kept in an encrypted vault that is locked at start and opened by the person typing its passphrase
(`vault_unlock`). The agent then uses a site through `request`: securl adds the credentials to the request and removes
them from the answer, so the agent never holds a cookie, a token or a password.

First get the `securl` binary. Pick the way that fits the machine (`go version` tells you):

**Go 1.21 or newer, for a Go developer:** install it directly. securl needs Go 1.26.9, and Go downloads that
toolchain itself unless `GOTOOLCHAIN=local` is set.

```
go install github.com/LeafAI/securl@latest
```

`@latest` is the newest `master`; the repository has no release tags. For a fixed version give a commit:
`go install github.com/LeafAI/securl@<commit>`.

**No Go toolchain:** download the nightly build for your platform, check it, and put it on your `PATH`. There is one
release, tagged `nightly`, built from `master` and replaced every night when `master` has changed
([releases](https://github.com/LeafAI/securl/releases/tag/nightly)):

```
# macOS / Linux: <os> is darwin or linux, <arch> is arm64 or amd64
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS            # sha256sum on Linux; must print OK
tar -xzf securl_<os>_<arch>.tar.gz
install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl
securl version                                          # nightly-<date>-<commit>
```

Every archive is published twice, as `securl_<version>_<os>_<arch>` and as `securl_<os>_<arch>` (the same file), so the
command above never goes stale. The release is a pre-release, so GitHub's "latest" link does not point at it: use the
`download/nightly` address. Each build lists `SHA1SUMS` and `SHA256SUMS`. Both catch a damaged download; rely on
SHA-256 against tampering, because SHA-1 collisions can be made. Windows gets a `.zip`: check it with
`certutil -hashfile securl_windows_<arch>.zip SHA256` and compare the line in `SHA256SUMS`. `--ignore-missing` is needed
because you downloaded one archive and the file lists all of them. The nightly is a build of the newest `master`, not a
tested release.

Then register it with your MCP client:

```
claude mcp add securl -- securl          # or add "securl" to any MCP client's server list
```

An agent skill that teaches install, update, setup and use is in [`skills/securl/SKILL.md`](skills/securl/SKILL.md). Copy
the `skills/securl` directory into your client's skills directory (for Claude Code: `~/.claude/skills/securl/`).


## How a login works

1. The agent calls `session_open(url)`. A valid cached session is reused (probed first).
2. `login` takes a key pair from a local pool (each key: ≤ 8 uses and ≤ 24 h), starts a one-shot JSON API on
   `127.0.0.1` and exposes it through an SSH reverse tunnel (pinggy, localhost.run, serveo, tunnl.gg, or your own).
3. A DingTalk robot message carries **one link** to a static login page. The link's `#fragment` holds the mode
   (`login`/`totp`), the tunnel API address and the **public key**; nothing in it reaches any server.
4. The human opens the link, types the credential; the page encrypts it (OpenPGP) to the key from the link and
   posts it to the API. The human can instead press **Reject** and give an optional reason — the agent receives
   `user_rejected` with that reason.
5. `login` decrypts it and runs the site's real login flow. If the site wants a second factor, the driver
   starts another round (a new link in DingTalk). The cookie/token is returned to the agent.

The static page is served by GitHub Pages (version-pinned) or from your disk (`securl page [dir]`); the tunnel
carries only ciphertext. See `DESIGN.md` (architecture, threat model) and `MCP_TOOLS.md` (tool schemas).

## Production deployment

![securl: production deployment architecture](docs/architecture.svg)

`securl` runs as one process next to the agent (the nightly binary, `go install`, or the Docker image) and talks to the agent over stdio.
Its config, key pool, encrypted sessions and audit log live in one private directory (a volume in Docker).
Nothing listens on a public port: the only inbound path is the `ssh -R` tunnel that `login` itself opens, and it
exists only while a person is being asked.

1. The agent calls `session_open(url)`; the session is opened and its use is described below.
2. `login` sends one link through the DingTalk robot (signed webhook).
3. The person receives it in DingTalk.
4. The link opens the static page from GitHub Pages (or your own copy); it carries the key and tunnel address in
   its `#fragment`, which no server sees.
5. The page encrypts what the person types and posts it to the tunnel address; the provider sees ciphertext only.
6. The tunnel forwards it to the one-shot API on `127.0.0.1`, where it is decrypted.
7. The site driver runs the real login against the target site inside your network.

## Security notes

- The static login page was reviewed in depth: see `docs/static-page-review.md` (findings, fixes, residual risks).
  Notably, the human must compare a short **key code** shown on the page with the one in the DingTalk message
  before the page lets them submit, and after a link is accepted the page can only talk to that link's tunnel.
- Agent-supplied text (`reason`, SQL title/remark/SQL) is escaped before it is put in DingTalk markdown, so it
  cannot add links or formatting to the message the human acts on.
- `security.allowed_hosts` limits which sites the agent can target.
- The agent chooses the URL, so the HTTP client refuses this machine's own addresses (loopback, link-local, the cloud
  metadata endpoint) unless `security.allow_local_addresses: true`; it checks the address it actually connects to, so
  a name that resolves to one is refused too. Private networks (10/8, 172.16/12, 192.168/16) stay reachable: that is
  where your sites live. A redirect that leaves the site (another host or port, or https to http) is not followed,
  so a site cannot bounce a login request, body included, to a second host; list an SSO server in `allowed_hosts`
  if a site legitimately redirects to it.
- Unknown keys in `config.yaml` are an error at startup and in `securl doctor`, with a suggestion ("did you mean
  `allowed_hosts`?"), so a typo cannot silently switch a protection off.
- `archery.allow_ddl: false` is enforced by a SQL scanner (comments, strings and `;` aware, MySQL executable
  comments included, `PREPARE`/`EXECUTE` refused, anything unparsable refused), not a pattern match.
- Every secret securl keeps (logged-in sessions, TOTP secrets) is in one **vault**: AES-256-GCM under a random master
  key that is wrapped with a key derived from your passphrase (argon2id, at least 16 characters). Nothing secret is on
  disk in the clear: no key file next to the data, and the OpenPGP keys that protect a link in transit live in memory
  only. The vault is locked when the process starts; the agent calls `vault_unlock`, you get a DingTalk link and type
  the passphrase on that page. Wrong passphrases are slowed (3 free attempts, then 30 s doubling to 15 min). Make it
  with `securl vault init`, which also moves anything an earlier version left in plain files into it. Every reuse of a
  session is validated against the site first; stale entries are dropped.
- **The agent never holds a credential.** `session_open` says that a session exists, not what it contains; `request`
  sends an HTTP request with the session's cookies and tokens put in here, and removes them from the answer (every
  value in the encodings a server repeats them in, `Set-Cookie`, credential headers). The agent can reach only the
  session's own site, cannot supply a `Cookie` or `Authorization` header, and redirects are never followed off the site.
  The scrubber is a safety net with stated limits (see `MCP_TOOLS.md`), not the only layer.

## Set it up without editing YAML

```
securl config init                 # DingTalk robot + safety settings, with a test message
securl config site add https://gitlab.corp.example   # detects the driver, asks that driver's own questions
securl config site custom          # any other website: answer questions, no YAML
securl config set                  # list every setting; `set <key> <value>`, `get`, `unset`, `show`
```

Each change is checked before it is saved (a typo such as `dingtalk.webhok` is refused with a suggestion), the
file stays private (0600), your comments are kept and the previous version is saved as `config.yaml.bak`.
Secrets are asked without echo and shown masked.

## First run

See `docs/OPERATING.md` for the full operator guide (setup order, per-site config, troubleshooting).

```
securl doctor                 # checks config, ssh, key dir, providers
securl doctor -tunnel         # starts each tunnel provider and fetches a page through it
securl doctor -send           # posts a test message through the DingTalk robot
securl doctor -site <url>     # no credentials: shows which driver/login method a site will get (use for every site)
securl page [dir]             # writes the static login page for local use
```

## Configuration

`~/.config/securl/config.yaml` (override with `-config`). Environment: `SECURL_DINGTALK_WEBHOOK`,
`SECURL_DINGTALK_SECRET`, `SECURL_TUNNEL_ORDER`.

```yaml
dingtalk:
  webhook: https://oapi.dingtalk.com/robot/send?access_token=...
  secret: SEC...            # signing secret, if the robot uses "加签"
  keyword: login            # only if the robot requires a keyword
  at_mobiles: ["138..."]    # phone numbers to @mention: digits only; each message starts with "@number" for every one
tunnel:
  order: [pinggy, localhost.run, serveo, tunnl]   # ssh-j is TCP-only and is never used for the web API
  timeout: 20s
  providers:                                        # extra servers
    - name: mycorp
      command: ssh -R 0.0.0.0:{{port}}:localhost:{{port}} jump.corp.example
      url: https://jump.corp.example:{{port}}       # or url_regex to parse a printed URL
web:
  page_url: https://leafai.github.io/securl/   # or file:///path/to/securl-page/index.html
  ttl: 10m                                          # per round
keys: {max_uses: 8, max_age: 24h}
sessions:
  persist: true               # keep logins (encrypted) so a new MCP server process reuses them; default false
mcp: {max_block_seconds: 50}
archery:
  allow_ddl: true            # false rejects CREATE/ALTER/DROP/TRUNCATE/RENAME (and PREPARE/EXECUTE, which hide SQL)
  default_group: dba         # Archery resource group when a call gives none
  wait_timeout: 30m          # default approval timeout
security:
  allowed_hosts: ["*.corp.example"]   # optional: the agent may only log in to matching hosts
  allow_local_addresses: false        # true lets the agent reach localhost / link-local / metadata addresses (dev only)
audit:
  enabled: true              # default; JSON lines (who/what/when, never secrets) in audit.jsonl next to this file
limits:                      # protect people from request floods; only requests that reach a person count
  per_site: 6                # per window (defaults shown)
  total: 20
  window: 1h
  reject_cooldown: 10m       # after a Reject, that site is paused
site_options:                # driver-specific settings
  gitlab:                    # LDAP-enabled GitLab: the LDAP tab is used automatically
    login_method: auto       # auto | ldap | standard (standard = local GitLab accounts)
    ldap_provider: ldapmain  # only if it differs from the name in the sign-in form
  kubesphere:                # LDAP users must log in through /oauth/login/<provider>
    identity_provider: auto  # auto (first LDAPIdentityProvider) | local | <provider name>
roots:                       # sites served under a path prefix: host -> full base URL
  elk.corp.example: https://elk.corp.example/kibana
aliases:                     # hostnames that do not hint at the product
  es.corp.example: kibana
  apm.corp.example: skywalking
sites:                       # any other website, no Go needed
  - name: grafana
    match_host: grafana
    steps: [{method: POST, path: /login, json: {user: "{{username}}", password: "{{password}}"}}]
    twofa: {detect_body: otp_required, step: {method: POST, path: /login/otp, form: {code: "{{code}}"}}}
    collect: {tokens: {access: data.token}, headers: {Authorization: "Bearer {{token:access}}"}}
    probe: {path: /api/user}
```

## Tools and resources

Every tool has a title and an output schema. Read-only resources: `securl://sites`, `securl://sessions`,
`securl://policy` (the limits that apply to the agent). The server also sends instructions on how to use the tools.

`vault_status`, `vault_unlock`, `session_open`, `session_wait`, `site_list`, `session_list`, `session_close`, `archery_instances`, `archery_groups`, `archery_query`,
`archery_run_sql`, `archery_wait`, `archery_workflow_status`, `archery_cancel`.
Long operations return a `pending` result with an id after `max_block_seconds`; resume with `session_wait` /
`archery_wait`.

## Adding a website

Describe it in YAML (`sites:` above), or write a Go driver: implement `site.Driver` in
`internal/site/<name>/`, call `site.Register` in `init()`, blank-import it in `main.go`. A driver asks the human
through `ask.Ask(ctx, "login", ...)` and, when the site wants a second factor, again with `"totp"`; the flow
turns each call into its own DingTalk link. Return `site.ErrBadCredentials`, `ErrLoginRejected` or
`ErrUnreachable` (wrapped) so the agent gets a precise error code.

## Testing

`go test ./...` — unit tests, the config wizards, the audit log and rate limits, MCP output schemas validated against real results, fake-site driver tests, a real `ssh`/`sshd` reverse-tunnel test (skipped without
them), and (when Node + Playwright + Chromium exist) browser end-to-end tests that drive the real page through the full MCP → DingTalk → tunnel → decrypt → login path.

## Docker

```
docker build -t login --build-arg VERSION=$(git describe --tags --always) .
docker run -it --rm -v securl-data:/home/securl/.config/securl securl vault init
docker run -it --rm -v securl-data:/home/securl/.config/securl securl config init
docker run -i --rm -v securl-data:/home/securl/.config/securl securl          # the MCP server (stdio)
```

The image contains `ssh` (tunnels), runs as a non-root user and keeps config, keys and the audit log in the volume.
`securl version` prints the build.

## Two optional TOTP factors

```
securl config totp init     # make the secrets, register them in your authenticator (1Password: 10 min is its maximum period)
```

An **unlock code** (long period) hides the site, the tunnel address and the one-shot password in the DingTalk link until
you type the code in the page; a **sealing code** (30 s) is mixed into the key that seals what you type. They sit on top of
the always-on AES-256-GCM seal and the OpenPGP layer, are never sent anywhere, and are not a substitute for either. See
`DESIGN.md` 4.2a for what they do and do not protect against, and `docs/OPERATING.md` for the commands.

## Roadmap

Sharing one gateway between several agents (network transport, caller identity, session isolation), keeping
credentials away from the agent (`login_request`), token renewal and more authentication methods are planned:
see `docs/ROADMAP.md`.

## What has and has not been verified

Verified in automated tests: key rotation, PGP round trip between openpgp.js and Go, round API validation,
tunnel banner parsing and fallback (with a fake `ssh`), real HTTP traffic through a real `ssh -R` forward
(local `sshd`), `ssh` accepting every built-in provider command line, DingTalk signing, the full login/2FA/reject flow in a
real browser, and every site driver against *fake* servers that imitate the flows.
**Archery**: both **1.x (checked against v1.12.0)** and the newer REST generation are supported and detected at
login. Endpoints, payloads, session/CSRF handling and the 2FA flow were checked against the Archery source code
of both generations, then exercised against fake servers that reproduce those contracts (including 1.x's HTML
error pages).

**Verified against live systems** (a real DingTalk robot, the SSH tunnel, the real login page and real accounts). In every
case the session was used on the site's own API, and a forged or missing credential was refused by the site:

| Site | What was exercised |
|---|---|
| Archery 1.x | login with TOTP, instances, groups, read-only queries, submit and cancel of a no-op workflow, Reject and the cool-down |
| Nightingale v7 | login, token used on its API |
| KubeSphere 3.4.1 | LDAP login the way the web console does it (JSON body with `title`, success as 302 with the tokens in `Set-Cookie`), token probe |
| GitLab 19.2 (JiHu) | LDAP login with TOTP |
| Kibana 7.9.3 | login with the flat `{username,password}` body, session probe, search through the console proxy |
| Jenkins 2.226 | login (`j_acegi_security_check`), success decided by the `anonymous` flag of `/whoAmI/api/json`, the session-bound `Jenkins-Crumb` equals what `crumbIssuer` issues, a job listing that anonymous users get a 403 for |
| SkyWalking 8.9.0 | no login needed: the URL answers and the GraphQL API returns data |

Real runs also found and fixed bugs that the fake servers had hidden: KubeSphere's request body and success response, its token
probe (it accepted any token, because the redirect to the login page answers 200), and Kibana 7.x's request body; and, in the
tunnel, a provider whose process was alive while its public name was not routed (the link is now checked before it is sent). The
two optional TOTP factors (unlock code of 10 minutes and sealing code of 30 seconds, both 8 digits, in 1Password) were exercised
live on Kibana and Jenkins.

What each driver was checked against in the source, besides the live run above:

**Jenkins** (2.226) was checked against its source: the login form action is read from the page
(`j_acegi_security_check` in 2.226, `j_spring_security_check` in newer releases), success is decided by
`/whoAmI/api/json` (an anonymous visitor also reports `authenticated: true`, so the `anonymous` flag is used), and
the session-bound CSRF crumb is returned as the `Jenkins-Crumb` header for POST requests. Core Jenkins has no
2FA; a 2FA plugin's extra step is reported as an error, not guessed. **GitLab** was checked against the GitLab source (16.8 and master): classic server-rendered forms, the LDAP tab
(`/users/auth/<provider>/callback`) and current GitLab's Vue sign-in and 2FA steps. **KubeSphere** 3.4.1 was checked
against its source and a browser capture of a real console login: LDAP users must use `/oauth/login/<provider>`
(the local `/oauth/token` grant cannot authenticate them), the provider is discovered from the published OAuth
config, the body is JSON, and success is a 302 whose `Set-Cookie` carries the tokens. A wrong password and an
unreachable LDAP both answer `200 {"status":500}`, so that message names both causes. **Kibana**'s login route and provider discovery were checked against
its source, and 7.9.3 against a live site. **Nightingale** (v7) was checked against its source: login payload, the optional math-image captcha (shown to
the human inside the login step) and optional RSA password encryption.

**Not verified against live systems:**
- the individual SSH provider services (use `securl doctor -tunnel`);
- Kibana's, Jenkins's and KubeSphere's second-factor paths: stock versions have none, and the retry path for custom setups is a
  guess that has never run against a real one (a 2FA plugin's extra step on Jenkins is reported as an error, not guessed);
- Nightingale's optional captcha and RSA password encryption (this instance has neither);
- other versions than the ones in the table: GitLab 16.8, Kibana 8.x, Nightingale versions other than v7 and the newer
  Archery REST generation were checked against their source (and fake servers) only; the versions in the table are the ones
  that were run.
