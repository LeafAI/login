---
name: securl
description: Install, update, set up and use the securl MCP server, which lets an AI agent reach websites that need a human login (GitLab, Jenkins, Kibana, KubeSphere, Nightingale, Archery, SkyWalking) without ever seeing a password, cookie or token. Use when the user wants to install or configure securl, unlock its vault, log in to an internal site, call a site's API through it, or run Archery SQL; also when a securl tool answers vault_locked, no_session or session_expired.
---

# securl

securl is an MCP server that sits between an agent and sites that need a person to log in. A person types the
credential once, on a page opened from a DingTalk link. The agent never holds a password, cookie or token: it sends
requests through the `request` tool, and securl adds the credentials on the way out and removes them from the answer.

**The one rule: never ask the user for a password, a TOTP code or the vault passphrase in the chat, and never pass one
to a tool.** Every secret is typed by the person on the page that securl links to. A tool that takes a passphrase does
not exist, and an extra argument is refused.

## 1. Install

You need an outbound `ssh` client (tunnels use it). Then pick the way that fits the machine: run `go version`.

- **No Go, or Go older than 1.21: download the nightly build** (a prebuilt binary, section 1a). Most machines that only
  use securl are in this group.
- **Go 1.21 or newer, for a developer who already builds Go programs: `go install` directly** (section 1b). securl needs
  Go 1.26.9; Go downloads that toolchain by itself, unless `GOTOOLCHAIN=local` is set.

### 1a. No Go toolchain: the nightly build

```
# macOS / Linux: <os> is darwin or linux, <arch> is arm64 or amd64
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS      # sha256sum on Linux; it must print OK
tar -xzf securl_<os>_<arch>.tar.gz
install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl
securl version                                    # nightly-<date>-<commit>
```

- Do not skip the check. If it does not print `OK` for your file, delete the download and do not run it.
- `--ignore-missing` is needed because you downloaded one archive and `SHA256SUMS` lists all of them.
- Use `uname -sm` to find the platform (`Darwin arm64` is `darwin` and `arm64`, `x86_64` is `amd64`, `aarch64` is `arm64`).
- Windows gets a `.zip` (`securl_windows_<arch>.zip`): check it with `certutil -hashfile securl_windows_<arch>.zip SHA256`
  and compare the line in `SHA256SUMS`, then unzip and put `securl.exe` on `PATH`.
- `SHA1SUMS` is published too. SHA-1 collisions can be made, so it only catches a damaged download. Rely on SHA-256 against
  tampering.
- The address is `releases/download/nightly`. GitHub's "latest release" link does not point at it, because the nightly is
  a pre-release.
- The nightly is the newest `master`, built each night when it has changed. It is not a tested release.

### 1b. Go 1.21 or newer: go install

```
go install github.com/LeafAI/securl@latest
securl version                                    # securl 0.1.0 (it builds master as it is, with no nightly name)
```

The binary is `$(go env GOPATH)/bin/securl` (or `$GOBIN`); make sure that directory is on `PATH`. `@latest` is the newest
`master`, because the repository has no release tags. For a fixed version, give a commit: `go install
github.com/LeafAI/securl@<commit>`. If it answers `no matching versions` right after a push, the module proxy has not seen
the new commit yet: run it again in a minute, or use `GOPROXY=direct`.

### Both ways

- Make sure the directory the binary went into is on `PATH`, and that it is the only copy: if `securl version` is not what
  you just installed, an older copy comes first. `command -v securl` shows which one runs; remove the other (a `go install`
  copy is in `~/go/bin`, a download in `~/.local/bin`) or reorder `PATH`. A download says `nightly-<date>-<commit>`; a
  `go install` says `0.1.0`.

Register it with the MCP client (it speaks MCP over stdio):

```
claude mcp add securl -- securl
```

For any other client, add a stdio server whose command is `securl`. To use another config file, pass `-config <file>`.

Docker is another alternative: see the README ("Docker"). It keeps config and the vault in a volume.

## 2. Update

Update the way you installed, so that the new binary replaces the old one and is the only copy.

- **Downloaded (1a):** run the same commands again, including the check.

```
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS      # it must print OK
tar -xzf securl_<os>_<arch>.tar.gz
install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl
securl version                                    # the new nightly-<date>-<commit>
```

- **Go (1b):** run `go install github.com/LeafAI/securl@latest` again. It does not change `securl version` (`0.1.0`), so to
  know it moved, look at the build: in `go version -m $(command -v securl)` the `mod` line ends with the commit it was
  built from (`v0.0.0-<time>-<commit>`).

Then restart the MCP server process (the client or gateway starts it again). **A restart locks the vault**: the user types
the passphrase once more (section 4). Sessions are kept in the vault, so logins survive the restart.

A new build can change the login page (it is published separately, from `master`). If logins start failing right after an
update, check that the page is current: `securl doctor` prints the page address.

## 3. Set up (once)

Do these in a terminal, in this order. They ask the user questions, so the user types the answers.

```
securl vault init                      # passphrase, at least 16 characters, typed twice
securl config init                     # DingTalk robot and safety settings; can send a test message
securl config site add https://gitlab.corp.example   # one per site: detects the driver, asks its questions
securl doctor                          # everything should be [ok]; the vault shows as locked, which is normal
```

- **The vault passphrase cannot be recovered.** Tell the user to keep it in a password manager.
- `securl vault init` also moves anything an earlier version kept in plain files (TOTP secrets, stored sessions, keys) into
  the vault and removes the files.
- `securl config init` needs a DingTalk custom robot (group settings, bots, add bot, custom). Use the signing secret
  (`dingtalk.secret`) or a keyword (`dingtalk.keyword`). Check with `securl doctor -send`.
- Check the tunnels from the user's network: `securl doctor -tunnel`. Free providers come and go; put the ones that pass
  first with `securl config set tunnel.order pinggy,localhost.run`.
- Check each site before the first login (needs no credentials): `securl doctor -site https://gitlab.corp.example`.
- A site whose host name does not hint at the product needs an alias: `securl config set aliases.es.corp.example kibana`.
  A site served under a path needs a root: `securl config set roots.elk.corp.example https://elk.corp.example/kibana`.
- To limit what an agent may reach: `securl config set security.allowed_hosts "*.corp.example"`.
- A site that is not built in: `securl config site custom` asks for the login form step by step.
- `securl config show` prints the configuration with secrets masked. `securl config set` with no arguments lists every
  setting. Each change is checked before it is saved and the previous file is kept as `config.yaml.bak`.

Optional hardening: `securl config totp init` makes two authenticator codes. The unlock code hides the site and tunnel
address in the DingTalk link until the user types it; the sealing code (30 s) is mixed into the key that seals what is
typed. 1Password supports periods up to 10 minutes. Check with `securl config totp status`.

## 4. Use it: the order of tool calls

The server starts **locked**. Follow this order and do not skip a step.

1. `vault_status`. It needs no unlock and shows no secret. `state` is `not_initialized`, `locked` or `unlocked`.
   - `not_initialized`: tell the user to run `securl vault init`. Nothing else works until then.
2. `vault_unlock` when it is `locked`. The user gets a DingTalk link and types the passphrase on that page. The call waits
   up to `max_block_seconds` and may return `pending`: call `vault_unlock` again (with `unlock_id` set to the returned
   `login_id`, or with no argument: it joins the same unlock and sends no second link). Repeat until `unlocked`.
3. `site_list` shows which sites securl can handle and whether each needs a login; `session_list` shows which already have
   a session. Reuse them: a person is asked only when none is valid.
4. `session_open` with `url` (any URL on the site) when there is none. Give a short `reason`: it is shown to the person.
   It returns `pending` with a `login_id` while the person types; call `session_wait` with that id until `status` is `ok`.
   Some sites need a second round (a TOTP code): `waiting_for` says which, and the person gets another link.
   The result says that a session exists (`auth` is `cookie`, `bearer` or `none`), never what it contains.
5. `request` to use the site. Give `url`, `method` and `path`:

```json
{"url": "https://gitlab.corp.example", "method": "GET", "path": "/api/v4/projects", "query": {"per_page": 20}}
```

   - `path` is absolute and has no query string or host; use `query`. Bodies are `json`, `form`, `text` or `base64`.
   - Never put a `Cookie` or `Authorization` header in it: it is refused. The session's credentials are added for you.
   - Only the session's own site can be reached. A redirect to another site is returned, not followed. Set
     `follow_redirects` to follow redirects that stay on the same site.
   - Big answers are cut at `max_response_bytes` (default 262144, at most 1048576); `truncated` and `total_bytes` say so.
     Ask for less (`per_page`, `fields`, a narrower path) instead of raising the limit.
   - `redactions` counts the secret values removed from the answer. Treat any `[REDACTED]` as intended.
   - Archery is not reachable with `request` (`request_not_allowed`): use the `archery_*` tools below. Only the owner
     can lift this (`security.allow_archery_requests`); do not look for another way around it.
6. A site that needs no login (SkyWalking) works with `request` directly; `session_open` just confirms `auth: none`.

When `request` answers `401` or `session_expired`, the session ended: call `session_open` with `force_refresh: true`.
securl never logs in again by itself, so a person is asked each time and you cannot loop on it.

### Archery SQL

`archery_instances` and `archery_groups` list what the user may use. `archery_query` runs one read-only statement with no
approval (`url`, `instance`, `database`, `sql`; `limit` caps the rows). To change data, `archery_run_sql` submits a
workflow, notifies the approvers and waits: pass `url`, `instance`, `database`, `sql` and a short `title`
(at most 50 characters), plus `resource_group` unless `archery.default_group` is set. If approval takes longer than
`max_block_seconds` it returns `pending` with a `workflow_id`; call `archery_wait` with it. `archery_workflow_status`
reads a workflow and `archery_cancel` aborts one. Never submit SQL the user did not ask for: a person approves it, but
the title and statement are shown to them from what you wrote.

### Databases (PostgreSQL, MySQL; not production)

`db_targets` lists what the owner made reachable: `name`, `driver`, `environment`, `mode` (`read_only` or `read_write`),
`allow_ddl`, `databases` and `has_session`. You choose a `target` by name; you never give a host or a password.

1. No session (`has_session: false`, or `no_session`): `session_open` with `url: "db://<target>"` and a `reason`. A person
   types the database account on the usual page. Wait with `session_wait`, as for any login.
2. `db_query` with `target`, `sql`, and `database` unless the target lists exactly one. One statement that only reads
   (`SELECT`, `SHOW`, `EXPLAIN`, `DESCRIBE`, `WITH ... SELECT`). Ask for what you need (`limit`, `WHERE`, columns):
   `truncated: true` means rows or bytes were left out.
3. `db_exec` changes data, only on a `read_write` target, with a `reason` the team will read in DingTalk after the
   change. Everything runs in one transaction; a change that touches more than `max_changed_rows` is rolled back
   (`too_many_rows`), so narrow the `WHERE`. DDL needs `allow_ddl` on the target (`ddl_disabled`).
4. `session_expired` means the database stopped accepting the saved account: `session_open` again with `force_refresh`.
   `session_close` with the same `db://` URL forgets the account.

Never use a database target for production: the owner cannot list one, and Archery (`archery_run_sql`) is where a person
approves each change there. Do not look for another way to reach a host you were not given.

## 5. Work efficiently

- **Check before asking.** `vault_status`, then `session_list`. A session is reused, so most calls need no person at all.
- **Do not poll.** `vault_unlock`, `session_open`, `session_wait` and `archery_wait` already wait up to
  `max_block_seconds`. A call that returns `pending` is normal: call the `next_tool` it names with the id it gives.
  Two calls in a row to `session_open` for the same site join one login and send one message.
- **Do not loop on a refusal.** `user_rejected` means the person pressed Reject: do not retry unless they ask. A rejected
  site is paused for 10 minutes, and people are asked at most 6 times per site and 20 per hour (`rate_limited`).
- **Batch your reads.** Prefer one `request` with a list endpoint and `fields`/`per_page` over many small ones.
- **Keep the person's time in mind.** A login is a message in a group chat. Say in `reason` what for, once.
- **If the client times out** (many abort a tool call after 30 s), lower the wait: `securl config set mcp.max_block_seconds 25`.
- **The vault stays open until the process ends.** To lock it again after a period of no use:
  `securl config set vault.idle_lock 1h`.

## 6. When something fails

| Answer | What it means | What to do |
|---|---|---|
| `vault_locked` | the vault is not open | call `vault_unlock` |
| `vault_not_initialized` | no vault yet | the user runs `securl vault init` |
| `no_session` | no valid session for that site | call `session_open` |
| `session_expired` or a `401` | the session ended | `session_open` with `force_refresh: true` |
| `human_timeout` | nobody finished within 10 minutes | ask again; check the DingTalk group |
| `user_rejected` | the person pressed Reject | do not retry unless asked |
| `bad_credentials` | the site refused what was typed | retry carefully; accounts can lock |
| `rate_limited` | people were asked too often, or wrong passphrases are being slowed | wait for the retry time |
| `host_not_allowed` | outside `security.allowed_hosts`, or one of this machine's own addresses | ask the user to change the setting; do not try other spellings |
| `tunnel_unavailable` | no tunnel carried traffic | the user runs `securl doctor -tunnel` |
| `notify_failed` | DingTalk refused the message | the user runs `securl doctor -send` |
| `site_unreachable` | the site could not be contacted | network, VPN or the `roots` path |
| `unknown_target` / `database_not_allowed` | a database or target name that is not configured | `db_targets`; use a name it lists |
| `target_read_only` / `not_read_only` | a change on a read-only target, or a `db_query` that is not one plain read | use `db_exec` on a `read_write` target |
| `too_many_rows` / `statement_timeout` | the change was rolled back, or the statement ran too long | narrow the statement |
| `invalid_argument` | a wrong or extra argument | read the message; a passphrase argument is always refused |

`securl doctor` is the first thing to run for anything about setup. It never asks for the passphrase.

## 7. What securl does not do

- It never shows the agent a credential, and it cannot be made to: no tool returns one and no tool accepts a passphrase.
- It does not log in without a person. There is no automatic re-login and no token renewal.
- It does not reach the machine it runs on (loopback, link-local, the cloud metadata address) unless
  `security.allow_local_addresses` is on, and it does not follow a redirect to another site.
- The response scrubber is a safety net, not a proof: a site that transforms a secret in an unusual way before echoing it
  can get past it. Do not ask a site to echo the session back.
- Not supported: GitLab reCAPTCHA, WebAuthn-only accounts, Jenkins 2FA plugins.

More: `README.md` (overview and configuration), `MCP_TOOLS.md` (every tool's schema), `docs/OPERATING.md` (operator
guide), `DESIGN.md` (threat model).
