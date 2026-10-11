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

You need Go 1.25 or newer and an outbound `ssh` client.

```
go install github.com/LeafAI/securl@latest
securl version
```

The binary is `$(go env GOPATH)/bin/securl` (usually `~/go/bin/securl`); make sure that directory is on `PATH`.

Register it with the MCP client (it speaks MCP over stdio):

```
claude mcp add securl -- securl
```

For any other client, add a stdio server whose command is `securl`. To use another config file, pass `-config <file>`.

Docker is an alternative: see the README ("Docker"). It keeps config and the vault in a volume.

## 2. Update

```
go install github.com/LeafAI/securl@latest
securl version
```

Then restart the MCP server process (the client or gateway starts it again). **A restart locks the vault**: the user
types the passphrase once more (section 4). Sessions are kept in the vault, so logins survive the restart.

A new release can change the login page (it is published separately, from `master`). If logins start failing right after
an update, check that the page is current: `securl doctor` prints the page address, and the release notes say when the
page and the binary must be updated together.

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
