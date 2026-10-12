# Operating guide

How to set securl up, check it before the first real use, and fix the usual problems.

## 0. The quick way

First make the vault, once: `securl vault init` asks for a passphrase of at least 16 characters (twice) and creates the
encrypted store that holds every secret securl keeps. It also moves anything an earlier version left in plain files
(TOTP secrets, stored sessions, transport keys) into it. **There is no way to recover a forgotten passphrase.**

`securl config init` asks for the DingTalk robot and the safety settings and can send a test message;
`securl config site add <url>` sets up one website. Everything below explains the same settings if you prefer
to edit `config.yaml` by hand. `securl config show` prints the file with secrets masked, and every `securl config`
change keeps the previous file as `config.yaml.bak`.

## 1. What you need

* The `securl` binary: `go install github.com/LeafAI/securl@latest` with Go 1.25 or newer, or, without Go, the nightly
  build (the README shows how to check the download against `SHA256SUMS`), or the Docker image.
* An outbound `ssh` client and network access to at least one tunnel provider (or your own jump server).
* A DingTalk **custom robot** in the group chat of whoever will type the credentials.
* Register the server with your MCP client, e.g. `claude mcp add securl -- securl`.

## 2. DingTalk robot

1. In the DingTalk group: *Group settings → Bots → Add bot → Custom*.
2. Choose a security setting: **signing secret** (recommended, put it in `dingtalk.secret`), or a **keyword**
   (put it in `dingtalk.keyword`), or an IP allow-list.
3. Put the webhook in `dingtalk.webhook` (or `SECURL_DINGTALK_WEBHOOK`).
   To @-mention people when a link is sent, list their phone numbers in `dingtalk.at_mobiles` (digits only, for example
   `securl config set dingtalk.at_mobiles 13800000001,13900000002`). Each message then starts with `@number` for every
   one of them: DingTalk needs the number in the text as well as in the mention list. A number with anything but digits
   in it is skipped, so check the first message: `securl doctor -send` mentions them too.
4. Check: `securl doctor -send` should post a test message. DingTalk rejects it with an `errcode` if the keyword,
   signature or IP rule does not match; the error is printed.

The robot is one-way: it only posts links. Everyone in the group can see them, so use a group of the people who
may log in. Anyone who opens a link still has to type credentials and match the key code.

## 3. Tunnel

The login API runs on 127.0.0.1 and is exposed through `ssh -R`. Order and extra servers are in `tunnel:`.

* `securl doctor -tunnel` starts each provider and fetches a page through it. Free providers come and go; use the
  ones that pass from **your** network, and put them first in `tunnel.order`.
* A server of your own is the most reliable option (`tunnel.providers`, see the README).
* `ssh-j` forwards raw TCP only and is never used for the web API.
* Tunnels are **one-shot**. Each is checked from outside before its link is sent (a provider's 502 "no tunnel" is
  caught and the tunnel replaced, the person never sees it) and is closed, with every process it started, as soon as
  the login ends, whatever the outcome. After a login there should be no `ssh -R` of securl left:
  `ps ax | grep 'ssh .*-R'`. The audit log says which provider carried each link
  (`grep '"event":"tunnel"' audit.jsonl`).
* If the tunnel drops while someone is typing, a new tunnel is started and a **replacement link** is sent
  (up to twice). The old link stops working.

## 4. The static login page

* Default: `https://leafai.github.io/securl/` (published from `master`). It contains no secrets and does no
  network calls until a link is opened.
* To verify the hosted copy: compare `https://leafai.github.io/securl/SHA256SUMS` with the sums printed by
  `securl page`.
* To avoid trusting the hosted copy: `securl page ./securl-page`, open `index.html`, or set
  `web.page_url: file:///.../securl-page/index.html`. (An https hosted page refuses http tunnels; a local file
  allows them.)
* Every login shows a **key code** on the page and in the DingTalk message. The human must compare them before
  Submit is enabled.

## 5. Configure each site

Use `securl doctor -site <url>` for every site before the first login. It needs no credentials, applies your
`aliases`, `roots` and `allowed_hosts` exactly like the tools do, and tells you what the driver will do.

| Site | Driver | Config you may need |
|---|---|---|
| GitLab 16.8 (LDAP + TOTP) | `gitlab` | usually none. The LDAP tab is used automatically. `site_options.gitlab.login_method: standard` for local accounts; `ldap_provider` if the form posts somewhere other than `ldapmain`. |
| Jenkins 2.226 | `jenkins` | `roots:` if Jenkins is under a context path (e.g. `/jenkins`). Returns the session cookie and the `Jenkins-Crumb` header. |
| KubeSphere 3.4.1 (LDAP) | `kubesphere` | usually none (the LDAP provider is discovered). `site_options.kubesphere.identity_provider: <name>` if discovery fails, `local` for built-in accounts. |
| Nightingale v7 | `nightingale` | none. A captcha, if enabled, appears in the login step. |
| Kibana | `kibana` | `roots:` for `server.basePath`. The login provider is discovered. |
| Archery 1.12.0 | `archery` | `archery.default_group` (resource group name); `roots:` if under a path. |
| SkyWalking (no login) | `skywalking` | none. |

Host names rarely contain the product name, so add `aliases:` (`es.corp.example: kibana`) and, to limit what the
agent may target, `security.allowed_hosts`.

### The two TOTP factors (optional)

Two time-based codes, from your authenticator, add layers around the credential. Both are off by default.

```
securl config totp init           # make both secrets, show them (and their otpauth:// URIs), switch both on
securl config totp init link      # just the unlock factor (or: seal)
securl config totp code           # print the current codes (valid for ...), for an authenticator that cannot do the period
securl config totp status         # what is on, with settings; never a secret or a code
securl config totp off link       # switch off, keep the secret (so your authenticator entry stays valid);  on link  to switch back
```

* **Unlock code** (`security.link_totp`): the DingTalk link hides the site, the tunnel address and the one-shot password; the
  page asks for this code before it shows anything. The default period is **10 minutes**, the longest 1Password supports
  (600 s); 1Password also supports the default of 8 digits. A longer period works in `config.yaml`, but many authenticators ignore a custom period: use `totp code`.
* **Sealing code** (`security.seal_totp`, 30 s): the page asks for this code too and seals what you type with it.
* Register each secret in your authenticator when `totp init` shows it; it is not shown again.
* If a factor is on and its secret file is missing or readable by others, **the server will not start** (`securl doctor`
  says which). A person who has lost an authenticator entry: delete the secret file and run `totp init` again.
* The unlock period must also fit the link's life: a link can touch at most 4 windows of it (more cannot be carried). With
  the default `web.ttl` of 10 minutes that means a period of **200 seconds or longer**; a shorter one is refused at start-up
  and by `securl doctor`. A longer `web.ttl` needs a proportionally longer period.

### Audit log and request limits

* `audit.jsonl` (next to the config; 0600) gets one JSON line per tool call, per request that reached a person and
  per refusal. It records who (MCP client name), which host, the reason the agent gave and the result. It never
  holds cookies, tokens, passwords or SQL text (only its length and a short hash).
  Handy questions: `grep '"event":"human_request"' audit.jsonl` (which logins reached a person),
  `grep '"event":"human_round"' audit.jsonl` (every message sent: password, TOTP, ...), `grep rate_limited audit.jsonl`.
* `limits:` stops an over-eager agent from flooding the DingTalk group: by default 6 requests per site and 20 overall
  per hour, and a 10-minute pause for a site after somebody pressed Reject. Raise them with
  `securl config set limits.per_site 12`. Cached sessions never count.

## 6. First-run checklist

0. `securl vault init` – once. `securl doctor` then shows the vault as `locked` (normal: a running server is opened with
   `vault_unlock`) and fails if it does not exist.
1. `securl doctor` – config, vault, ssh, providers.
2. `securl doctor -send` – DingTalk.
3. `securl doctor -tunnel` – at least one provider passes.
4. `securl doctor -site https://gitlab.corp.example` (and each other site).
5. Ask the agent to open the vault (`vault_unlock`) and then a session (`session_open`). You should receive a DingTalk
   message for each: open the link, compare the key code, type the vault passphrase, then the site credential, and (for TOTP) get a second message.
6. Logins survive a restart of the MCP server: sessions are kept in the vault, which the next process opens with
   `vault_unlock` (you type the passphrase once per start).

## 7. Troubleshooting

| Error code | Meaning | What to do |
|---|---|---|
| `notify_failed` | DingTalk refused or was unreachable | `securl doctor -send`; check webhook, secret/keyword/IP rule |
| `tunnel_unavailable` | no provider produced a URL, or none of the tunnels opened carried traffic | `securl doctor -tunnel`; check outbound ssh; reorder or add a provider |
| `human_timeout` | nobody finished the step in `web.ttl` (10 min) | ask again; check the DingTalk group |
| `user_rejected` | the human pressed Reject (the reason is in the message) | do not retry unless asked |
| `bad_credentials` | the site refused the username/password/code | retry carefully: KubeSphere/GitLab/Jenkins may lock accounts after repeated failures |
| `login_rejected` | the site refused for another reason (locked, captcha, unsupported 2FA, wrong URL) | read the message; `securl doctor -site` often shows why |
| `site_unreachable` | the site could not be contacted | network/proxy/DNS; check `roots:` path prefix |
| `session_expired` | a cached session was rejected | call `session_open` with `force_refresh` |
| `rate_limited` | people were asked too often, or the site was just rejected | wait for the retry time; do not loop. Raise `limits:` only if the volume is legitimate |
| `unsupported_site` | no driver for that host | add `aliases:` or pass `site` |
| `host_not_allowed` | outside `security.allowed_hosts`, or a local address (`127.0.0.1`, `localhost`, link-local, metadata) while `security.allow_local_addresses` is off | add the host, or set `allow_local_addresses: true` for a development service on this machine |
| `ddl_disabled` / `sql_check_failed` / `archery_error` | Archery tool refusals | see `MCP_TOOLS.md` |

Page-side messages (shown to the human): *Key fingerprint does not match* or *link is incomplete* mean the link
was altered or truncated; ask for a new login. *stale timestamp* means the device clock is off by more than two
minutes. *refused the submission (400…)* usually means the link belongs to an older round: use the newest message.

## 8. Not supported (yet)

GitLab reCAPTCHA after repeated failures; WebAuthn/passkey-only accounts; Jenkins 2FA plugins; any TOTP on Kibana
or KubeSphere (stock versions have none). These fail with an explanatory error rather than being guessed at.
