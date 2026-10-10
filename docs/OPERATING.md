# Operating guide

How to set `login` up, check it before the first real use, and fix the usual problems.

## 1. What you need

* Go 1.25+ to install: `go install github.com/LeafAI/login@latest`
* An outbound `ssh` client and network access to at least one tunnel provider (or your own jump server).
* A DingTalk **custom robot** in the group chat of whoever will type the credentials.
* Register the server with your MCP client, e.g. `claude mcp add login -- login`.

## 2. DingTalk robot

1. In the DingTalk group: *Group settings → Bots → Add bot → Custom*.
2. Choose a security setting: **signing secret** (recommended, put it in `dingtalk.secret`), or a **keyword**
   (put it in `dingtalk.keyword`), or an IP allow-list.
3. Put the webhook in `dingtalk.webhook` (or `LOGIN_DINGTALK_WEBHOOK`).
4. Check: `login doctor -send` should post a test message. DingTalk rejects it with an `errcode` if the keyword,
   signature or IP rule does not match; the error is printed.

The robot is one-way: it only posts links. Everyone in the group can see them, so use a group of the people who
may log in. Anyone who opens a link still has to type credentials and match the key code.

## 3. Tunnel

The login API runs on 127.0.0.1 and is exposed through `ssh -R`. Order and extra servers are in `tunnel:`.

* `login doctor -tunnel` starts each provider and fetches a page through it. Free providers come and go; use the
  ones that pass from **your** network, and put them first in `tunnel.order`.
* A server of your own is the most reliable option (`tunnel.providers`, see the README).
* `ssh-j` forwards raw TCP only and is never used for the web API.
* If the tunnel drops while someone is typing, a new tunnel is started and a **replacement link** is sent
  (up to twice). The old link stops working.

## 4. The static login page

* Default: `https://leafai.github.io/login/` (published from `master`). It contains no secrets and does no
  network calls until a link is opened.
* To verify the hosted copy: compare `https://leafai.github.io/login/SHA256SUMS` with the sums printed by
  `login page`.
* To avoid trusting the hosted copy: `login page ./login-page`, open `index.html`, or set
  `web.page_url: file:///.../login-page/index.html`. (An https hosted page refuses http tunnels; a local file
  allows them.)
* Every login shows a **key code** on the page and in the DingTalk message. The human must compare them before
  Submit is enabled.

## 5. Configure each site

Use `login doctor -site <url>` for every site before the first login. It needs no credentials, applies your
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

## 6. First-run checklist

1. `login doctor` – config, ssh, providers.
2. `login doctor -send` – DingTalk.
3. `login doctor -tunnel` – at least one provider passes.
4. `login doctor -site https://gitlab.corp.example` (and each other site).
5. Ask the agent to log in. You should receive a DingTalk message, open the link, compare the key code, type
   the credential, and (for TOTP) get a second message.
6. Set `sessions.persist: true` if you want logins to survive a restart of the MCP server.

## 7. Troubleshooting

| Error code | Meaning | What to do |
|---|---|---|
| `notify_failed` | DingTalk refused or was unreachable | `login doctor -send`; check webhook, secret/keyword/IP rule |
| `tunnel_unavailable` | no provider produced a URL | `login doctor -tunnel`; check outbound ssh; reorder or add a provider |
| `human_timeout` | nobody finished the step in `web.ttl` (10 min) | ask again; check the DingTalk group |
| `user_rejected` | the human pressed Reject (the reason is in the message) | do not retry unless asked |
| `bad_credentials` | the site refused the username/password/code | retry carefully: KubeSphere/GitLab/Jenkins may lock accounts after repeated failures |
| `login_rejected` | the site refused for another reason (locked, captcha, unsupported 2FA, wrong URL) | read the message; `login doctor -site` often shows why |
| `site_unreachable` | the site could not be contacted | network/proxy/DNS; check `roots:` path prefix |
| `session_expired` | a cached session was rejected | call `login` with `force_refresh` |
| `unsupported_site` | no driver for that host | add `aliases:` or pass `site` |
| `host_not_allowed` | outside `security.allowed_hosts` | add the host if intended |
| `ddl_disabled` / `sql_check_failed` / `archery_error` | Archery tool refusals | see `MCP_TOOLS.md` |

Page-side messages (shown to the human): *Key fingerprint does not match* or *link is incomplete* mean the link
was altered or truncated; ask for a new login. *stale timestamp* means the device clock is off by more than two
minutes. *refused the submission (400…)* usually means the link belongs to an older round: use the newest message.

## 8. Not supported (yet)

GitLab reCAPTCHA after repeated failures; WebAuthn/passkey-only accounts; Jenkins 2FA plugins; any TOTP on Kibana
or KubeSphere (stock versions have none). These fail with an explanatory error rather than being guessed at.
