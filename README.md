# login

An MCP server that lets an AI agent obtain a valid cookie/token for sites that need a human to type
credentials (GitLab, Kibana, KubeSphere, Nightingale v7, Archery, SkyWalking, and any site you describe in YAML).
The agent never sees the password.

```
go install github.com/LeafAI/login@latest
claude mcp add login -- login          # or add "login" to any MCP client's server list
```

## How a login works

1. The agent calls `login(url)`. A valid cached session is reused (probed first).
2. `login` takes a key pair from a local pool (each key: ≤ 8 uses and ≤ 24 h), starts a one-shot JSON API on
   `127.0.0.1` and exposes it through an SSH reverse tunnel (pinggy, localhost.run, serveo, tunnl.gg, or your own).
3. A DingTalk robot message carries **one link** to a static login page. The link's `#fragment` holds the mode
   (`login`/`totp`), the tunnel API address and the **public key**; nothing in it reaches any server.
4. The human opens the link, types the credential; the page encrypts it (OpenPGP) to the key from the link and
   posts it to the API. The human can instead press **Reject** and give an optional reason — the agent receives
   `user_rejected` with that reason.
5. `login` decrypts it and runs the site's real login flow. If the site wants a second factor, the driver
   starts another round (a new link in DingTalk). The cookie/token is returned to the agent.

The static page is served by GitHub Pages (version-pinned) or from your disk (`login page [dir]`); the tunnel
carries only ciphertext. See `DESIGN.md` (architecture, threat model) and `MCP_TOOLS.md` (tool schemas).

## Configuration

`~/.config/login/config.yaml` (override with `-config`). Environment: `LOGIN_DINGTALK_WEBHOOK`,
`LOGIN_DINGTALK_SECRET`, `LOGIN_TUNNEL_ORDER`.

```yaml
dingtalk:
  webhook: https://oapi.dingtalk.com/robot/send?access_token=...
  secret: SEC...            # signing secret, if the robot uses "加签"
  keyword: login            # only if the robot requires a keyword
  at_mobiles: ["138..."]
tunnel:
  order: [pinggy, localhost.run, serveo, tunnl]   # ssh-j is TCP-only and is never used for the web API
  timeout: 20s
  providers:                                        # extra servers
    - name: mycorp
      command: ssh -R 0.0.0.0:{{port}}:localhost:{{port}} jump.corp.example
      url: https://jump.corp.example:{{port}}       # or url_regex to parse a printed URL
web:
  page_url: https://leafai.github.io/login/v0.1.0/  # or file:///path/to/login-page/index.html
  ttl: 10m                                          # per round
keys: {max_uses: 8, max_age: 24h}
mcp: {max_block_seconds: 50}
archery:
  allow_ddl: true            # false rejects CREATE/ALTER/DROP/TRUNCATE/RENAME
  default_group: dba         # Archery resource group when a call gives none
  wait_timeout: 30m          # default approval timeout
sites:                       # any other website, no Go needed
  - name: grafana
    match_host: grafana
    steps: [{method: POST, path: /login, json: {user: "{{username}}", password: "{{password}}"}}]
    twofa: {detect_body: otp_required, step: {method: POST, path: /login/otp, form: {code: "{{code}}"}}}
    collect: {tokens: {access: data.token}, headers: {Authorization: "Bearer {{token:access}}"}}
    probe: {path: /api/user}
```

## Tools

`login`, `login_wait`, `login_sites`, `login_sessions`, `logout`, `archery_instances`, `archery_query`,
`archery_run_sql`, `archery_wait`, `archery_workflow_status`, `archery_cancel`.
Long operations return a `pending` result with an id after `max_block_seconds`; resume with `login_wait` /
`archery_wait`.

## Testing

`go test ./...` — unit tests, fake-site driver tests, and (when Node + Playwright + Chromium exist) browser
end-to-end tests that drive the real page through the full MCP → DingTalk → tunnel → decrypt → login path.

## What has and has not been verified

Verified in automated tests: key rotation, PGP round trip between openpgp.js and Go, round API validation,
tunnel banner parsing and fallback (with a fake `ssh`), DingTalk signing, the full login/2FA/reject flow in a
real browser, and every site driver against *fake* servers that imitate the flows.
**Not verified against live systems:** the real SSH providers, a real DingTalk robot, and the live
GitLab/Kibana/KubeSphere/Nightingale/Archery endpoints. In particular the Archery 2FA and workflow-list/result
endpoints, and the second-factor handling of Kibana/KubeSphere/Nightingale (stock versions of these have no
TOTP), are best-effort and need a live check.
