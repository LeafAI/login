# Roadmap: from a login helper to a shared authentication gateway

`login` started as a single-user MCP server over stdio: one agent, one person typing credentials.
The aim is a **unified authenticator gateway** that any AI agent can use through MCP. This page records
what is already in place and what is deliberately left for later, with the reasoning, so nobody has to
rediscover it.

## Done

| Area | What exists |
|---|---|
| Human-in-the-loop login | DingTalk link, static page, OpenPGP end to end, SSH tunnel providers, TOTP rounds, Reject with reason |
| Sites | gitlab, jenkins, kibana, kubesphere, nightingale, archery (1.x and REST), skywalking, plus YAML `generic` sites |
| Sessions | in-memory or encrypted-on-disk cache, probe before reuse, one flow per site (singleflight) |
| Guardrails | `security.allowed_hosts`, escaped agent text in messages, key rotation (<= 8 uses / 24 h) |
| Setup without YAML | `login config init`, `site add`, `site custom`, `set/get/unset/show` (validated, comments kept, backup) |
| Accountability | append-only JSON-lines audit log (metadata only, never secrets or SQL text) |
| Protecting people | per-site and overall request limits; cool-down after a Reject; `rate_limited` error |
| MCP surface | output schemas and titles on every tool, resources `login://sites|sessions|policy`, server instructions |
| Operations | `login version`, Dockerfile, CI build check, `login doctor` covers audit and limits |
| Transport hardening | one-shot tunnels (checked before use, closed with their process tree); AES-256-GCM seal under a per-round password; optional unlock (long-period TOTP) and sealing (30 s TOTP) factors |

## Planned (tracked, not started)

Each item names the problem, why it matters for a gateway, the proposed design and the first small step.
They are ordered by value; 1 and 2 are prerequisites for sharing one gateway between several agents.

### 1. Network transport

* **Problem.** Only stdio exists, so every agent needs its own `login` process and cannot reach a shared one.
* **Design.** `login serve -listen 127.0.0.1:8443` using MCP **Streamable HTTP** (the SDK ships
  `NewStreamableHTTPHandler`). MCP defines stdio and Streamable HTTP only; there is no MCP-over-gRPC, so a gRPC
  facade would be a separate, non-standard layer on top and is not planned unless a platform requires it.
  Bind to loopback by default; refuse a non-loopback address without TLS and authentication.
* **First step.** The `serve` subcommand with `/healthz`, graceful shutdown and the same tool set.

### 2. Caller identity and authorization

* **Problem.** Every connected agent may target any allowed host and use any cached session.
* **Design.** A `clients:` section: one bearer token per agent (stored hashed), each with its own
  `allowed_hosts`, tool allow-list and limits. The audit log already has a `client` field to carry the identity.
* **First step.** Token check in the HTTP transport (depends on 1).

### 3. Session isolation

* **Problem.** The cache key is the site, so two agents share one login.
* **Design.** Key the cache by `(principal, site)`; an explicit `shared: true` policy per site keeps today's behaviour.
* **First step.** Add the principal to the cache key; default to a single anonymous principal so stdio is unchanged.

### 4. The agent should not hold plaintext credentials

* **Problem.** `login` returns raw cookies and tokens, so they enter the agent's context and can be leaked
  by a prompt-injected agent. This is the largest remaining security gap.
* **Design.** A `login_request(url, method, headers, body)` tool: the gateway makes the call with the cached
  session and returns the response, so the agent never sees a secret. `login` becomes redacted by default;
  returning secrets needs an explicit `reveal: true` that policy must allow. Re-login on 401 behind the scenes.
* **First step.** `login_request` limited to GET and to hosts in `allowed_hosts`.

### 5. Token renewal

* **Problem.** KubeSphere and Nightingale return a `refresh_token` that is never used, so every expiry
  bothers a person again.
* **Design.** An optional `Refresh` step on the driver interface, called by the cache when a session is
  near expiry or fails its probe, before asking a human.
* **First step.** KubeSphere (`grant_type=refresh_token`).

### 6. More authentication methods

* **Problem.** Only form and JSON logins exist. Static API keys, Basic auth, OAuth2 client credentials and
  OIDC/CAS single sign-on are common in internal tools.
* **Design.** Extend the `generic` driver with `auth: basic | api_key | oauth2_client`, and a small secret
  store so non-human credentials are never in `config.yaml`.
* **First step.** `api_key` and `basic` in the generic driver.
