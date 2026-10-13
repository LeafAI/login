# securl — MCP tool schemas

Status: **implemented** (companion to `DESIGN.md`). Schemas are JSON Schema (draft 2020-12);
in Go they are generated from tagged structs by the MCP SDK, so these definitions are the source
for `internal/mcpserver/types.go`.

## 0. Conventions

**Tools (15)**

| Tool | Purpose | Blocks? |
|---|---|---|
| `vault_status` | is the vault open, and are wrong passphrases being slowed down | no |
| `vault_unlock` | ask the user to open the vault (they type the passphrase on a page; the agent never sees it) | up to `max_block_seconds` |
| `request` | send an HTTP request with the session's credentials; they never reach the agent | up to `timeout_seconds` |
| `session_open` | open a session on a website; a person types the credential once (no credential is returned) | up to `max_block_seconds` |
| `session_wait` | keep waiting for a session that is being opened | up to `max_block_seconds` |
| `site_list` | list supported sites/drivers | no |
| `session_list` | list sessions (no secrets) | no |
| `session_close` | forget session(s) | no |
| `archery_instances` | list instances/databases the user can use | no |
| `archery_groups` | list resource groups (and a group's writable instances) | no |
| `archery_query` | read-only SQL query (no approval) | no |
| `archery_run_sql` | submit -> approval -> execute -> result, as one sync call | up to `max_block_seconds` |
| `archery_wait` | resume a pending workflow (idempotent) | up to `max_block_seconds` |
| `archery_workflow_status` | read a workflow's state | no |
| `archery_cancel` | abort a workflow | no |

(`archery_submit_sql` is intentionally omitted: `archery_run_sql` with `wait: false` covers it.)

**Blocking and client timeouts.** Many MCP clients abort a tool call after 30-120 s, but a human may
take minutes. So every blocking tool:
- waits at most `max_block_seconds` (default 50, config `mcp.max_block_seconds`, 1-600);
- sends MCP `notifications/progress` every 5 s while waiting (resets client timeouts that honour it) and
  `notifications/message` for milestones ("DingTalk sent", "waiting for TOTP", "waiting for approval");
- if still unfinished, returns a **pending** result (not an error) containing an id (`login_id` /
  `workflow_id`) and `next_tool`; the agent calls `session_wait` / `vault_unlock` / `archery_wait` with that id.
  Waiting never restarts the flow and never re-notifies the human.

**Result shape.** Success and pending are normal results (`isError: false`) with `structuredContent`
matching the output schema plus a short text summary. Failures are `isError: true` with
`structuredContent` = `Error` (below). Secret values appear only in `session_open`/`session_wait` output.

```jsonc
// Error
{ "code": "string", "message": "string", "retryable": false, "hint": "string?" }
```
Codes: `invalid_argument`, `unsupported_site`, `human_timeout` (nobody completed a round before the TTL),
`host_not_allowed` (the URL's host is outside `security.allowed_hosts`, or is one of this machine's own addresses and `security.allow_local_addresses` is off),
`user_rejected` (the human pressed Reject on the page; `message` carries their optional reason, not retryable),
`rate_limited` (too many requests to people, or the site was just rejected; `retryable`, carries a hint not to loop),
`bad_credentials`, `login_rejected` (site refused, e.g. account locked / captcha), `tunnel_unavailable`,
`notify_failed` (DingTalk), `site_unreachable`, `ddl_disabled`, `sql_check_failed`, `archery_error`,
`workflow_not_found`, `session_expired` (a cached session was rejected by the site; call `session_open` with `force_refresh`), `internal`.

**Output schemas and titles.** Every tool advertises a human-readable `title` and an `outputSchema` (generated
from the Go result types, so they cannot drift). The schemas list the fields of both the success and the
pending answer; no field is `required`, because one result type serves both. A tool that fails returns
`isError: true` with the `Error` object above, which is not part of `outputSchema`.

**Resources** (read-only, JSON, never contain secrets):

| URI | Content |
|---|---|
| `securl://sites` | same as `site_list` |
| `securl://sessions` | same as `session_list` |
| `securl://policy` | `allowed_hosts`, `local_addresses_allowed`, `max_block_seconds`, `limits` (per site / total / window / reject cool-down), `archery_ddl_allowed`, `archery_requests_allowed`, `audit_enabled`, `human_step_ttl_seconds`, `link_unlock_required`, `sealing_code_required` (which TOTP factors the person is asked for; never a secret or a code) |

**Server instructions.** At connect time the server tells the model how to use the tools: open the vault with `vault_unlock` when it is locked, call `session_open`, on
`pending` call `session_wait` (never `session_open` again), what to do for each error code, treat cookies as secrets.

**Annotations** (MCP tool hints): `session_open`/`session_wait`/`vault_unlock`: `openWorldHint: true`; `site_list`/`session_list`/`vault_status`/
`archery_instances`/`archery_groups`/`archery_query`/`archery_workflow_status`: `readOnlyHint: true`;
`archery_run_sql`: `destructiveHint: true`; `archery_wait`/`session_wait`: `idempotentHint: true`.

## 0a. `vault_status`

Input: `{}`. Output: no secrets, ever. Needs no unlock.
```jsonc
{ "state": "not_initialized" | "locked" | "unlocked",
  "unlock_pending": true,          // a person has been asked and has not answered yet
  "failed_attempts": 3,            // wrong passphrases since the last success (omitted when 0)
  "retry_after_seconds": 120 }     // present while wrong passphrases are being slowed down
```

## 0b. `vault_unlock`

Ask the user to open the vault. Every tool that touches a site or a credential answers `vault_locked` until it is open.
The person receives a DingTalk link, compares the key code, and types the vault passphrase on that page; it is sealed in
the browser with the round's one-shot password before it leaves. **No tool takes a passphrase**: an extra argument is
refused (`invalid_argument`), so a prompt-injected agent cannot be made to pass one through.

Input: `{ "reason": string? (max 200), "unlock_id": string?, "max_block_seconds": integer? }`

Output
```jsonc
{ "status":"unlocked", "already_unlocked":true }                      // nothing was asked: it was already open
{ "status":"unlocked" }                                               // the person typed the right passphrase
{ "status":"pending", "login_id":"lg_...", "waiting_for":"vault passphrase",
  "expires_at":"...", "next_tool":"vault_unlock" }                    // call again with unlock_id = login_id
```
A call without `unlock_id` while a link is out joins that unlock instead of sending a second link. Errors:
`vault_not_initialized` (run `securl vault init`), `rate_limited` (wrong passphrases are slowed: 3 free attempts, then
30 s doubling to 15 min; the same counter serves every route), `user_rejected`, `human_timeout`, `notify_failed`,
`tunnel_unavailable`, `bad_credentials` (five wrong passphrases in one request), `vault_locked` (the passphrase was
right but the server could not open: a TOTP factor is on and its secret is missing; the message says how to fix it).

## 1. `session_open`

Open a session on a website. May ask the human (DingTalk) for one or more rounds (e.g. the `login` step, then `totp`).
The agent never sees the password.

Input
```jsonc
{ "type":"object", "required":["url"], "additionalProperties":false, "properties":{
  "url":   {"type":"string","format":"uri","description":"Any URL on the site; scheme+host(+port) identify the site."},
  "site":  {"type":"string","description":"Driver name (see site_list). Auto-detected from the URL when omitted."},
  "reason":{"type":"string","maxLength":200,"description":"Why the agent needs access; shown to the human in DingTalk."},
  "force_refresh":{"type":"boolean","default":false,"description":"Skip the cached session and log in again."},
  "wait":  {"type":"boolean","default":true,"description":"false: return `pending` immediately after notifying the human."},
  "max_block_seconds":{"type":"integer","minimum":1,"maximum":600,"description":"Override the default blocking time."} } }
```

Output (`oneOf` by `status`)
```jsonc
// status = "ok"
{ "status":"ok", "site":"gitlab", "base_url":"https://gitlab.corp.example",
  "auth":"cookie" | "bearer" | "none",           // what the site uses
  "cached":false,                                 // true = reused without asking the human
  "expires_at":"2026-10-11T08:00:00Z" }           // omitted when unknown

// status = "pending"
{ "status":"pending", "login_id":"lg_3f9a...", "site":"gitlab",
  "waiting_for":"login" | "totp" | "custom",      // the current round
  "round":1, "expires_at":"2026-10-10T08:10:00Z", // when the human link stops working
  "next_tool":"session_wait" }
```
**No result carries a credential, for any site.** The result says that a session exists, for which site, how the site
authenticates (`auth`) and until when. The cookies, tokens and headers stay in the vault; the `request` tool (and the
`archery_*` tools) put them into each request and remove them from the answer.

Notes: `cached` hits are validated with the driver's `Probe` first. Concurrent calls for the same site
share one flow (same `login_id`).

## 1a. `request`

Send an HTTP request to a site that has a session. The gateway puts the session's cookies and tokens into the request and
removes them from the answer, so the agent neither sends nor receives a credential. It never opens a session by itself:
without one it answers `no_session` (asking a person is `session_open`'s job). A site that needs no login at all (SkyWalking)
has no session to look for: the request goes out as it is, with no credential added.

**Archery is refused** (`request_not_allowed`) unless the owner sets `security.allow_archery_requests: true`. A change on
Archery needs a person's approval, a DDL check, a notification and counts against the limits; the `archery_*` tools do
all of that, and a raw request would post or approve a workflow without any of it. Archery is recognised by the driver
the session was opened with, by the configured alias and by the host name, so choosing another `site` in `session_open`
does not get around it. The switch is the owner's: the agent cannot set it, and `securl://policy` shows it as
`archery_requests_allowed`.

Input
```jsonc
{ "type":"object", "required":["url","method","path"], "additionalProperties":false, "properties":{
  "url":    {"type":"string","description":"Any URL on the site; scheme+host(+port) identify it."},
  "method": {"type":"string","description":"GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS."},
  "path":   {"type":"string","description":"Absolute path starting with /. No query, no host, no fragment, no .. segment."},
  "query":  {"type":"object","description":"Each name maps to a string or a list of strings."},
  "headers":{"type":"object","description":"Ordinary headers. Cookie, Authorization, Host, Content-Length, Transfer-Encoding, Connection, Upgrade, TE, Expect, Accept-Encoding, Trailer, Keep-Alive and any header the session itself sets are refused."},
  "json":   {"description":"A JSON body (any JSON value; large integers keep their exact text)."},
  "form":   {"type":"object","description":"A form-encoded body."},
  "text":   {"type":"string"}, "base64": {"type":"string","description":"A binary body, standard base64."},
  "follow_redirects":{"type":"boolean","default":false},
  "timeout_seconds":{"type":"integer","maximum":120,"description":"Default 25."},
  "max_response_bytes":{"type":"integer","maximum":1048576,"description":"Default 262144."} } }
```
At most one of `json`, `form`, `text`, `base64`; none with GET/HEAD. There is deliberately no field for a cookie, token or
authorization header.

Output
```jsonc
{ "status":200, "headers":{ "Content-Type":["application/json"] },
  "body":"...", "body_is_base64":false,
  "truncated":false, "total_bytes":1234,       // the real size of the answer, even when the body was cut
  "redactions":2,                               // credential values removed from the headers and the body
  "withheld":false,                             // true: a binary body held a credential and is not returned
  "final_path":"/new",                          // where the request ended (after followed redirects)
  "hint":"..." }                                // on 401: how to get a new session
```
What is removed: every value of the session (cookies, the `Authorization` header and the token after its scheme, CSRF
and other session headers, tokens other than driver state) and of any cookie the site rotates during the request, in
the encodings a server repeats them in (raw, lower/upper case, URL, double URL, percent-all, HTML, JSON incl. `\/` and
`\uXXXX`, base64 four ways, hex), plus anything shaped like a bearer token, an `access_token`-style JSON key, a
`token=` query parameter or a `Cookie:` line. `Set-Cookie`, `Authorization`, `Proxy-Authorization` are dropped from the
headers. A cookie the site rotates is kept for the next call (and stored in the vault); it is never shown.
**Limits, stated plainly:** this is a safety net. A server that transforms a value in a way not listed can still echo
it; the layers that do not depend on the scrubber are that the agent cannot send credentials, can only reach the
session's own site (an absolute path on that origin), and never follows a redirect off the site or down from https.

Errors: `vault_locked`/`vault_not_initialized`, `no_session`, `host_not_allowed`, `request_not_allowed` (Archery, see above), `invalid_argument` (the refusals above,
before anything is sent), `session_expired`, `site_unreachable` (the message never contains the URL or a credential).
Each call is audited as `request`: method, path (never the query), status, size, host.

## 2. `session_wait`

Input: `{ "login_id": string (required), "max_block_seconds": integer? }`
Output: same as `session_open` (`ok` | `pending`). Unknown/expired id -> error `invalid_argument`
("login_id not found; call session_open again").

## 3. `site_list`

Input: `{}` (no properties).
Output
```jsonc
{ "sites":[ { "name":"gitlab", "auth":"cookie", "needs_login":true,
              "rounds":["login","totp?"],            // "?" = only if the account has it
              "match":"URL path/host hints, e.g. contains 'gitlab'",
              "source":"builtin" | "config" } ] }
```
Includes sites defined through the YAML `generic` driver.

## 4. `session_list`

Input: `{}`. Output: no secrets, ever.
```jsonc
{ "sessions":[ { "site":"gitlab","base_url":"https://gitlab.corp.example","auth":"cookie",
                 "obtained_at":"...","expires_at":"...","last_validated_at":"..." } ] }
```

## 5. `session_close`

Input: `{ "url": string?, "all": boolean? }` — exactly one of the two (`oneOf`).
Output: `{ "removed": integer }`. Only forgets the local cache (and cancels a pending flow for that
site); it does not log out on the server unless the driver supports it (`server_logout: bool` in output).

## 6. `archery_instances`

Input: `{ "url": uri (required), "site": string?, "instance": string? }` (login performed implicitly; with `instance`, that instance's `databases` are listed too).
Output
```jsonc
{ "instances":[ { "name":"prod-mysql-01","type":"master","db_type":"mysql" } ],
  "databases":["orders","users"],                 // only when `instance` was given
  "login": { ...pending login... } }              // only when a human login is still pending
```

## 6a. `archery_groups`

Lists the resource groups the user may submit SQL to, so an agent can fill `resource_group` of
`archery_run_sql` without ever handling a session credential. Names only; Archery's internal ids are not exposed.

Input: `{ "url": uri (required), "site": string?, "group": string? }` (with `group`, that group's instances that
accept changes are listed too; an unknown group answers `archery_error` listing the available names).
Output
```jsonc
{ "groups":["dba","dev"],
  "writable_instances":[ { "id":7,"name":"prod","db_type":"mysql" } ],   // only when `group` was given
  "login": { ...pending login... } }                                       // only when a human login is still pending
```

## 7. `archery_query`

Read-only query using Archery's query endpoint (needs query privilege; no approval).
Input
```jsonc
{ "type":"object","required":["url","instance","database","sql"],"additionalProperties":false,"properties":{
  "url":{"type":"string","format":"uri"},
  "instance":{"type":"string","description":"Archery instance name."},
  "database":{"type":"string"},
  "schema":{"type":"string","description":"Schema for PostgreSQL/Oracle-style instances."},
  "sql":{"type":"string","description":"A single SELECT/SHOW/DESC/EXPLAIN statement."},
  "limit":{"type":"integer","minimum":1,"maximum":10000,"default":100} } }
```
Output
```jsonc
{ "columns":["id","name"], "rows":[[1,"a"]], "row_count":1, "truncated":false,
  "cost_ms":12, "warnings":[ "masked columns: phone" ] }
```
Non-read statements are rejected client-side with `invalid_argument` ("use archery_run_sql").

## 8. `archery_run_sql`

Turns Archery's asynchronous approval into one synchronous call:
check -> submit workflow -> notify approvers (DingTalk) -> wait for approval -> execute ->
return result. Execution is **automatic** after approval. DDL is allowed unless
`archery.allow_ddl: false` (then `ddl_disabled`; the check is a SQL scanner, so comments, several statements and
`/*!…*/` executable comments do not get around it, and `PREPARE`/`EXECUTE` are refused too). The approval message
shows the first 500 characters of the SQL; when there is more it says so, with the full length, and every message
carries a sha256 prefix to match against the statement in Archery.

Input
```jsonc
{ "type":"object","required":["url","instance","database","sql","title"],"additionalProperties":false,"properties":{
  "url":{"type":"string","format":"uri"},
  "instance":{"type":"string"}, "database":{"type":"string"}, "schema":{"type":"string"},
  "sql":{"type":"string","description":"One or more statements."},
  "title":{"type":"string","maxLength":50,"description":"Workflow name shown to approvers."},
  "remark":{"type":"string","description":"Business reason; shown to approvers."},
  "resource_group":{"type":"string","description":"Archery resource group; default = the user's only/first group."},
  "backup":{"type":"boolean","default":true,"description":"Ask Archery to take a rollback backup when supported."},
  "wait":{"type":"boolean","default":true,"description":"false: return `pending` right after submitting."},
  "max_block_seconds":{"type":"integer","minimum":1,"maximum":600},
  "approval_timeout_seconds":{"type":"integer","minimum":60,"default":1800,"description":"Give up (workflow aborted) if nobody approves in time."} } }
```
Output (`oneOf` by `status`)
```jsonc
// status = "done" | "failed"
{ "status":"done", "workflow_id":123, "workflow_url":"https://archery/detail/123/",
  "results":[ { "sequence":1,"sql":"UPDATE ...","state":"success"|"error"|"warning",
                "affected_rows":3,"error":"","execute_ms":8,"backup_id":"..." } ],
  "approver":"zhangsan","approved_at":"...","executed_at":"..." }

// status = "pending"  (still waiting for a person or still executing)
{ "status":"pending", "phase":"checking"|"awaiting_approval"|"executing",
  "workflow_id":123, "workflow_url":"...", "check":[ {"sequence":1,"level":"warning","message":"..."} ],
  "next_tool":"archery_wait" }

// status = "aborted"  (rejected or cancelled in Archery, or approval timed out and we cancelled it)
{ "status":"aborted","workflow_id":123,"reason":"..." }

// status = "pending", phase = "login"  (the Archery login itself still waits for the human)
{ "status":"pending","phase":"login","login_id":"lg_...","next_tool":"session_wait" }
```
Pre-submit check findings of level `error` abort with `sql_check_failed` (the `check` list is in the
error `hint`/structured data); `warning` is submitted and reported.

## 9. `archery_wait`

Input: `{ "workflow_id": integer (required), "url": uri (required), "max_block_seconds": integer? }`.
Behaviour: if awaiting approval, waits; once approved, executes **once** (guarded by workflow status
and a local lock) and returns the `archery_run_sql` output shape. Safe to call repeatedly or after a
restart; an already-executed workflow just returns its result.

## 10. `archery_workflow_status`

Input: `{ "workflow_id": integer, "url": uri }` (both required).
Output
```jsonc
{ "workflow_id":123,"title":"...","status":"awaiting_approval"|"approved"|"executing"|"done"|"failed"|"aborted"|"check_failed",
  "status_text":"<Archery's own wording>","submitter":"...","instance":"...","database":"...",
  "created_at":"...","review_history":[ {"stage":"...","by":"...","result":"...","at":"..."} ],
  "results":[ ... ]  /* same item shape as archery_run_sql, when executed */ }
```

## 11. `archery_cancel`

Input: `{ "workflow_id": integer, "url": uri, "reason": string? }`. Output: `{ "status": "aborted" }`.
Refuses if already executing/executed (`invalid_argument`).

## 12. Human-facing side effects (summary)

| Tool | DingTalk message |
|---|---|
| `session_open` / `session_wait` | one per round: site, `reason`, round link, key fingerprint, expiry |
| `archery_run_sql` | one after submit: title, instance/db, SQL summary (first 500 chars), Archery workflow link — to the same robot (approval itself happens in Archery) |
| others | none |

## 13. Notes

- `resource_group` is required by Archery's submit; set `archery.default_group` in the config to omit it per call.
- `archery_workflow_status` pages through the 200 most recent workflows visible to the user.
- The Archery endpoints are exercised against a fake server only; see the README's verification section.

## 14. Archery (as implemented)

Two Archery generations are supported and detected at login (the session records which one it found):
**1.x** (verified against v1.12.0: `/query/`, `/execute/`, `/cancel/`, `/getWorkflowStatus/`, `/workflow/log/`,
`POST /api/v1/workflow/` to submit) and the **newer REST API** (`/api/v1/sqlquery/…`,
`/api/v1/sql-workflows/<audit_id>/…`, verified against master). Every Archery tool addresses a workflow by
its **`workflow_id`** (the number in `/detail/<id>/`); the REST generation additionally reports an `audit_id`,
which the server maps internally.

`resource_group` is the group **name**; the instance must be writable in that group (Archery's `can_write`
tag). An aborted workflow is reported as `rejected` (with `by` and the approver's reason, taken from the
workflow log) or `aborted` (cancelled, or the approval timed out). `archery_run_sql` has no `schema` argument
(Archery's submit API does not take one). On Archery 1.x, `/execute/` and `/cancel/` answer failures with an
HTML page rather than an error status; the client turns those pages into `archery_error`.

## 15. Decisions on the earlier open points

1. (agreed) `max_block_seconds` default 50 s is tuned for ~60 s client timeouts; make it larger if your MCP
   client allows longer calls. OK?
2. `session_open` carries no credential for any site; `request` is the only way to use one (decided, implemented).
3. Archery SQL > 500 chars: DingTalk shows a truncated preview only; full text is in the workflow link.
