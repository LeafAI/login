# login — MCP tool schemas

Status: **design draft** (companion to `DESIGN.md`). Schemas are JSON Schema (draft 2020-12);
in Go they are generated from tagged structs by the MCP SDK, so these definitions are the source
for `internal/mcpserver/types.go`.

## 0. Conventions

**Tools (11)**

| Tool | Purpose | Blocks? |
|---|---|---|
| `login` | get a valid cookie/token for a website | up to `max_block_seconds` |
| `login_wait` | resume a pending `login` | up to `max_block_seconds` |
| `login_sites` | list supported sites/drivers | no |
| `login_sessions` | list cached sessions (no secrets) | no |
| `logout` | drop cached session(s) | no |
| `archery_instances` | list instances/databases the user can use | no |
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
  `workflow_id`) and `next_tool`; the agent calls `login_wait` / `archery_wait` with that id.
  Waiting never restarts the flow and never re-notifies the human.

**Result shape.** Success and pending are normal results (`isError: false`) with `structuredContent`
matching the output schema plus a short text summary. Failures are `isError: true` with
`structuredContent` = `Error` (below). Secret values appear only in `login`/`login_wait` output.

```jsonc
// Error
{ "code": "string", "message": "string", "retryable": false, "hint": "string?" }
```
Codes: `invalid_argument`, `unsupported_site`, `human_timeout` (nobody completed a round before the TTL),
`host_not_allowed` (the URL's host is outside `security.allowed_hosts`),
`user_rejected` (the human pressed Reject on the page; `message` carries their optional reason, not retryable),
`bad_credentials`, `login_rejected` (site refused, e.g. account locked / captcha), `tunnel_unavailable`,
`notify_failed` (DingTalk), `site_unreachable`, `ddl_disabled`, `sql_check_failed`, `archery_error`,
`workflow_not_found`, `session_expired` (a cached session was rejected by the site; call `login` with `force_refresh`), `internal`.

**Annotations** (MCP tool hints): `login*`: `openWorldHint: true`; `login_sites`/`login_sessions`/
`archery_instances`/`archery_query`/`archery_workflow_status`: `readOnlyHint: true`;
`archery_run_sql`: `destructiveHint: true`; `archery_wait`/`login_wait`: `idempotentHint: true`.

**Shared definitions**

```jsonc
"Cookie": { "type":"object", "required":["name","value"], "properties":{
  "name":{"type":"string"}, "value":{"type":"string"},
  "domain":{"type":"string"}, "path":{"type":"string"},
  "expires":{"type":"string","format":"date-time"},
  "secure":{"type":"boolean"}, "http_only":{"type":"boolean"} } }
```

## 1. `login`

Log in to a website and return what is needed to call it. May ask the human (DingTalk) for
one or more rounds (e.g. `login`, then `totp`). The agent never sees the password.

Input
```jsonc
{ "type":"object", "required":["url"], "additionalProperties":false, "properties":{
  "url":   {"type":"string","format":"uri","description":"Any URL on the site; scheme+host(+port) identify the site."},
  "site":  {"type":"string","description":"Driver name (see login_sites). Auto-detected from the URL when omitted."},
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
  "cookie_header":"_gitlab_session=...; ...",     // ready for a Cookie request header; "" when none
  "cookies":[ Cookie ],
  "headers":{ "Authorization":"Bearer ..." },     // extra request headers to send (also X-CSRF etc.)
  "tokens":{ "access_token":"...", "refresh_token":"..." },   // raw values, driver specific
  "expires_at":"2026-10-11T08:00:00Z" }           // omitted when unknown

// status = "pending"
{ "status":"pending", "login_id":"lg_3f9a...", "site":"gitlab",
  "waiting_for":"login" | "totp" | "custom",      // the current round
  "round":1, "expires_at":"2026-10-10T08:10:00Z", // when the human link stops working
  "next_tool":"login_wait" }
```
Notes: `cached` hits are validated with the driver's `Probe` first. Concurrent calls for the same site
share one flow (same `login_id`).

## 2. `login_wait`

Input: `{ "login_id": string (required), "max_block_seconds": integer? }`
Output: same as `login` (`ok` | `pending`). Unknown/expired id -> error `invalid_argument`
("login_id not found; call login again").

## 3. `login_sites`

Input: `{}` (no properties).
Output
```jsonc
{ "sites":[ { "name":"gitlab", "auth":"cookie", "needs_login":true,
              "rounds":["login","totp?"],            // "?" = only if the account has it
              "match":"URL path/host hints, e.g. contains 'gitlab'",
              "source":"builtin" | "config" } ] }
```
Includes sites defined through the YAML `generic` driver.

## 4. `login_sessions`

Input: `{}`. Output: no secrets, ever.
```jsonc
{ "sessions":[ { "site":"gitlab","base_url":"https://gitlab.corp.example","auth":"cookie",
                 "obtained_at":"...","expires_at":"...","last_validated_at":"..." } ] }
```

## 5. `logout`

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
`archery.allow_ddl: false` (then `ddl_disabled`).

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
{ "status":"pending","phase":"login","login_id":"lg_...","next_tool":"login_wait" }
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
| `login` / `login_wait` | one per round: site, `reason`, round link, key fingerprint, expiry |
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
2. `login` output always includes raw secrets (by design). Add an opt-in `redact: true` that returns
   only `cookie_header` presence/metadata for dry runs? (Default stays unredacted.)
3. Archery SQL > 500 chars: DingTalk shows a truncated preview only; full text is in the workflow link.
