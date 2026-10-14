package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/LeafAI/securl/internal/site/archery"
)

// ToolError is the structured payload of a failed tool call.
type ToolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	Hint      string `json:"hint,omitempty"`
}

func (e *ToolError) Error() string { return e.Code + ": " + e.Message }

func errf(code string, retryable bool, format string, a ...any) *ToolError {
	return &ToolError{Code: code, Message: sprintf(format, a...), Retryable: retryable}
}

type LoginInput struct {
	URL             string `json:"url" jsonschema:"Any URL on the site; scheme+host identify the site."`
	Site            string `json:"site,omitempty" jsonschema:"Driver name (see site_list). Auto-detected from the URL when omitted."`
	Reason          string `json:"reason,omitempty" jsonschema:"Why the agent needs access; shown to the human in DingTalk."`
	ForceRefresh    bool   `json:"force_refresh,omitempty" jsonschema:"Skip the cached session and log in again."`
	Wait            *bool  `json:"wait,omitempty" jsonschema:"false: return pending immediately after notifying the human. Default true."`
	MaxBlockSeconds int    `json:"max_block_seconds,omitempty" jsonschema:"Override the default blocking time (1-600)."`
}

type LoginWaitInput struct {
	LoginID         string `json:"login_id" jsonschema:"The login_id returned by a pending login."`
	MaxBlockSeconds int    `json:"max_block_seconds,omitempty"`
}

// LoginOutput is the state of a session being opened. It says that a session exists, for which site and until when; it
// carries nothing that could be used to act as the person. The credentials stay in the vault and are used by the request
// tool, which puts them into each request and removes them from the answer.
type LoginOutput struct {
	Status     string `json:"status"` // ok | pending
	Site       string `json:"site,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	Auth       string `json:"auth,omitempty"` // cookie | bearer | none: how the site authenticates, not with what
	Cached     bool   `json:"cached,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LoginID    string `json:"login_id,omitempty"`
	WaitingFor string `json:"waiting_for,omitempty"`
	Round      int    `json:"round,omitempty"`
	NextTool   string `json:"next_tool,omitempty"`
}

// RequestInput is what an agent may ask for. There is deliberately no field for a cookie, a token or an
// authorization header: the gateway puts the session's credentials into the request itself.
type RequestInput struct {
	URL              string                `json:"url" jsonschema:"Any URL on the site; scheme+host(+port) identify it. The session for that site is used."`
	Method           string                `json:"method" jsonschema:"GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS."`
	Path             string                `json:"path" jsonschema:"Absolute path on the site, starting with /. No query string and no host: use the query field."`
	Query            map[string]multiValue `json:"query,omitempty" jsonschema:"Query parameters. Each name maps to a string, or a list of strings for a repeated parameter."`
	Headers          map[string]string     `json:"headers,omitempty" jsonschema:"Ordinary request headers (Accept, X-Request-Id, ...). Cookie, Authorization, Host and the session's own headers are set by the gateway and refused here."`
	JSON             json.RawMessage       `json:"json,omitempty" jsonschema:"A JSON request body (any JSON value)."`
	Form             map[string]multiValue `json:"form,omitempty" jsonschema:"A form-encoded request body. Each name maps to a string, or a list of strings."`
	Text             string                `json:"text,omitempty" jsonschema:"A plain-text request body."`
	Base64           string                `json:"base64,omitempty" jsonschema:"A binary request body, standard base64."`
	FollowRedirects  bool                  `json:"follow_redirects,omitempty" jsonschema:"Follow redirects that stay on the same site. Default false: the redirect is returned."`
	TimeoutSeconds   int                   `json:"timeout_seconds,omitempty" jsonschema:"Give up after this many seconds (default 25, at most 120)."`
	MaxResponseBytes int                   `json:"max_response_bytes,omitempty" jsonschema:"Return at most this much of the body (default 262144, at most 1048576)."`
}

// RequestOutput is the site's answer with every credential removed. It never carries a cookie, a token or a Set-Cookie.
type RequestOutput struct {
	Status       int                 `json:"status"`
	Headers      map[string][]string `json:"headers,omitempty"`
	Body         string              `json:"body,omitempty"`
	BodyIsBase64 bool                `json:"body_is_base64,omitempty"`
	Truncated    bool                `json:"truncated,omitempty"`
	TotalBytes   int                 `json:"total_bytes,omitempty"`
	Redactions   int                 `json:"redactions"`
	Withheld     bool                `json:"withheld,omitempty"`
	FinalPath    string              `json:"final_path,omitempty"`
	Hint         string              `json:"hint,omitempty"`
}

// VaultUnlockInput asks for the vault to be opened by its owner.
type VaultUnlockInput struct {
	Reason          string `json:"reason,omitempty" jsonschema:"Why the agent needs the vault open; shown to the person who is asked for the passphrase."`
	UnlockID        string `json:"unlock_id,omitempty" jsonschema:"The unlock_id of a pending unlock, to keep waiting for it. Leave empty to start one."`
	MaxBlockSeconds int    `json:"max_block_seconds,omitempty" jsonschema:"Override the default blocking time (1-600)."`
}

// VaultUnlockOutput is the state of an unlock. It never carries the passphrase or anything derived from it.
type VaultUnlockOutput struct {
	Status          string `json:"status"` // unlocked | pending
	AlreadyUnlocked bool   `json:"already_unlocked,omitempty"`
	LoginID         string `json:"login_id,omitempty"` // the unlock_id to pass to the next call
	WaitingFor      string `json:"waiting_for,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	NextTool        string `json:"next_tool,omitempty"`
}

// VaultStatusOutput says whether the vault is open and, when unlock attempts are being slowed, for how long.
type VaultStatusOutput struct {
	State          string `json:"state"` // not_initialized | locked | unlocked
	UnlockPending  bool   `json:"unlock_pending,omitempty"`
	FailedAttempts int    `json:"failed_attempts,omitempty"`
	RetryAfterSecs int    `json:"retry_after_seconds,omitempty"`
}

type Empty struct{}

type SiteInfo struct {
	Name       string   `json:"name"`
	Auth       string   `json:"auth"`
	NeedsLogin bool     `json:"needs_login"`
	Rounds     []string `json:"rounds"`
	Match      string   `json:"match"`
	Source     string   `json:"source"`
}

type SitesOutput struct {
	Sites []SiteInfo `json:"sites"`
}

type SessionInfo struct {
	Site            string `json:"site"`
	BaseURL         string `json:"base_url"`
	Auth            string `json:"auth"`
	ObtainedAt      string `json:"obtained_at"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	LastValidatedAt string `json:"last_validated_at"`
}

type SessionsOutput struct {
	Sessions []SessionInfo `json:"sessions"`
}

type LogoutInput struct {
	URL string `json:"url,omitempty"`
	All bool   `json:"all,omitempty"`
}

type LogoutOutput struct {
	Removed int `json:"removed"`
}

// Archery

type ArcheryURL struct {
	URL  string `json:"url" jsonschema:"Archery base URL."`
	Site string `json:"site,omitempty"`
}

type InstancesInput struct {
	ArcheryURL
	Instance string `json:"instance,omitempty" jsonschema:"When given, also list this instance's databases."`
}

type InstancesOutput struct {
	Instances []archery.Instance `json:"instances,omitempty"`
	Databases []string           `json:"databases,omitempty"`
	Pending   *LoginOutput       `json:"login,omitempty"`
}

type GroupsInput struct {
	ArcheryURL
	Group string `json:"group,omitempty" jsonschema:"When given, also list the instances of this resource group that accept changes."`
}

// GroupsOutput lists resource-group names only: ids are Archery internals the agent never needs.
type GroupsOutput struct {
	Groups    []string           `json:"groups,omitempty"`
	Instances []archery.Instance `json:"writable_instances,omitempty"`
	Pending   *LoginOutput       `json:"login,omitempty"`
}

type QueryInput struct {
	ArcheryURL
	Instance string `json:"instance"`
	Database string `json:"database"`
	Schema   string `json:"schema,omitempty"`
	SQL      string `json:"sql" jsonschema:"A single SELECT/SHOW/DESC/EXPLAIN statement."`
	Limit    int    `json:"limit,omitempty"`
}

type QueryOutput struct {
	*archery.QueryResult
	Login *LoginOutput `json:"login,omitempty"`
}

type RunSQLInput struct {
	ArcheryURL
	Instance        string `json:"instance"`
	Database        string `json:"database"`
	SQL             string `json:"sql"`
	Title           string `json:"title" jsonschema:"Workflow name shown to approvers (max 50 chars)."`
	Remark          string `json:"remark,omitempty"`
	ResourceGroup   string `json:"resource_group,omitempty" jsonschema:"Archery resource group name; defaults to archery.default_group."`
	Backup          *bool  `json:"backup,omitempty"`
	Wait            *bool  `json:"wait,omitempty"`
	MaxBlockSeconds int    `json:"max_block_seconds,omitempty"`
	ApprovalTimeout int    `json:"approval_timeout_seconds,omitempty"`
}

type WaitInput struct {
	ArcheryURL
	WorkflowID      int `json:"workflow_id" jsonschema:"The workflow_id returned by archery_run_sql."`
	MaxBlockSeconds int `json:"max_block_seconds,omitempty"`
}

type ArcheryOut struct {
	archery.Outcome
	NextTool string `json:"next_tool,omitempty"`
	LoginID  string `json:"login_id,omitempty"`
}

type StatusInput struct {
	ArcheryURL
	WorkflowID int `json:"workflow_id"`
}

type StatusOutput struct {
	WorkflowID  int                 `json:"workflow_id"`
	Status      string              `json:"status"`      // awaiting_approval | approved | executing | done | failed | aborted | check_failed
	StatusCode  string              `json:"status_code"` // Archery's own workflow status
	WorkflowURL string              `json:"workflow_url"`
	Results     []archery.ResultRow `json:"results,omitempty"`
}

type CancelInput struct {
	ArcheryURL
	WorkflowID int    `json:"workflow_id"`
	Reason     string `json:"reason,omitempty"`
}

type CancelOutput struct {
	Status string `json:"status"`
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// multiValue is one value or several: {"q":"a"} and {"q":["a","b"]} both mean what they say. Numbers and booleans are
// taken as their text, exactly as written (an id of 12345678901234567890 stays that).
type multiValue []string

func (m *multiValue) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}
	one := func(x any) (string, error) {
		switch t := x.(type) {
		case string:
			return t, nil
		case json.Number:
			return t.String(), nil
		case bool:
			return strconv.FormatBool(t), nil
		}
		return "", fmt.Errorf("a value must be a string, a number or a boolean")
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			s, err := one(x)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		*m = out
	default:
		s, err := one(v)
		if err != nil {
			return err
		}
		*m = multiValue{s}
	}
	return nil
}

// multiValueSchema tells a model what is accepted: a string, a number or a boolean, or a list of those.
func multiValueSchema() *jsonschema.Schema {
	scalar := []*jsonschema.Schema{{Type: "string"}, {Type: "number"}, {Type: "boolean"}}
	return &jsonschema.Schema{AnyOf: append(append([]*jsonschema.Schema{}, scalar...), &jsonschema.Schema{Type: "array", Items: &jsonschema.Schema{AnyOf: scalar}})}
}

func (m multiValue) values() []string { return []string(m) }

func multiValues(in map[string]multiValue) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = v.values()
	}
	return out
}

// Databases

// DBTargetInfo describes one database target. It never carries a host, a port or an account: the owner's configuration
// holds those, and the agent has no use for them.
type DBTargetInfo struct {
	Name           string   `json:"name"`
	Driver         string   `json:"driver"`
	Environment    string   `json:"environment"`
	Mode           string   `json:"mode"`
	AllowDDL       bool     `json:"allow_ddl"`
	Databases      []string `json:"databases,omitempty"`
	MaxRows        int      `json:"max_rows"`
	MaxChangedRows int      `json:"max_changed_rows"`
	HasSession     bool     `json:"has_session"`
}

type DBTargetsOutput struct {
	Targets []DBTargetInfo `json:"targets"`
}

type DBQueryInput struct {
	Target   string `json:"target" jsonschema:"A target name from db_targets."`
	Database string `json:"database,omitempty" jsonschema:"The database to use. Optional when the target lists exactly one."`
	SQL      string `json:"sql" jsonschema:"A single read-only statement: SELECT, SHOW, EXPLAIN, DESCRIBE, WITH ... SELECT."`
	Limit    int    `json:"limit,omitempty" jsonschema:"At most this many rows (default 1000; the target sets a ceiling)."`
}

type DBQueryOutput struct {
	Columns    []string `json:"columns"`
	Rows       [][]any  `json:"rows"`
	Truncated  bool     `json:"truncated,omitempty"`
	Redactions int      `json:"redactions"`
}

type DBExecInput struct {
	Target   string `json:"target" jsonschema:"A target name from db_targets whose mode is read_write."`
	Database string `json:"database,omitempty" jsonschema:"The database to use. Optional when the target lists exactly one."`
	SQL      string `json:"sql" jsonschema:"The statement or statements that change data. DDL needs allow_ddl on the target."`
	Reason   string `json:"reason" jsonschema:"Why this change is made. The team reads it in DingTalk after the change."`
}

type DBExecOutput struct {
	RowsAffected int64 `json:"rows_affected"`
	Notified     bool  `json:"notified"`
}
