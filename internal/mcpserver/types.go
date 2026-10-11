package mcpserver

import (
	"time"

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

type CookieOut struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Expires  string `json:"expires,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
}

type LoginInput struct {
	URL             string `json:"url" jsonschema:"Any URL on the site; scheme+host identify the site."`
	Site            string `json:"site,omitempty" jsonschema:"Driver name (see login_sites). Auto-detected from the URL when omitted."`
	Reason          string `json:"reason,omitempty" jsonschema:"Why the agent needs access; shown to the human in DingTalk."`
	ForceRefresh    bool   `json:"force_refresh,omitempty" jsonschema:"Skip the cached session and log in again."`
	Wait            *bool  `json:"wait,omitempty" jsonschema:"false: return pending immediately after notifying the human. Default true."`
	MaxBlockSeconds int    `json:"max_block_seconds,omitempty" jsonschema:"Override the default blocking time (1-600)."`
}

type LoginWaitInput struct {
	LoginID         string `json:"login_id" jsonschema:"The login_id returned by a pending login."`
	MaxBlockSeconds int    `json:"max_block_seconds,omitempty"`
}

type LoginOutput struct {
	Status  string `json:"status"` // ok | pending
	Site    string `json:"site,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
	Auth    string `json:"auth,omitempty"` // cookie | bearer | none
	Cached  bool   `json:"cached,omitempty"`
	// Redacted is true when the credentials were withheld on purpose: the site's tools (archery_*) use the
	// session on the agent's behalf.
	Redacted     bool              `json:"redacted,omitempty"`
	CookieHeader string            `json:"cookie_header,omitempty"`
	Cookies      []CookieOut       `json:"cookies,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Tokens       map[string]string `json:"tokens,omitempty"`
	ExpiresAt    string            `json:"expires_at,omitempty"`
	LoginID      string            `json:"login_id,omitempty"`
	WaitingFor   string            `json:"waiting_for,omitempty"`
	Round        int               `json:"round,omitempty"`
	NextTool     string            `json:"next_tool,omitempty"`
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
