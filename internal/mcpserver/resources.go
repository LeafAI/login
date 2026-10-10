package mcpserver

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Resource URIs. They are read-only views an agent can consult before calling tools.
const (
	uriSites    = "login://sites"
	uriSessions = "login://sessions"
	uriPolicy   = "login://policy"
)

// Policy tells an agent how this gateway will treat it, so it can plan instead of tripping over limits.
// It never contains secrets: no webhook, signing secret, key paths or cached credentials.
type Policy struct {
	AllowedHosts    []string     `json:"allowed_hosts"` // empty: any host
	MaxBlockSeconds int          `json:"max_block_seconds"`
	Limits          PolicyLimits `json:"limits"`
	DDLAllowed      bool         `json:"archery_ddl_allowed"`
	AuditEnabled    bool         `json:"audit_enabled"`
	HumanTTLSeconds int          `json:"human_step_ttl_seconds"`
}

// PolicyLimits mirrors the `limits:` config section.
type PolicyLimits struct {
	PerSite               int `json:"per_site"`
	Total                 int `json:"total"`
	WindowSeconds         int `json:"window_seconds"`
	RejectCooldownSeconds int `json:"reject_cooldown_seconds"`
}

func (s *Server) policy() Policy {
	hosts := append([]string{}, s.cfg.Security.AllowedHosts...)
	sort.Strings(hosts)
	l := s.cfg.Limits
	return Policy{
		AllowedHosts: hosts, MaxBlockSeconds: int(s.maxBlock(0).Seconds()),
		Limits: PolicyLimits{PerSite: l.PerSite, Total: l.Total,
			WindowSeconds: int(l.Window.Seconds()), RejectCooldownSeconds: int(l.RejectCooldown.Seconds())},
		DDLAllowed: s.cfg.Archery.DDLAllowed(), AuditEnabled: s.cfg.Audit.On(),
		HumanTTLSeconds: int(s.cfg.Web.TTL.Seconds()),
	}
}

func jsonResource(uri string, v any) (*mcp.ReadResourceResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(b)}}}, nil
}

func (s *Server) registerResources(m *mcp.Server) {
	add := func(uri, name, title, desc string, view func() (any, *ToolError)) {
		m.AddResource(&mcp.Resource{URI: uri, Name: name, Title: title, Description: desc, MIMEType: "application/json"},
			func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				v, terr := view()
				if terr != nil {
					return nil, terr
				}
				return jsonResource(uri, v)
			})
	}
	add(uriSites, "sites", "Supported websites",
		"The websites this gateway can log in to, how each authenticates and how many human steps it may need. Same data as the login_sites tool.",
		func() (any, *ToolError) { return s.sites(context.Background(), nil, Empty{}) })
	add(uriSessions, "sessions", "Cached sessions",
		"Which sites currently have a valid cached login (never the cookies or tokens). Same data as the login_sessions tool.",
		func() (any, *ToolError) { return s.sessions(context.Background(), nil, Empty{}) })
	add(uriPolicy, "policy", "Gateway policy",
		"Which hosts are allowed, how long calls block, how often people may be asked, and whether DDL is allowed. Read it before planning a login.",
		func() (any, *ToolError) { return s.policy(), nil })
}

// instructions is what MCP clients show the model when it connects.
const instructions = `login is a gateway that gets you a valid session (cookie / token) for internal websites. A person types the credential on a page opened from a DingTalk link; you never see a password.

How to use it:
1. Call login with the site's URL and a short, honest reason (the person sees it). A cached session is returned without bothering anyone (cached: true).
2. If the result is status "pending", a person has been asked. Call login_wait with the login_id; do not call login again. Waiting never re-sends the message.
3. Errors have a code. user_rejected: the person said no, stop and tell the user. rate_limited: people are being asked too often, wait for retry, do not loop. host_not_allowed: the host is outside policy, do not try other spellings. session_expired: call login with force_refresh.
4. Cookies and tokens are secrets: use them only for requests to that site and never print or store them.
5. For SQL on Archery use archery_query (read-only, no approval) or archery_run_sql (needs a human approval; call archery_wait if it returns pending).

Resources: login://sites (what is supported), login://sessions (what is already logged in), login://policy (limits that apply to you).`
