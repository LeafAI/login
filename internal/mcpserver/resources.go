package mcpserver

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Policy tells an agent how this gateway will treat it, so it can plan instead of tripping over limits.
// It never contains secrets: no webhook, signing secret, key paths or cached credentials.
type Policy struct {
	AllowedHosts []string `json:"allowed_hosts"` // empty: any host
	// LocalAddressesAllowed: false (the default) means loopback, link-local and cloud-metadata addresses are refused.
	LocalAddressesAllowed bool         `json:"local_addresses_allowed"`
	MaxBlockSeconds       int          `json:"max_block_seconds"`
	Limits                PolicyLimits `json:"limits"`
	DDLAllowed            bool         `json:"archery_ddl_allowed"`
	// ArcheryRequestsAllowed: false (the default) means the request tool refuses Archery; use the archery_* tools.
	ArcheryRequestsAllowed bool `json:"archery_requests_allowed"`
	AuditEnabled           bool `json:"audit_enabled"`
	HumanTTLSeconds        int  `json:"human_step_ttl_seconds"`
	// LinkUnlockRequired: the person must type a long-period code in the page to read the details of a login.
	LinkUnlockRequired bool `json:"link_unlock_required"`
	// SealingCodeRequired: the person must type a short-period code in the page, and what they type is sealed with it.
	SealingCodeRequired bool `json:"sealing_code_required"`
	// DatabaseTargets lists the configured database targets by name, with what an agent may do on each. No hosts.
	DatabaseTargets []PolicyDatabase `json:"database_targets"`
	// VaultState: not_initialized | locked | unlocked. While it is not "unlocked" every tool that touches a site refuses.
	VaultState string `json:"vault_state"`
}

// PolicyDatabase is one database target as the policy shows it.
type PolicyDatabase struct {
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Mode        string `json:"mode"`
	AllowDDL    bool   `json:"allow_ddl"`
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
	dbs := make([]PolicyDatabase, 0, len(s.cfg.Databases))
	for _, d := range s.cfg.Databases {
		dbs = append(dbs, PolicyDatabase{Name: d.Name, Environment: d.Environment, Mode: d.Mode, AllowDDL: d.AllowsDDL()})
	}
	return Policy{
		DatabaseTargets: dbs,
		AllowedHosts:    hosts, LocalAddressesAllowed: s.cfg.Security.AllowLocalAddresses, MaxBlockSeconds: int(s.maxBlock(0).Seconds()),
		Limits: PolicyLimits{PerSite: l.PerSite, Total: l.Total,
			WindowSeconds: int(l.Window.Seconds()), RejectCooldownSeconds: int(l.RejectCooldown.Seconds())},
		DDLAllowed: s.cfg.Archery.DDLAllowed(), ArcheryRequestsAllowed: s.cfg.Security.AllowArcheryRequests, AuditEnabled: s.cfg.Audit.On(),
		HumanTTLSeconds:    int(s.cfg.Web.TTL.Seconds()),
		LinkUnlockRequired: s.cfg.Security.LinkTOTP.Enabled, SealingCodeRequired: s.cfg.Security.SealTOTP.Enabled,
		VaultState: s.vault.State().String(),
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
		"The websites securl can open a session on, how each authenticates and how many human steps it may need. Same data as the site_list tool.",
		func() (any, *ToolError) { return s.sites(context.Background(), nil, Empty{}) })
	add(uriSessions, "sessions", "Cached sessions",
		"Which sites currently have a valid cached login (never the cookies or tokens). Same data as the session_list tool.",
		func() (any, *ToolError) { return s.sessions(context.Background(), nil, Empty{}) })
	add(uriPolicy, "policy", "Gateway policy",
		"Which hosts are allowed, how long calls block, how often people may be asked, and whether DDL is allowed. Read it before planning a login.",
		func() (any, *ToolError) { return s.policy(), nil })
}

// instructions is what MCP clients show the model when it connects.
const instructions = `securl lets you work with internal websites that need a person's credentials. A person types the credential once, on a page opened from a DingTalk link; you never see a password.

How to use it:
0. securl starts locked. Until the user has unlocked its vault, every tool except ` + toolVaultStatus + `, ` + toolVaultUnlock + ` and ` + toolSiteList + ` answers vault_locked. Call ` + toolVaultUnlock + `: the person gets a DingTalk link and types the vault passphrase on that page. You never see it and cannot pass it. If it is pending, call ` + toolVaultUnlock + ` again with the unlock_id. Do not call it in a loop: after wrong passphrases it answers rate_limited with a retry time, and ` + toolVaultStatus + ` shows the same.
1. Call ` + toolSessionOpen + ` with the site's URL and a short, honest reason (the person sees it). A session that already exists is reused without bothering anyone (cached: true).
2. If the result is status "pending", a person has been asked. Call ` + toolSessionWait + ` with the login_id; do not call ` + toolSessionOpen + ` again. Waiting never re-sends the message.
3. Errors have a code. user_rejected: the person said no, stop and tell the user. rate_limited: people are being asked too often, wait for retry, do not loop. host_not_allowed: the host is outside policy, do not try other spellings. session_expired: call ` + toolSessionOpen + ` with force_refresh.
4. Cookies and tokens are secrets: use them only for requests to that site and never print or store them. Archery is the exception: ` + toolSessionOpen + ` returns no credentials for it (redacted: true) and the archery_* tools use the session for you.
5. For SQL on Archery: archery_instances / archery_groups discover what exists (archery_run_sql needs a resource_group name from archery_groups), archery_query is read-only with no approval, archery_run_sql needs a human approval (call archery_wait if it returns pending).

Resources: ` + uriSites + ` (what is supported), ` + uriSessions + ` (which sites have a session), ` + uriPolicy + ` (limits that apply to you).`
