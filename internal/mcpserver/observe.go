package mcpserver

import (
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site"
)

// admit decides whether a new login flow may bother a human, and audits the decision.
func (s *Server) admit(d site.Driver, base *url.URL, reason string) error {
	if lim := s.limiter.Allow(session.Key(base)); lim != nil {
		s.audit.Record(audit.Event{Event: "rate_limited", Site: d.Name(), Host: base.Host, Reason: reason, Result: lim.Reason})
		return lim
	}
	s.audit.Record(audit.Event{Event: "human_request", Site: d.Name(), Host: base.Host, Reason: reason})
	return nil
}

// onRound audits each message sent to a person: a login with a second factor shows up as two rounds.
func (s *Server) onRound(f *flow.Flow, mode string, round int) {
	s.audit.Record(audit.Event{Event: "human_round", Site: f.Site, Host: f.Base.Host, Mode: mode, Round: round})
}

// onTunnel audits which provider carries a flow's link, and how many tunnels were opened to find one that works.
func (s *Server) onTunnel(f *flow.Flow, provider string, attempts int) {
	s.audit.Record(audit.Event{Event: "tunnel", Site: f.Site, Host: f.Base.Host, Tunnel: provider, Attempts: attempts})
}

// The inputs say which site they target and which SQL they carry, so the audit trail can name them.
type targeter interface{ target() string }
type sqler interface{ sqlText() string }

func (i LoginInput) target() string    { return i.URL }
func (i LogoutInput) target() string   { return i.URL }
func (i DBQueryInput) target() string  { return "db://" + i.Target }
func (i DBExecInput) target() string   { return "db://" + i.Target }
func (a ArcheryURL) target() string    { return a.URL }
func (i QueryInput) sqlText() string   { return i.SQL }
func (i DBQueryInput) sqlText() string { return i.SQL }
func (i DBExecInput) sqlText() string  { return i.SQL }
func (i RunSQLInput) sqlText() string  { return i.SQL }

// maxReasonBytes bounds agent-controlled text in the audit log, as the login tool does for the message to people.
const maxReasonBytes = 200

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func clientName(req *mcp.CallToolRequest) string {
	if req == nil || req.Session == nil {
		return ""
	}
	p := req.Session.InitializeParams()
	if p == nil || p.ClientInfo == nil {
		return ""
	}
	if p.ClientInfo.Version == "" {
		return p.ClientInfo.Name
	}
	return p.ClientInfo.Name + "/" + p.ClientInfo.Version
}

// observe records one finished tool call: metadata only, never the result's secrets or the SQL text.
func (s *Server) observe(tool string, req *mcp.CallToolRequest, in, out any, terr *ToolError, took time.Duration) {
	e := audit.Event{Event: "tool_call", Tool: tool, Client: clientName(req), Millis: took.Milliseconds(), Result: "ok"}
	if t, ok := in.(targeter); ok {
		if u, err := url.Parse(t.target()); err == nil {
			e.Host = u.Host
		}
	}
	if q, ok := in.(sqler); ok {
		e.SQLBytes, e.SQLHash = audit.Fingerprint(q.sqlText())
	}
	if li, ok := in.(LoginInput); ok {
		e.Reason = clip(li.Reason, maxReasonBytes)
	}
	switch o := out.(type) {
	case *LoginOutput:
		e.Site, e.Result, e.Cached = o.Site, o.Status, o.Cached
	case ArcheryOut:
		e.Result, e.Workflow = o.Status, o.WorkflowID
	}
	if terr != nil {
		e.Result = terr.Code
	}
	s.audit.Record(e)
}

func siteKey(base *url.URL) string { return session.Key(base) }
