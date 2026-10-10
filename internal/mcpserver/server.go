// Package mcpserver exposes the login tools over MCP.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/flow"
	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/notify"
	"github.com/LeafAI/login/internal/session"
	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/archery"
	"github.com/LeafAI/login/internal/site/generic"
	"github.com/LeafAI/login/internal/tunnel"
)

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// Options overrides the default collaborators (used by tests).
type Options struct {
	Notifier flow.Notifier
	Tunnels  flow.TunnelStarter
	HTTP     *http.Client
	Log      func(format string, args ...any)
}

type Server struct {
	cfg     *config.Config
	hc      *http.Client
	mgr     *flow.Manager
	cache   *session.Cache
	tracker *archery.Tracker
	notify  flow.Notifier
	log     func(string, ...any)
}

// New builds the MCP server with all tools registered.
func New(cfg *config.Config, opt Options) (*mcp.Server, *Server, error) {
	for _, spec := range cfg.Sites {
		d, err := generic.New(spec)
		if err != nil {
			return nil, nil, err
		}
		site.Replace(d)
	}
	s := &Server{cfg: cfg, hc: opt.HTTP, log: opt.Log, cache: session.New()}
	if s.hc == nil {
		s.hc = &http.Client{Timeout: 30 * time.Second}
	}
	if s.log == nil {
		s.log = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "login: "+f+"\n", a...) }
	}
	s.notify = opt.Notifier
	if s.notify == nil {
		s.notify = &notify.DingTalk{Webhook: cfg.DingTalk.Webhook, Secret: cfg.DingTalk.Secret, Keyword: cfg.DingTalk.Keyword, Mobiles: cfg.DingTalk.Mobiles}
	}
	ts := opt.Tunnels
	if ts == nil {
		var err error
		if ts, err = newTunnelStarter(cfg, s.log); err != nil {
			return nil, nil, err
		}
	}
	s.mgr = flow.NewManager(flow.Config{
		Keys:     keyring.NewPool(cfg.Keys.Dir, cfg.Keys.MaxUses, cfg.Keys.MaxAge),
		Notifier: s.notify, Tunnels: ts, PageURL: cfg.Web.PageURL, TTL: cfg.Web.TTL, Log: s.log,
	})
	s.tracker = archery.NewTracker(cfg.Archery.DDLAllowed(), cfg.Archery.WaitTimeout)
	s.tracker.Poll = cfg.Archery.PollInterval

	m := mcp.NewServer(&mcp.Implementation{Name: "login", Version: "0.1.0"}, nil)
	s.register(m)
	return m, s, nil
}

func (s *Server) register(m *mcp.Server) {
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	open := func(h bool) *mcp.ToolAnnotations {
		v := true
		return &mcp.ToolAnnotations{OpenWorldHint: &v, IdempotentHint: h}
	}
	destructive := true
	addTool(m, "login", "Log in to a website (gitlab, kibana, kubesphere, nightingale, archery, skywalking, or a configured site) and return a valid cookie/token. A human types the credential on a page opened from a DingTalk link; the agent never sees the password. If still pending after max_block_seconds, call login_wait with the returned login_id.", open(false), s.login)
	addTool(m, "login_wait", "Resume a pending login started by `login`.", open(true), s.loginWait)
	addTool(m, "login_sites", "List the websites this server can log in to.", ro, s.sites)
	addTool(m, "login_sessions", "List cached login sessions (no secrets).", ro, s.sessions)
	addTool(m, "logout", "Forget the cached session for a URL (or all sessions) and cancel a pending login for it.", nil, s.logout)
	addTool(m, "archery_instances", "List Archery instances (and optionally an instance's databases) the user can access.", ro, s.archeryInstances)
	addTool(m, "archery_query", "Run a read-only SQL query through Archery's query endpoint (no approval needed).", ro, s.archeryQuery)
	addTool(m, "archery_run_sql", "Submit SQL to Archery, notify approvers, wait for approval, execute automatically and return the result, as one call. If approval takes longer than max_block_seconds a pending result with workflow_id is returned; continue with archery_wait.", &mcp.ToolAnnotations{DestructiveHint: &destructive}, s.archeryRunSQL)
	addTool(m, "archery_wait", "Continue waiting for an Archery workflow; executes it once when approved. Safe to call repeatedly.", &mcp.ToolAnnotations{IdempotentHint: true}, s.archeryWait)
	addTool(m, "archery_workflow_status", "Read the state of an Archery workflow.", ro, s.archeryStatus)
	addTool(m, "archery_cancel", "Abort an Archery workflow that has not started executing.", nil, s.archeryCancel)
}

// addTool registers a typed tool with structured success/error results.
func addTool[In any](m *mcp.Server, name, desc string, ann *mcp.ToolAnnotations,
	h func(ctx context.Context, req *mcp.CallToolRequest, in In) (any, *ToolError)) {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("schema for %s: %v", name, err))
	}
	m.AddTool(&mcp.Tool{Name: name, Description: desc, InputSchema: schema, Annotations: ann},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in In
			if len(req.Params.Arguments) > 0 {
				dec := json.NewDecoder(strings.NewReader(string(req.Params.Arguments)))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&in); err != nil {
					return toolError(errf("invalid_argument", false, "%v", err)), nil
				}
			}
			out, terr := h(ctx, req, in)
			if terr != nil {
				return toolError(terr), nil
			}
			b, _ := json.Marshal(out)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, StructuredContent: json.RawMessage(b)}, nil
		})
}

func toolError(e *ToolError) *mcp.CallToolResult {
	b, _ := json.Marshal(e)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, StructuredContent: json.RawMessage(b)}
}

func (s *Server) progress(ctx context.Context, req *mcp.CallToolRequest, n *float64, msg string) {
	s.log("%s", msg)
	tok := req.Params.GetProgressToken()
	if tok == nil || req.Session == nil {
		return
	}
	*n++
	req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Progress: *n, Message: msg})
}

func (s *Server) maxBlock(override int) time.Duration {
	n := s.cfg.MCP.MaxBlockSeconds
	if override > 0 {
		n = override
	}
	if n > 600 {
		n = 600
	}
	return time.Duration(n) * time.Second
}

// Providers returns the configured tunnel providers in order.
func Providers(cfg *config.Config) ([]*tunnel.Provider, error) {
	b := tunnel.Builtins()
	for _, c := range cfg.Tunnel.Custom {
		p, err := tunnel.Custom(c.Name, c.Command, c.URL, c.URLRegex)
		if err != nil {
			return nil, err
		}
		b[c.Name] = p
	}
	var list []*tunnel.Provider
	for _, name := range cfg.Tunnel.Order {
		name = strings.TrimSpace(name)
		p, ok := b[name]
		if !ok {
			return nil, fmt.Errorf("tunnel.order: unknown provider %q", name)
		}
		list = append(list, p)
	}
	return list, nil
}

func newTunnelStarter(cfg *config.Config, log func(string, ...any)) (flow.TunnelStarter, error) {
	list, err := Providers(cfg)
	if err != nil {
		return nil, err
	}
	return &tunnelStarter{providers: list, runner: &tunnel.Runner{Timeout: cfg.Tunnel.Timeout, Log: log}}, nil
}

type tunnelStarter struct {
	providers []*tunnel.Provider
	runner    *tunnel.Runner
}

func (t *tunnelStarter) Start(ctx context.Context, port int) (flow.Tunnel, error) {
	tn, err := t.runner.Start(ctx, t.providers, port)
	if err != nil {
		return nil, err
	}
	return tunnelAdapter{tn}, nil
}

type tunnelAdapter struct{ *tunnel.Tunnel }

func (a tunnelAdapter) PublicURL() string { return a.URL }
