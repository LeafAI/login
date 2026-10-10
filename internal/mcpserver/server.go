// Package mcpserver exposes the login tools over MCP.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/audit"
	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/flow"
	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/notify"
	"github.com/LeafAI/login/internal/ratelimit"
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
	audit   *audit.Log
	limiter *ratelimit.Limiter

	linkTOTP, sealTOTP bool // which TOTP factors are on (reported by the policy resource; never their secrets)
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
	if err := ApplySiteOptions(cfg); err != nil {
		return nil, nil, err
	}
	s := &Server{cfg: cfg, hc: opt.HTTP, log: opt.Log}
	if s.hc == nil {
		s.hc = &http.Client{Timeout: 30 * time.Second}
	}
	if s.log == nil {
		s.log = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "login: "+f+"\n", a...) }
	}
	if cfg.Sessions.Persist {
		s.cache = session.NewPersistent(&session.Store{Dir: cfg.Sessions.Dir})
	} else {
		s.cache = session.New()
	}
	s.cache.Log = s.log
	if cfg.Audit.On() {
		a, err := audit.Open(cfg.Audit.File, s.log)
		if err != nil {
			return nil, nil, err
		}
		s.audit = a
	}
	s.limiter = ratelimit.New(ratelimit.Config{PerSite: cfg.Limits.PerSite, Total: cfg.Limits.Total,
		Window: cfg.Limits.Window, RejectCooldown: cfg.Limits.RejectCooldown}, nil)
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
	// The factors are loaded before anything else can use them. A factor that is on but whose secret is missing stops
	// the server: carrying on would hand out plain links to people who switched the protection on.
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	linkSrc, sealSrc, err := cfg.Security.Sources()
	if err != nil {
		return nil, nil, err
	}
	s.linkTOTP, s.sealTOTP = linkSrc != nil, sealSrc != nil
	var unlock, sealing flow.CodeSource
	if linkSrc != nil {
		unlock = linkSrc
	}
	if sealSrc != nil {
		sealing = sealSrc
	}
	s.mgr = flow.NewManager(flow.Config{
		Keys:     keyring.NewPool(cfg.Keys.Dir, cfg.Keys.MaxUses, cfg.Keys.MaxAge),
		Notifier: s.notify, Tunnels: ts, PageURL: cfg.Web.PageURL, TTL: cfg.Web.TTL, Log: s.log,
		Admit: s.admit, OnRound: s.onRound, OnTunnel: s.onTunnel, Unlock: unlock, Seal: sealing,
	})
	s.tracker = archery.NewTracker(cfg.Archery.DDLAllowed(), cfg.Archery.WaitTimeout)
	s.tracker.Poll = cfg.Archery.PollInterval

	m := mcp.NewServer(&mcp.Implementation{Name: "login", Title: "Login gateway", Version: Version}, &mcp.ServerOptions{Instructions: instructions})
	if err := s.register(m); err != nil {
		return nil, nil, err
	}
	s.registerResources(m)
	return m, s, nil
}

// ApplySiteOptions hands the `site_options:` section to the drivers that accept options.
func ApplySiteOptions(cfg *config.Config) error {
	for name, opts := range cfg.SiteOptions {
		d, err := site.Resolve(name, nil)
		if err != nil {
			return fmt.Errorf("site_options: %w", err)
		}
		c, ok := d.(site.Configurable)
		if !ok {
			return fmt.Errorf("site_options: driver %q has no options", name)
		}
		c.Configure(opts)
	}
	return nil
}

// Close stops pending logins and their tunnels.
func (s *Server) Close() { s.mgr.Close() }

func (s *Server) register(m *mcp.Server) error {
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	open := func(idempotent bool) *mcp.ToolAnnotations {
		v := true
		return &mcp.ToolAnnotations{OpenWorldHint: &v, IdempotentHint: idempotent}
	}
	destructive := true
	for _, reg := range []func() error{
		func() error {
			return addTool(m, s.observe, spec[LoginOutput]{"login", "Log in to a website",
				"Log in to a website (gitlab, jenkins, kibana, kubesphere, nightingale, archery, skywalking, or a configured site) and return a valid cookie/token. A human types the credential on a page opened from a DingTalk link; the agent never sees the password. For archery the result carries no credentials (use the archery_* tools). If still pending after max_block_seconds, call login_wait with the returned login_id.", open(false)}, s.login)
		},
		func() error {
			return addTool(m, s.observe, spec[LoginOutput]{"login_wait", "Resume a pending login", "Resume a pending login started by `login`.", open(true)}, s.loginWait)
		},
		func() error {
			return addTool(m, s.observe, spec[SitesOutput]{"login_sites", "List supported websites", "List the websites this server can log in to.", ro}, s.sites)
		},
		func() error {
			return addTool(m, s.observe, spec[SessionsOutput]{"login_sessions", "List cached sessions", "List cached login sessions (no secrets).", ro}, s.sessions)
		},
		func() error {
			return addTool(m, s.observe, spec[LogoutOutput]{"logout", "Forget a session", "Forget the cached session for a URL (or all sessions) and cancel a pending login for it.", nil}, s.logout)
		},
		func() error {
			return addTool(m, s.observe, spec[InstancesOutput]{"archery_instances", "List Archery instances", "List Archery instances (and optionally an instance's databases) the user can access.", ro}, s.archeryInstances)
		},
		func() error {
			return addTool(m, s.observe, spec[GroupsOutput]{"archery_groups", "List Archery resource groups", "List the Archery resource groups the user can submit SQL to (use a name as resource_group in archery_run_sql). With group, also list that group's instances that accept changes.", ro}, s.archeryGroups)
		},
		func() error {
			return addTool(m, s.observe, spec[QueryOutput]{"archery_query", "Run a read-only SQL query", "Run a read-only SQL query through Archery's query endpoint (no approval needed).", ro}, s.archeryQuery)
		},
		func() error {
			return addTool(m, s.observe, spec[ArcheryOut]{"archery_run_sql", "Submit SQL for approval and run it", "Submit SQL to Archery, notify approvers, wait for approval, execute automatically and return the result, as one call. If approval takes longer than max_block_seconds a pending result with workflow_id is returned; continue with archery_wait.", &mcp.ToolAnnotations{DestructiveHint: &destructive}}, s.archeryRunSQL)
		},
		func() error {
			return addTool(m, s.observe, spec[ArcheryOut]{"archery_wait", "Continue waiting for an Archery workflow", "Continue waiting for an Archery workflow; executes it once when approved. Safe to call repeatedly.", &mcp.ToolAnnotations{IdempotentHint: true}}, s.archeryWait)
		},
		func() error {
			return addTool(m, s.observe, spec[ArcheryStatusOrPending]{"archery_workflow_status", "Read an Archery workflow's state", "Read the state of an Archery workflow.", ro}, s.archeryStatus)
		},
		func() error {
			return addTool(m, s.observe, spec[ArcheryCancelOrPending]{"archery_cancel", "Abort an Archery workflow", "Abort an Archery workflow that has not started executing.", nil}, s.archeryCancel)
		},
	} {
		if err := reg(); err != nil {
			return err
		}
	}
	return nil
}

// spec describes one tool: its names, annotations and (via the type parameter) its result type.
type spec[Out any] struct {
	name, title, desc string
	ann               *mcp.ToolAnnotations
}

// addTool registers a typed tool with a generated input schema, a generated output schema, and
// structured success/error results.
func addTool[In, Out any](m *mcp.Server, obs observer, sp spec[Out],
	h func(ctx context.Context, req *mcp.CallToolRequest, in In) (any, *ToolError)) error {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		return fmt.Errorf("input schema for %s: %w", sp.name, err)
	}
	out, err := outputSchema(reflect.TypeFor[Out]())
	if err != nil {
		return fmt.Errorf("%s: %w", sp.name, err)
	}
	name := sp.name
	m.AddTool(&mcp.Tool{Name: name, Title: sp.title, Description: sp.desc, InputSchema: schema, OutputSchema: out, Annotations: sp.ann},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var in In
			if len(req.Params.Arguments) > 0 {
				dec := json.NewDecoder(strings.NewReader(string(req.Params.Arguments)))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&in); err != nil {
					return toolError(errf("invalid_argument", false, "%v", err)), nil
				}
			}
			start := time.Now()
			res, terr := h(ctx, req, in)
			obs(name, req, in, res, terr, time.Since(start))
			if terr != nil {
				return toolError(terr), nil
			}
			b, err := json.Marshal(res)
			if err != nil {
				return toolError(errf("internal", false, "encode result: %v", err)), nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, StructuredContent: json.RawMessage(b)}, nil
		})
	return nil
}

func toolError(e *ToolError) *mcp.CallToolResult {
	b, _ := json.Marshal(e)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}, StructuredContent: json.RawMessage(b)}
}

// observer is told about every finished tool call (for the audit log).
type observer func(tool string, req *mcp.CallToolRequest, in, out any, terr *ToolError, took time.Duration)

func (s *Server) progress(ctx context.Context, req *mcp.CallToolRequest, n *float64, msg string) {
	s.log("%s", msg)
	if req == nil || req.Params == nil || req.Session == nil {
		return
	}
	tok := req.Params.GetProgressToken()
	if tok == nil {
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

func (a tunnelAdapter) PublicURL() string    { return a.URL }
func (a tunnelAdapter) ProviderName() string { return a.Provider }
