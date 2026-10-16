// Package mcpserver exposes securl's tools over MCP.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/keyring"
	"github.com/LeafAI/securl/internal/netguard"
	"github.com/LeafAI/securl/internal/notify"
	"github.com/LeafAI/securl/internal/ratelimit"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/archery"
	"github.com/LeafAI/securl/internal/site/generic"
	"github.com/LeafAI/securl/internal/tunnel"
	"github.com/LeafAI/securl/internal/vault"
)

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// freshnessOf is the freshness window of an Options value: zero is the default, a negative value is "always ask".
func freshnessOf(d time.Duration) time.Duration {
	switch {
	case d == 0:
		return sessionFreshness
	case d < 0:
		return 0
	}
	return d
}

// Options overrides the default collaborators (used by tests).
type Options struct {
	Notifier flow.Notifier
	Tunnels  flow.TunnelStarter
	HTTP     *http.Client
	Log      func(format string, args ...any)
	// Vault is the encrypted store of every secret (nil: one is opened at cfg.Vault.Dir). It starts locked.
	Vault *vault.Vault
	// SessionFreshness is how long a session that was just validated is used without asking the site (or the database)
	// again. Zero means the default, 30 seconds; a negative value means every use asks.
	SessionFreshness time.Duration
}

type Server struct {
	cfg     *config.Config
	hc      *http.Client
	notify  flow.Notifier
	tunnels flow.TunnelStarter
	log     func(string, ...any)
	audit   *audit.Log
	limiter *ratelimit.Limiter
	vault   *vault.Vault
	db      dbOpener
	fresh   time.Duration

	mu       sync.Mutex
	core     *core     // nil while the vault is locked
	unlocker *unlocker // works while the vault is locked
}

// core is everything that holds or handles a secret. It exists only while the vault is open: it is built when the
// vault unlocks and dropped when it locks, so nothing that can use a credential outlives the passphrase.
type core struct {
	mgr     *flow.Manager
	cache   *session.Cache
	tracker *archery.Tracker
	keys    *keyring.MemoryPool

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
	s := &Server{cfg: cfg, hc: opt.HTTP, log: opt.Log, db: realDB{}, fresh: freshnessOf(opt.SessionFreshness)}
	if s.hc == nil {
		s.hc = netguard.New(netguard.Policy{AllowLocal: cfg.Security.AllowLocalAddresses, AllowedHosts: cfg.Security.AllowedHosts})
	}
	if s.log == nil {
		s.log = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "securl: "+f+"\n", a...) }
	}
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
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	s.tunnels = ts
	s.unlocker = newUnlocker(s)
	s.vault = opt.Vault
	if s.vault == nil {
		s.vault = vault.New(cfg.Vault.Dir)
	}
	s.vault.SetIdleTimeout(cfg.Vault.IdleLock)

	m := mcp.NewServer(&mcp.Implementation{Name: "securl", Title: "Secure URL requestor", Version: Version}, &mcp.ServerOptions{Instructions: instructions})
	if err := s.register(m); err != nil {
		return nil, nil, err
	}
	s.registerResources(m)
	// A vault that is already open (a test, or a caller that unlocked it first) is taken up at once.
	if s.vault.State() == vault.Unlocked {
		if err := s.openCore(); err != nil {
			return nil, nil, err
		}
	}
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
		if err := site.ValidateOptions(name, opts); err != nil {
			return fmt.Errorf("site_options: %w", err)
		}
		c.Configure(opts)
	}
	return nil
}

// Close stops pending logins and their tunnels.
func (s *Server) Close() {
	s.mu.Lock()
	c := s.core
	s.mu.Unlock()
	if c != nil {
		c.mgr.Close()
	}
}

func (s *Server) register(m *mcp.Server) error {
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true}
	open := func(idempotent bool) *mcp.ToolAnnotations {
		v := true
		return &mcp.ToolAnnotations{OpenWorldHint: &v, IdempotentHint: idempotent}
	}
	destructive := true
	for _, reg := range []func() error{
		func() error {
			return addTool(m, s.observe, spec[VaultStatusOutput]{toolVaultStatus, "Vault state", "Say whether the vault that holds every secret is open, and whether wrong passphrases are being slowed down. Needs no unlock and shows nothing secret.", ro}, s.vaultStatus)
		},
		func() error {
			return addTool(m, s.observe, spec[VaultUnlockOutput]{toolVaultUnlock, "Ask the user to unlock the vault", "Open the vault: every other tool refuses while it is locked. The person gets a DingTalk link and types the vault passphrase on that page; you never see it. Returns pending if they have not yet, then call again with the unlock_id. Does nothing and asks nobody when the vault is already open.", open(false)}, s.vaultUnlock)
		},
		func() error {
			return addTool(m, s.observe, spec[LoginOutput]{toolSessionOpen, "Open a session on a website",
				"Get a session on a website (gitlab, jenkins, kibana, kubesphere, nightingale, archery, skywalking, rocketmq, or a configured site). A person types the credential once, on a page opened from a DingTalk link; the agent never sees the password. For archery the result carries no credentials (use the archery_* tools). If still pending after max_block_seconds, call " + toolSessionWait + " with the returned login_id.", open(false)}, s.login)
		},
		func() error {
			return addTool(m, s.observe, spec[LoginOutput]{toolSessionWait, "Wait for a session being opened", "Keep waiting for a session that " + toolSessionOpen + " asked a person for.", open(true)}, s.loginWait)
		},
		func() error {
			return addTool(m, s.observe, spec[RequestOutput]{toolRequest, "Send an authenticated HTTP request",
				"Send an HTTP request to a site you hold a session for. The gateway puts the session's cookies and tokens into the request and removes them from the answer, so you never see or send a credential: do not put a Cookie or Authorization header in it (refused). Only the site of the session can be reached, by an absolute path; redirects are returned unless follow_redirects is set, and never followed to another site. Needs a session: call " + toolSessionOpen + " first (it asks a person once). A 401 means the session ended: call " + toolSessionOpen + " with force_refresh.", open(false)}, s.request)
		},
		func() error {
			return addTool(m, s.observe, spec[DBTargetsOutput]{toolDBTargets, "List database targets",
				"List the databases the owner has made reachable: name, engine, environment, whether it takes changes, which databases it offers and whether a session exists. Never a host or an account.", ro}, s.dbTargets)
		},
		func() error {
			return addTool(m, s.observe, spec[DBQueryOutput]{toolDBQuery, "Run a read-only SQL statement",
				"Run one read-only statement (SELECT, SHOW, EXPLAIN, DESCRIBE) on a database target, as the account a person typed for it. Needs a session: call " + toolSessionOpen + " with url db://<target> first. Rows are limited in number and size; the answer says when it was cut. The account's password never appears in an answer.", open(true)}, s.dbQuery)
		},
		func() error {
			return addTool(m, s.observe, spec[DBExecOutput]{toolDBExec, "Change data on a database",
				"Change data on a database target whose mode is read_write, as the account a person typed for it. Needs a session and a reason; the team is told in DingTalk after the change. A change that touches more rows than the target allows is rolled back. Schema changes need allow_ddl on the target. Production databases are not reachable: use archery_run_sql.", &mcp.ToolAnnotations{DestructiveHint: &destructive}}, s.dbExec)
		},
		func() error {
			return addTool(m, s.observe, spec[SitesOutput]{toolSiteList, "List supported websites", "List the websites securl can open a session on.", ro}, s.sites)
		},
		func() error {
			return addTool(m, s.observe, spec[SessionsOutput]{toolSessionList, "List sessions", "List the sites that have a session (never the credentials).", ro}, s.sessions)
		},
		func() error {
			return addTool(m, s.observe, spec[LogoutOutput]{toolSessionClose, "Close a session", "Forget the session for a URL (or all sessions) and cancel a session that is still being opened for it.", nil}, s.logout)
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
	// json.RawMessage is a byte slice to the generator, which would tell a model to send an array of numbers: it holds
	// any JSON value, so it gets the schema that says so.
	schema, err := jsonschema.For[In](&jsonschema.ForOptions{TypeSchemas: map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[json.RawMessage](): {},
		// a value that is one string or a list of strings; numbers and booleans are accepted too and read as text
		reflect.TypeFor[multiValue](): multiValueSchema(),
	}})
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
