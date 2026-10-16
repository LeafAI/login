package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dbsite"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/netguard"
	"github.com/LeafAI/securl/internal/ratelimit"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site"
)

func baseOf(raw string) (*url.URL, *ToolError) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errf("invalid_argument", false, "invalid url %q (need http(s)://host[:port])", raw)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func (s *Server) login(ctx context.Context, req *mcp.CallToolRequest, in LoginInput) (any, *ToolError) {
	if len(in.Reason) > 200 {
		in.Reason = in.Reason[:200]
	}
	wait := in.Wait == nil || *in.Wait
	out, terr := s.ensureLogin(ctx, req, in.URL, in.Site, in.Reason, in.ForceRefresh, wait, s.maxBlock(in.MaxBlockSeconds))
	if terr != nil {
		return nil, terr
	}
	return out, nil
}

func (s *Server) loginWait(ctx context.Context, req *mcp.CallToolRequest, in LoginWaitInput) (any, *ToolError) {
	c, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	f := c.mgr.Get(in.LoginID)
	if f == nil {
		return nil, errf("invalid_argument", false, "login_id %q not found or expired; call "+toolSessionOpen+" again", in.LoginID)
	}
	out, terr := s.await(ctx, req, f, s.maxBlock(in.MaxBlockSeconds))
	if terr != nil {
		return nil, terr
	}
	return out, nil
}

// ensureLogin returns a valid session for the site: from cache, or by running a login flow.
func (s *Server) ensureLogin(ctx context.Context, req *mcp.CallToolRequest, raw, siteName, reason string, force, wait bool, max time.Duration) (*LoginOutput, *ToolError) {
	c, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	var (
		base *url.URL
		d    site.Driver
	)
	if strings.HasPrefix(strings.ToLower(raw), dbsite.Scheme+":") {
		if _, base, terr = s.databaseTarget(raw); terr != nil {
			return nil, terr
		}
		d = s.openDriver()
	} else {
		var err error
		if base, terr = baseOf(raw); terr != nil {
			return nil, terr
		}
		if terr := checkHost(s.cfg, base); terr != nil {
			return nil, terr
		}
		if siteName == "" {
			siteName = s.alias(base)
		}
		base = s.root(base)
		if d, err = site.Resolve(siteName, base); err != nil {
			return nil, errf("unsupported_site", false, "%v", err)
		}
	}
	if !d.NeedsLogin() {
		sess, err := d.Login(ctx, base, nil, s.hc)
		if err != nil {
			return nil, classify(err)
		}
		out := sessionOutput(d.Name(), base, sess)
		return &out, nil
	}
	if !force {
		e, err := c.cache.Lookup(ctx, base, s.hc, 0)
		if err == nil {
			out := sessionOutput(e.Site, base, e.Session)
			out.Cached = true
			return &out, nil
		}
		if errors.Is(err, site.ErrUnreachable) {
			// The saved session is kept. Asking a person to log in again would not fix a site that cannot be reached, and it
			// would replace an account that is good.
			return nil, sessionLost(err, base.Host, "", "")
		}
	} else {
		c.cache.Delete(session.Key(base))
	}
	f := c.mgr.Start(d, base, reason, s.hc, func(f *flow.Flow, r flow.Result) {
		var rj *flow.RejectedError
		switch {
		case r.Err == nil:
			c.cache.Put(f.Base, d, r.Session)
		case errors.As(r.Err, &rj):
			s.limiter.Rejected(session.Key(f.Base))
		}
	})
	select {
	case <-f.Done(): // refused before it started (rate limit), or finished instantly
		if r := f.Result(); r.Err != nil {
			return nil, classify(r.Err)
		}
	default:
	}
	if !wait {
		return pendingOut(f), nil
	}
	return s.await(ctx, req, f, max)
}

// await waits for a flow, reporting progress, until it ends or max elapses.
func (s *Server) await(ctx context.Context, req *mcp.CallToolRequest, f *flow.Flow, max time.Duration) (*LoginOutput, *ToolError) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	timer := time.NewTimer(max)
	defer timer.Stop()
	var n float64
	s.progress(ctx, req, &n, describe(f))
	for {
		select {
		case <-f.Done():
			r := f.Result()
			if r.Err != nil {
				return nil, classify(r.Err)
			}
			out := sessionOutput(f.Site, f.Base, r.Session)
			return &out, nil
		case <-timer.C:
			return pendingOut(f), nil
		case <-tick.C:
			s.progress(ctx, req, &n, describe(f))
		case <-ctx.Done():
			return nil, errf("internal", true, "cancelled: %v", ctx.Err())
		}
	}
}

func describe(f *flow.Flow) string {
	sn := f.Snapshot()
	switch sn.Phase {
	case "waiting_human":
		return fmt.Sprintf("waiting for the human to complete the %q step on %s (DingTalk link sent)", sn.Mode, f.Base.Host)
	case "working":
		return "logging in to " + f.Base.Host
	case "done":
		return "login finished"
	}
	return "starting the login flow for " + f.Base.Host
}

func pendingOut(f *flow.Flow) *LoginOutput {
	sn := f.Snapshot()
	return &LoginOutput{Status: "pending", Site: f.Site, BaseURL: f.Base.String(), LoginID: f.ID,
		WaitingFor: sn.Mode, Round: sn.Round, ExpiresAt: fmtTime(sn.ExpiresAt), NextTool: nextSessionWait}
}

// sessionOutput describes a session without any of its credentials.
func sessionOutput(name string, base *url.URL, sess *site.Session) LoginOutput {
	out := LoginOutput{Status: "ok", Site: name, BaseURL: base.String(), ExpiresAt: fmtTime(sess.ExpiresAt)}
	switch {
	case sess.Headers["Authorization"] != "":
		out.Auth = "bearer"
	case len(sess.Cookies) > 0:
		out.Auth = "cookie"
	default:
		out.Auth = "none"
	}
	return out
}

// classify maps internal errors to tool error codes.
func classify(err error) *ToolError {
	var rj *flow.RejectedError
	var lim *ratelimit.Limited
	switch {
	case errors.As(err, &rj):
		e := errf("user_rejected", false, "%s", rj.Error())
		e.Hint = "The human declined the login request. Do not retry unless the user asks you to."
		return e
	case errors.As(err, &lim):
		e := errf("rate_limited", true, "%v", err)
		e.Hint = "People are being asked too often. Do not retry in a loop: wait, or ask the user to complete or reject the pending request."
		return e
	case errors.Is(err, flow.ErrHumanTimeout):
		e := errf("human_timeout", true, "%v", err)
		e.Hint = "Nobody completed the login page in time. Ask the user to watch DingTalk, then call " + toolSessionOpen + " again."
		return e
	case errors.Is(err, flow.ErrNotify):
		return errf("notify_failed", true, "%v", err)
	case errors.Is(err, flow.ErrTunnel):
		return errf("tunnel_unavailable", true, "%v", err)
	case errors.Is(err, site.ErrBadCredentials):
		return errf("bad_credentials", true, "%v", err)
	case errors.Is(err, site.ErrLoginRejected):
		return errf("login_rejected", false, "%v", err)
	case errors.Is(err, site.ErrUnreachable):
		return errf("site_unreachable", true, "%v", err)
	}
	return errf("internal", false, "%v", err)
}

var builtinInfo = map[string]SiteInfo{
	"gitlab":      {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "hostname contains 'gitlab'"},
	"jenkins":     {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login"}, Match: "hostname contains 'jenkins'"},
	"kibana":      {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login"}, Match: "hostname contains 'kibana'"},
	"kubesphere":  {Auth: "bearer", NeedsLogin: true, Rounds: []string{"login"}, Match: "hostname contains 'kubesphere'"},
	"nightingale": {Auth: "bearer", NeedsLogin: true, Rounds: []string{"login", "(captcha is part of the login step when enabled)"}, Match: "hostname contains 'nightingale' or 'n9e'"},
	"archery":     {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "hostname contains 'archery'"},
	"rocketmq":    {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login"}, Match: "hostname contains 'rocketmq', 'rmq-' or '-mq.'"},
	"skywalking":  {Auth: "none", NeedsLogin: false, Rounds: []string{}, Match: "hostname contains 'skywalking'"},
}

func (s *Server) sites(_ context.Context, _ *mcp.CallToolRequest, _ Empty) (any, *ToolError) {
	var out SitesOutput
	for _, n := range site.Names() {
		info, ok := builtinInfo[n]
		info.Name, info.Source = n, "builtin"
		if !ok {
			info = SiteInfo{Name: n, Auth: "cookie", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "configured match_host", Source: "config"}
		}
		out.Sites = append(out.Sites, info)
	}
	return out, nil
}

func (s *Server) sessions(_ context.Context, _ *mcp.CallToolRequest, _ Empty) (any, *ToolError) {
	c, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	out := SessionsOutput{Sessions: []SessionInfo{}}
	for _, e := range c.cache.List() {
		auth := "cookie"
		if e.Session.Headers["Authorization"] != "" {
			auth = "bearer"
		}
		out.Sessions = append(out.Sessions, SessionInfo{Site: e.Site, BaseURL: e.Base, Auth: auth,
			ObtainedAt: fmtTime(e.ObtainedAt), ExpiresAt: fmtTime(e.Session.ExpiresAt), LastValidatedAt: fmtTime(e.ValidatedAt)})
	}
	return out, nil
}

func (s *Server) logout(_ context.Context, _ *mcp.CallToolRequest, in LogoutInput) (any, *ToolError) {
	c, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	switch {
	case in.All && in.URL != "", !in.All && in.URL == "":
		return nil, errf("invalid_argument", false, "give exactly one of url or all")
	case in.All:
		return LogoutOutput{Removed: c.cache.Clear()}, nil
	}
	var base *url.URL
	if strings.HasPrefix(strings.ToLower(in.URL), dbsite.Scheme+":") {
		_, b, terr := s.databaseTarget(in.URL)
		if terr != nil {
			return nil, terr
		}
		base = b
	} else {
		b, terr := baseOf(in.URL)
		if terr != nil {
			return nil, terr
		}
		base = s.root(b)
	}
	n := 0
	if c.cache.Delete(session.Key(base)) {
		n++
	}
	if c.mgr.CancelBase(session.Key(base)) {
		n++
	}
	return LogoutOutput{Removed: n}, nil
}

// alias returns the configured site name for a host, if any.
func aliasOf(cfg *config.Config, base *url.URL) string {
	for _, k := range []string{base.Host, base.Hostname()} {
		if n, ok := cfg.Aliases[k]; ok {
			return n
		}
	}
	return ""
}

// rootOf applies roots: for sites served under a path prefix the drivers need the full base URL.
func rootOf(cfg *config.Config, base *url.URL) *url.URL {
	for _, k := range []string{base.Host, base.Hostname()} {
		if r, ok := cfg.Roots[k]; ok {
			if u, err := url.Parse(strings.TrimRight(r, "/")); err == nil && u.Scheme != "" && u.Host == base.Host {
				return u
			}
		}
	}
	return base
}

// checkHost refuses a base URL the configuration does not allow: a host outside security.allowed_hosts, or
// one of this machine's own addresses unless security.allow_local_addresses says otherwise. Names are checked
// here for a clear message; the HTTP client checks the address it actually connects to as well.
func checkHost(cfg *config.Config, base *url.URL) *ToolError {
	if !hostAllowedBy(cfg, base) {
		e := errf("host_not_allowed", false, "%s is not in security.allowed_hosts", base.Host)
		e.Hint = "Ask the user to allow this host in the securl config; do not try other spellings of it."
		return e
	}
	if !cfg.Security.AllowLocalAddresses && netguard.LocalHost(base.Host) {
		e := errf("host_not_allowed", false, "%s is a local address; securl does not connect to this machine's own addresses unless security.allow_local_addresses is set", base.Host)
		e.Hint = "Ask the user to set security.allow_local_addresses in the securl config if this is intended; do not try other spellings of the address."
		return e
	}
	return nil
}

// hostAllowedBy applies security.allowed_hosts (empty means every host is allowed).
func hostAllowedBy(cfg *config.Config, base *url.URL) bool {
	if len(cfg.Security.AllowedHosts) == 0 {
		return true
	}
	for _, pat := range cfg.Security.AllowedHosts {
		for _, h := range []string{base.Host, base.Hostname()} {
			if ok, _ := path.Match(strings.ToLower(pat), strings.ToLower(h)); ok {
				return true
			}
		}
	}
	return false
}

func (s *Server) alias(base *url.URL) string     { return aliasOf(s.cfg, base) }
func (s *Server) root(base *url.URL) *url.URL    { return rootOf(s.cfg, base) }
func (s *Server) hostAllowed(base *url.URL) bool { return hostAllowedBy(s.cfg, base) }

// Resolve applies roots, aliases and allowed_hosts exactly as the login tools do and returns the driver and
// the base URL it would be given.
func Resolve(cfg *config.Config, raw, siteName string) (site.Driver, *url.URL, error) {
	base, terr := baseOf(raw)
	if terr != nil {
		return nil, nil, terr
	}
	if terr := checkHost(cfg, base); terr != nil {
		return nil, nil, terr
	}
	if siteName == "" {
		siteName = aliasOf(cfg, base)
	}
	base = rootOf(cfg, base)
	d, err := site.Resolve(siteName, base)
	if err != nil {
		return nil, nil, errf("unsupported_site", false, "%v", err)
	}
	return d, base, nil
}

// HostAllowed applies security.allowed_hosts to a base URL (an empty list allows every host).
func HostAllowed(cfg *config.Config, base *url.URL) bool { return hostAllowedBy(cfg, base) }
