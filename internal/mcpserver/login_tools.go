package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/flow"
	"github.com/LeafAI/login/internal/session"
	"github.com/LeafAI/login/internal/site"
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
	f := s.mgr.Get(in.LoginID)
	if f == nil {
		return nil, errf("invalid_argument", false, "login_id %q not found or expired; call login again", in.LoginID)
	}
	out, terr := s.await(ctx, req, f, s.maxBlock(in.MaxBlockSeconds))
	if terr != nil {
		return nil, terr
	}
	return out, nil
}

// ensureLogin returns a valid session for the site: from cache, or by running a login flow.
func (s *Server) ensureLogin(ctx context.Context, req *mcp.CallToolRequest, raw, siteName, reason string, force, wait bool, max time.Duration) (*LoginOutput, *ToolError) {
	base, terr := baseOf(raw)
	if terr != nil {
		return nil, terr
	}
	d, err := site.Resolve(siteName, base)
	if err != nil {
		return nil, errf("unsupported_site", false, "%v", err)
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
		if e, ok := s.cache.Get(ctx, base, s.hc); ok {
			out := sessionOutput(e.Site, base, e.Session)
			out.Cached = true
			return &out, nil
		}
	} else {
		s.cache.Delete(session.Key(base))
	}
	f := s.mgr.Start(d, base, reason, s.hc, func(f *flow.Flow, r flow.Result) {
		if r.Err == nil {
			s.cache.Put(f.Base, d, r.Session)
		}
	})
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
		WaitingFor: sn.Mode, Round: sn.Round, ExpiresAt: fmtTime(sn.ExpiresAt), NextTool: "login_wait"}
}

func sessionOutput(name string, base *url.URL, sess *site.Session) LoginOutput {
	out := LoginOutput{Status: "ok", Site: name, BaseURL: base.String(), Headers: sess.Headers, Tokens: sess.Tokens, ExpiresAt: fmtTime(sess.ExpiresAt)}
	parts := make([]string, 0, len(sess.Cookies))
	for _, c := range sess.Cookies {
		parts = append(parts, c.Name+"="+c.Value)
		co := CookieOut{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Secure: c.Secure, HTTPOnly: c.HttpOnly}
		if !c.Expires.IsZero() {
			co.Expires = fmtTime(c.Expires)
		}
		out.Cookies = append(out.Cookies, co)
	}
	out.CookieHeader = strings.Join(parts, "; ")
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
	switch {
	case errors.As(err, &rj):
		e := errf("user_rejected", false, "%s", rj.Error())
		e.Hint = "The human declined the login request. Do not retry unless the user asks you to."
		return e
	case errors.Is(err, flow.ErrHumanTimeout):
		e := errf("human_timeout", true, "%v", err)
		e.Hint = "Nobody completed the login page in time. Ask the user to watch DingTalk, then call login again."
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
	"kibana":      {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "hostname contains 'kibana'"},
	"kubesphere":  {Auth: "bearer", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "hostname contains 'kubesphere'"},
	"nightingale": {Auth: "bearer", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "hostname contains 'nightingale' or 'n9e'"},
	"archery":     {Auth: "cookie", NeedsLogin: true, Rounds: []string{"login", "totp?"}, Match: "hostname contains 'archery'"},
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
	out := SessionsOutput{Sessions: []SessionInfo{}}
	for _, e := range s.cache.List() {
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
	switch {
	case in.All && in.URL != "", !in.All && in.URL == "":
		return nil, errf("invalid_argument", false, "give exactly one of url or all")
	case in.All:
		return LogoutOutput{Removed: s.cache.Clear()}, nil
	}
	base, terr := baseOf(in.URL)
	if terr != nil {
		return nil, terr
	}
	n := 0
	if s.cache.Delete(session.Key(base)) {
		n++
	}
	if s.mgr.CancelBase(session.Key(base)) {
		n++
	}
	return LogoutOutput{Removed: n}, nil
}
