package mcpserver

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/proxy"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site"
)

const (
	maxRequestTimeout   = 120 // seconds: the proxy's own cap, restated so that the schema and the refusal agree
	maxResponseBytesCap = 1 << 20
	// A session validated this recently is used without asking the site again: a request is not a login.
	sessionFreshness = 30 * time.Second
)

// request sends one HTTP request to a site with the session's credentials put in here and taken out of the answer.
func (s *Server) request(ctx context.Context, _ *mcp.CallToolRequest, in RequestInput) (any, *ToolError) {
	k, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	if in.TimeoutSeconds < 0 || in.TimeoutSeconds > maxRequestTimeout {
		return nil, errf("invalid_argument", false, "timeout_seconds must be between 1 and %d", maxRequestTimeout)
	}
	if in.MaxResponseBytes < 0 || in.MaxResponseBytes > maxResponseBytesCap {
		return nil, errf("invalid_argument", false, "max_response_bytes must be between 1 and %d", maxResponseBytesCap)
	}
	base, terr := s.siteBase(in.URL)
	if terr != nil {
		return nil, terr
	}
	siteName, sess, terr := s.sessionFor(ctx, k, base)
	if terr != nil {
		return nil, terr
	}
	if !s.cfg.Security.AllowArcheryRequests && s.isArchery(siteName, base) {
		return nil, archeryRequestRefusal()
	}
	px := &proxy.Proxy{HC: s.hc, MaxResponseBytes: in.MaxResponseBytes}
	res, err := px.Do(ctx, sess, proxy.Request{
		Base: base, Method: in.Method, Path: in.Path, Query: multiValues(in.Query), Headers: in.Headers,
		JSON: in.JSON, Form: multiValues(in.Form), Text: in.Text, Base64: in.Base64,
		FollowRedirects: in.FollowRedirects, Timeout: time.Duration(in.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, requestErr(err)
	}
	if res.NewSession != nil {
		k.cache.Update(base, res.NewSession)
	}
	s.audit.Record(audit.Event{Event: "request", Site: siteName, Host: base.Host, Method: in.Method, Path: res.FinalPathOr(in.Path),
		Status: res.Status, Bytes: res.TotalBytes})
	out := RequestOutput{Status: res.Status, Headers: res.Headers, Body: res.Body, BodyIsBase64: res.BodyIsBase64,
		Truncated: res.Truncated, TotalBytes: res.TotalBytes, Redactions: res.Redactions, Withheld: res.Withheld, FinalPath: res.FinalPath}
	if res.Status == 401 {
		out.Hint = requestExpiredHint
	}
	return out, nil
}

// archeryDriver is the driver name of Archery, the one site the request tool refuses unless the owner allows it.
const archeryDriver = "archery"

// isArchery tells whether a request is for Archery by every way the server knows: the driver the session was opened
// with, the configured alias, and the host name. An agent picks the site argument of session_open, so the driver
// name alone would let it register an Archery host as some other site and walk around the filter.
func (s *Server) isArchery(sessionSite string, base *url.URL) bool {
	if sessionSite == archeryDriver || s.alias(base) == archeryDriver {
		return true
	}
	d, err := site.Resolve(archeryDriver, nil)
	return err == nil && d.Match(base)
}

func archeryRequestRefusal() *ToolError {
	e := errf("request_not_allowed", false, "the request tool does not talk to Archery: a change there needs a person's approval, and this tool would skip it")
	e.Hint = "Use archery_instances, archery_groups, archery_query and archery_run_sql. Only the owner can lift this, with security.allow_archery_requests: true in the securl config; do not look for another way around it."
	return e
}

// sessionLost turns what session.Cache.Lookup said into the error a tool answers with. The three cases are told apart on
// purpose: no session (ask a person), a session the site refused (ask a person again), and a site that could not be reached
// just now (the session is kept; try again).
func sessionLost(err error, what, retryTool, noSession string) *ToolError {
	switch {
	case errors.Is(err, site.ErrUnreachable):
		e := errf("site_unreachable", true, "%s cannot be reached right now: %v", what, err)
		e.Hint = "The saved session is kept. Check the network or the VPN and try again; nobody needs to log in again."
		return e
	case errors.Is(err, session.ErrExpired), errors.Is(err, session.ErrRejected):
		e := errf("session_expired", true, "the saved session for %s is no longer accepted", what)
		e.Hint = retryTool
		return e
	}
	e := errf("no_session", false, "%s", noSession)
	return e
}

// sessionFor returns the session a request goes out with. A request only ever uses a session that exists: asking a
// person to type a password is session_open's job. A site that has no login at all has nothing to look up, and gets an
// empty session, so that no credential is added.
func (s *Server) sessionFor(ctx context.Context, k *core, base *url.URL) (string, *site.Session, *ToolError) {
	if d, err := site.Resolve(s.alias(base), base); err == nil && !d.NeedsLogin() {
		return d.Name(), &site.Session{}, nil
	}
	e, err := k.cache.Lookup(ctx, base, s.hc, s.fresh)
	if err != nil {
		te := sessionLost(err, base.Host, requestExpiredHint, "there is no valid session for "+base.Host)
		if te.Code == "no_session" {
			te.Hint = noSessionHint
		}
		return "", nil, te
	}
	return e.Site, e.Session, nil
}

// siteBase applies the same rules as every other tool to the URL an agent names: a valid URL, a host the policy allows
// (and not one of this machine's own addresses), the configured path prefix.
func (s *Server) siteBase(raw string) (*url.URL, *ToolError) {
	base, terr := baseOf(raw)
	if terr != nil {
		return nil, terr
	}
	if terr := checkHost(s.cfg, base); terr != nil {
		return nil, terr
	}
	return s.root(base), nil
}

func requestErr(err error) *ToolError {
	switch {
	case errors.Is(err, proxy.ErrInvalid):
		return errf("invalid_argument", false, "%v", err)
	case errors.Is(err, proxy.ErrSessionExpired):
		e := errf("session_expired", true, "%v", err)
		e.Hint = requestExpiredHint
		return e
	case errors.Is(err, proxy.ErrTooManyRedirects):
		return errf("site_unreachable", false, "%v", err)
	case errors.Is(err, proxy.ErrUnreachable), errors.Is(err, site.ErrUnreachable):
		return errf("site_unreachable", true, "%v", err)
	}
	return errf("internal", false, "the request failed")
}
