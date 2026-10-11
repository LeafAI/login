package mcpserver

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/proxy"
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
	// A request only ever uses a session that exists: asking a person to type a password is session_open's job.
	e, ok := k.cache.GetWithin(ctx, base, s.hc, sessionFreshness)
	if !ok {
		e := errf("no_session", false, "there is no valid session for %s", base.Host)
		e.Hint = noSessionHint
		return nil, e
	}
	px := &proxy.Proxy{HC: s.hc, MaxResponseBytes: in.MaxResponseBytes}
	res, err := px.Do(ctx, e.Session, proxy.Request{
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
	s.audit.Record(audit.Event{Event: "request", Site: e.Site, Host: base.Host, Method: in.Method, Path: res.FinalPathOr(in.Path),
		Status: res.Status, Bytes: res.TotalBytes})
	out := RequestOutput{Status: res.Status, Headers: res.Headers, Body: res.Body, BodyIsBase64: res.BodyIsBase64,
		Truncated: res.Truncated, TotalBytes: res.TotalBytes, Redactions: res.Redactions, Withheld: res.Withheld, FinalPath: res.FinalPath}
	if res.Status == 401 {
		out.Hint = requestExpiredHint
	}
	return out, nil
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
