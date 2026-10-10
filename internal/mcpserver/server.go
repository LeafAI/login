// Package mcpserver exposes the login tools over MCP.
package mcpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/site"
)

type Server struct {
	cfg *config.Config
	hc  *http.Client
}

func New(cfg *config.Config) *mcp.Server {
	s := &Server{cfg: cfg, hc: &http.Client{Timeout: 30 * time.Second}}
	m := mcp.NewServer(&mcp.Implementation{Name: "login", Version: "0.1.0"}, nil)
	mcp.AddTool(m, &mcp.Tool{
		Name:        "login",
		Description: "Log in to a website (gitlab, kibana, kubesphere, nightingale, archery, skywalking, ...) and return a valid cookie/token. A human may be asked for credentials through DingTalk; the agent never sees the password.",
	}, s.login)
	return m
}

type LoginInput struct {
	URL          string `json:"url" jsonschema:"website URL to log in to"`
	Site         string `json:"site,omitempty" jsonschema:"driver name; auto-detected from the URL when empty"`
	ForceRefresh bool   `json:"force_refresh,omitempty" jsonschema:"ignore cached session"`
}

type LoginOutput struct {
	Site         string            `json:"site"`
	CookieHeader string            `json:"cookie_header,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Tokens       map[string]string `json:"tokens,omitempty"`
	ExpiresAt    string            `json:"expires_at,omitempty"`
}

func (s *Server) login(ctx context.Context, _ *mcp.CallToolRequest, in LoginInput) (*mcp.CallToolResult, LoginOutput, error) {
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, LoginOutput{}, fmt.Errorf("invalid url %q", in.URL)
	}
	d, err := site.Resolve(in.Site, u)
	if err != nil {
		return nil, LoginOutput{}, err
	}
	if d.NeedsLogin() {
		return nil, LoginOutput{}, fmt.Errorf("%s: interactive login is not implemented yet", d.Name())
	}
	sess, err := d.Login(ctx, u, nil, s.hc)
	if err != nil {
		return nil, LoginOutput{}, err
	}
	return nil, toOutput(d.Name(), sess), nil
}

func toOutput(name string, s *site.Session) LoginOutput {
	out := LoginOutput{Site: name, Headers: s.Headers, Tokens: s.Tokens}
	for i, c := range s.Cookies {
		if i > 0 {
			out.CookieHeader += "; "
		}
		out.CookieHeader += c.Name + "=" + c.Value
	}
	if !s.ExpiresAt.IsZero() {
		out.ExpiresAt = s.ExpiresAt.Format(time.RFC3339)
	}
	return out
}
