// Package archery implements the Archery (SQL audit platform) login driver and API client.
//
// Endpoints and payloads follow the Archery source (github.com/hhyo/Archery, master): the ajax login
// at /authenticate/, the 2FA verification at /api/v1/user/2fa/verify/, and the session-authenticated
// REST API under /api/v1/ (sqlquery, workflow/sqlcheck, sql-workflows). Older Archery releases that
// predate those REST endpoints are not supported. The package is tested against a fake server that
// mimics this contract, not against a live Archery.
package archery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "archery" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "archery")
}

type envelope struct {
	Status int             `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

func csrfOf(c *http.Client, base *url.URL) string {
	for _, ck := range site.CookiesFrom(c, base) {
		if ck.Name == "csrftoken" {
			return ck.Value
		}
	}
	return ""
}

func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	c := site.JarClient(hc)
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/login/", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	site.ReadBody(resp)
	if csrfOf(c, base) == "" {
		return nil, fmt.Errorf("%w: no csrftoken from /login/ (is this Archery?)", site.ErrLoginRejected)
	}

	env, err := postForm(ctx, c, base, "/authenticate/", url.Values{"username": {creds["username"]}, "password": {creds["password"]}})
	if err != nil {
		return nil, err
	}
	if env.Status != 0 {
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, site.Clip(env.Msg, 200))
	}
	// Archery answers data=null when the user is logged in. With 2FA it answers a temporary session
	// key, which its own login page stores as the sessionid cookie before opening /login/2fa/.
	var tempKey string
	json.Unmarshal(env.Data, &tempKey)
	if tempKey != "" {
		c.Jar.SetCookies(base, []*http.Cookie{{Name: "sessionid", Value: tempKey, Path: "/"}})
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		v, err := postForm(ctx, c, base, "/api/v1/user/2fa/verify/", url.Values{
			"engineer": {creds["username"]}, "otp": {strings.TrimSpace(code["code"])}, "auth_type": {"totp"}})
		if err != nil {
			return nil, err
		}
		if v.Status != 0 {
			if strings.Contains(v.Msg, "未配置") {
				return nil, fmt.Errorf("%w: Archery enforces 2FA but this account has not set it up; configure it in Archery first", site.ErrLoginRejected)
			}
			return nil, fmt.Errorf("%w: invalid two-factor code: %s", site.ErrBadCredentials, site.Clip(v.Msg, 200))
		}
	}
	s := &site.Session{Cookies: site.CookiesFrom(c, base), Headers: map[string]string{"X-CSRFToken": csrfOf(c, base)},
		Tokens: map[string]string{"api": detectGeneration(ctx, base, c)}}
	has := false
	for _, ck := range s.Cookies {
		has = has || ck.Name == "sessionid"
	}
	if !has {
		return nil, fmt.Errorf("%w: no sessionid cookie was issued", site.ErrLoginRejected)
	}
	return s, nil
}

// detectGeneration tells the newer REST API (has /api/v1/sqlquery/) from Archery 1.x (404 there).
func detectGeneration(ctx context.Context, base *url.URL, c *http.Client) string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/v1/sqlquery/instances/", nil)
	resp, err := site.NoRedirect(c).Do(req)
	if err != nil {
		return GenLegacy
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return GenREST
	}
	return GenLegacy
}

func postForm(ctx context.Context, c *http.Client, base *url.URL, path string, form url.Values) (*envelope, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRFToken", csrfOf(c, base))
	req.Header.Set("Referer", base.String()+"/login/")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	raw := site.ReadBody(resp)
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, fmt.Errorf("%w: archery %s answered %d with non-JSON: %s", site.ErrLoginRejected, path, resp.StatusCode, site.Clip(raw, 120))
	}
	return &env, nil
}

// Probe checks the session with an endpoint every logged-in user can call. Unauthenticated page requests
// are redirected to /login/ by Archery's middleware, API requests answer 403.
func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	path := "/group/user_all_instances/"
	if s.Tokens["api"] == GenREST {
		path = "/api/v1/sqlquery/instances/"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+path, nil)
	req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	resp, err := site.NoRedirect(hc).Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	resp.Body.Close()
	return site.ProbeStatus("archery", resp.StatusCode)
}

// Inspect reports the Archery generation (REST API or 1.x) and that the login page is reachable.
func (driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	c := site.JarClient(hc)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/login/", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	site.ReadBody(resp)
	if csrfOf(c, base) == "" {
		return nil, fmt.Errorf("no csrftoken from %s/login/: not Archery, or a path prefix is missing (use roots:)", base)
	}
	// Unauthenticated, the REST route answers 403 JSON when it exists and 404 on Archery 1.x.
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/v1/sqlquery/instances/", nil)
	probe, err := site.NoRedirect(c).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	probe.Body.Close()
	if probe.StatusCode == http.StatusNotFound {
		return []string{"login page found", "Archery 1.x generation (verified against v1.12.0): ajax endpoints /query/, /execute/, /cancel/ are used"}, nil
	}
	return []string{"login page found", fmt.Sprintf("newer REST generation (/api/v1/sqlquery answered %d without a session): /api/v1/sql-workflows is used", probe.StatusCode)}, nil
}
