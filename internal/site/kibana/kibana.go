// Package kibana logs in to Kibana's built-in "basic" security provider.
//
// Kibana's built-in basic provider has no TOTP. As a courtesy for setups with a custom provider or a
// fronting auth layer, a 401 whose body mentions OTP/MFA makes the driver ask for a "totp" round and
// retry with params.otp. That path is a guess that has never run against a real second factor.
package kibana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/login/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "kibana" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "kibana")
}

func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	c := site.JarClient(hc)
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	params := map[string]string{"username": creds["username"], "password": creds["password"]}
	status, body, err := attempt(ctx, c, base, params)
	if err != nil {
		return nil, err
	}
	if status == 401 && site.Looks2FA(body) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		params["otp"] = strings.TrimSpace(code["code"])
		if status, body, err = attempt(ctx, c, base, params); err != nil {
			return nil, err
		}
	}
	switch {
	case status == 200 || status == 204:
	case status == 401:
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, site.Clip(body, 200))
	default:
		return nil, fmt.Errorf("%w: kibana returned %d: %s", site.ErrLoginRejected, status, site.Clip(body, 200))
	}
	s := &site.Session{Cookies: site.CookiesFrom(c, base)}
	if len(s.Cookies) == 0 {
		return nil, fmt.Errorf("%w: no session cookie was issued", site.ErrLoginRejected)
	}
	return s, nil
}

func attempt(ctx context.Context, c *http.Client, base *url.URL, params map[string]string) (int, string, error) {
	status, body, err := doLogin(ctx, c, base, "/internal/security/login", map[string]any{
		"providerType": "basic", "providerName": "basic", "currentURL": base.String() + "/login", "params": params})
	if err == nil && status == 404 { // Kibana 7.x without the internal route
		status, body, err = doLogin(ctx, c, base, "/api/security/v1/login", map[string]any{
			"username": params["username"], "password": params["password"]})
	}
	return status, body, err
}

func doLogin(ctx context.Context, c *http.Client, base *url.URL, path string, payload any) (int, string, error) {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("x-elastic-internal-origin", "kibana")
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return resp.StatusCode, site.ReadBody(resp), nil
}

func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/internal/security/me", nil)
	req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("x-elastic-internal-origin", "kibana")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("kibana session invalid: %s", resp.Status)
	}
	return nil
}
