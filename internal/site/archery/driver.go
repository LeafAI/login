// Package archery implements the Archery (SQL audit platform) login driver and API client.
//
// The endpoints used here follow Archery's web UI (Django views). They have been exercised against
// a fake server only; verify them against your Archery version before relying on them.
package archery

import (
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
	// Second factor: Archery's authenticate answer points at its 2FA page when the account has it.
	if needs2FA(env) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		v, err := postForm(ctx, c, base, "/twofa/verify/", url.Values{
			"engineer": {creds["username"]}, "otp": {strings.TrimSpace(code["code"])}, "auth_type": {"totp"}})
		if err != nil {
			return nil, err
		}
		if v.Status != 0 {
			return nil, fmt.Errorf("%w: invalid two-factor code: %s", site.ErrBadCredentials, site.Clip(v.Msg, 200))
		}
	}
	s := &site.Session{Cookies: site.CookiesFrom(c, base), Headers: map[string]string{"X-CSRFToken": csrfOf(c, base)}}
	has := false
	for _, ck := range s.Cookies {
		has = has || ck.Name == "sessionid"
	}
	if !has {
		return nil, fmt.Errorf("%w: no sessionid cookie was issued", site.ErrLoginRejected)
	}
	return s, nil
}

func needs2FA(env *envelope) bool {
	var data string
	json.Unmarshal(env.Data, &data)
	return strings.Contains(strings.ToLower(data), "2fa") || strings.Contains(strings.ToLower(env.Msg), "2fa")
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

// Probe fetches a login-protected page without following redirects.
func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/sqlquery/", nil)
	req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	resp, err := site.NoRedirect(hc).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("archery session invalid: %s", resp.Status)
	}
	return nil
}
