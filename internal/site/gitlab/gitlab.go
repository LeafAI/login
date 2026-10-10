// Package gitlab logs in to GitLab through the sign-in form (with optional TOTP 2FA).
package gitlab

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/LeafAI/login/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "gitlab" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "gitlab")
}

var (
	tokenRe  = regexp.MustCompile(`name="authenticity_token"[^>]*value="([^"]+)"`)
	tokenRe2 = regexp.MustCompile(`value="([^"]+)"[^>]*name="authenticity_token"`)
	metaRe   = regexp.MustCompile(`<meta[^>]*name="csrf-token"[^>]*content="([^"]+)"`)
)

func csrf(body string) string {
	for _, re := range []*regexp.Regexp{tokenRe, tokenRe2, metaRe} {
		if m := re.FindStringSubmatch(body); m != nil {
			return html.UnescapeString(m[1])
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
	page, err := get(ctx, c, base, "/users/sign_in")
	if err != nil {
		return nil, err
	}
	tok := csrf(page)
	if tok == "" {
		return nil, fmt.Errorf("%w: gitlab sign-in page has no CSRF token (is this GitLab?)", site.ErrLoginRejected)
	}
	body, finalPath, err := post(ctx, c, base, url.Values{
		"authenticity_token": {tok},
		"user[login]":        {creds["username"]},
		"user[password]":     {creds["password"]},
		"user[remember_me]":  {"0"},
	})
	if err != nil {
		return nil, err
	}

	if strings.Contains(body, `name="user[otp_attempt]"`) { // 2FA required
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		body, finalPath, err = post(ctx, c, base, url.Values{
			"authenticity_token": {csrf(body)},
			"user[otp_attempt]":  {strings.TrimSpace(code["code"])},
			"user[remember_me]":  {"0"},
		})
		if err != nil {
			return nil, err
		}
		if strings.Contains(body, `name="user[otp_attempt]"`) {
			return nil, fmt.Errorf("%w: invalid two-factor code", site.ErrBadCredentials)
		}
	}
	switch {
	case strings.Contains(body, "webauthn") && strings.Contains(finalPath, "sign_in"):
		return nil, fmt.Errorf("%w: this account requires a WebAuthn/U2F device, which is not supported", site.ErrLoginRejected)
	case strings.HasPrefix(finalPath, "/users/sign_in") || strings.Contains(body, `name="user[password]"`):
		return nil, fmt.Errorf("%w: invalid login or password", site.ErrBadCredentials)
	}
	s := &site.Session{Cookies: site.CookiesFrom(c, base)}
	if !hasCookie(s, "_gitlab_session") {
		return nil, fmt.Errorf("%w: no session cookie was issued", site.ErrLoginRejected)
	}
	return s, nil
}

func hasCookie(s *site.Session, name string) bool {
	for _, c := range s.Cookies {
		if c.Name == name {
			return true
		}
	}
	return false
}

func get(ctx context.Context, c *http.Client, base *url.URL, path string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+path, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return site.ReadBody(resp), nil
}

func post(ctx context.Context, c *http.Client, base *url.URL, form url.Values) (body, finalPath string, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/users/sign_in", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	finalPath = resp.Request.URL.Path
	return site.ReadBody(resp), finalPath, nil
}

func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/v4/user", nil)
	req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("gitlab session invalid: %s", resp.Status)
	}
	return nil
}
