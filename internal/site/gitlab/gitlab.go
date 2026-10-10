// Package gitlab logs in to GitLab through the sign-in form (with optional TOTP 2FA).
//
// Two page generations are handled, both verified against the GitLab source: the classic server-rendered
// forms (inputs named user[login], user[password], user[otp_attempt]) and current GitLab, whose sign-in and
// 2FA steps are Vue components (the 2FA page only carries <div id="js-2fa" data-totp-enabled=...>). Both post
// the same fields to /users/sign_in; the CSRF token comes from a hidden input or the csrf-token meta tag.
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

	if isTwoFactorPage(body) { // 2FA required
		if !totpAvailable(body) {
			return nil, fmt.Errorf("%w: this account's second factor is WebAuthn/passkey or email only, which is not supported (TOTP is not enabled)", site.ErrLoginRejected)
		}
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		body, finalPath, err = post(ctx, c, base, url.Values{
			"authenticity_token": {csrf(body)},
			"user[otp_attempt]":  {strings.TrimSpace(code["code"])},
			"user[remember_me]":  {"0"},
			"two_factor_method":  {"totp"},
		})
		if err != nil {
			return nil, err
		}
		if isTwoFactorPage(body) {
			return nil, fmt.Errorf("%w: invalid two-factor code", site.ErrBadCredentials)
		}
	}
	switch {
	case strings.HasPrefix(finalPath, "/users/sign_in") || strings.Contains(body, `name="user[password]"`):
		return nil, fmt.Errorf("%w: invalid login or password", site.ErrBadCredentials)
	}
	s := &site.Session{Cookies: site.CookiesFrom(c, base)}
	if !hasCookie(s, "_gitlab_session") {
		return nil, fmt.Errorf("%w: no session cookie was issued", site.ErrLoginRejected)
	}
	return s, nil
}

var (
	js2fa       = regexp.MustCompile(`id=["']js-2fa["']`)
	totpEnabled = regexp.MustCompile(`data-totp-enabled=["'](true|false)["']`)
)

// isTwoFactorPage recognises both the classic form and the Vue mount point of the 2FA step.
func isTwoFactorPage(body string) bool {
	return strings.Contains(body, `name="user[otp_attempt]"`) || js2fa.MatchString(body)
}

// totpAvailable is false only when the modern page explicitly says TOTP is not enabled for the account.
func totpAvailable(body string) bool {
	if m := totpEnabled.FindStringSubmatch(body); m != nil {
		return m[1] == "true"
	}
	return true
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
