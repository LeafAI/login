// Package gitlab logs in to GitLab through the sign-in form (with optional TOTP 2FA).
//
// Two page generations are handled, both verified against the GitLab source: the classic server-rendered
// forms (inputs named user[login], user[password], user[otp_attempt]) and current GitLab, whose sign-in and
// 2FA steps are Vue components (the 2FA page only carries <div id="js-2fa" data-totp-enabled=...>). Both post
// the same fields to /users/sign_in; the CSRF token comes from a hidden input or the csrf-token meta tag.
//
// LDAP: when LDAP is enabled, the sign-in page has an LDAP tab whose form posts username/password to
// /users/auth/<provider>/callback (provider usually "ldapmain"); LDAP users can not use the standard form.
// The driver uses the LDAP form when the page offers one ("auto"), unless site_options say otherwise:
//
//	login_method: auto | ldap | standard      ldap_provider: ldapmain (name from the form action)
//
// After either form, a TOTP prompt (classic or Vue page) is answered through the OTP form at /users/sign_in.
package gitlab

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct {
	mu   sync.RWMutex
	opts map[string]string
}

func init() { site.Register(&driver{}) }

func (*driver) Name() string     { return "gitlab" }
func (*driver) NeedsLogin() bool { return true }
func (*driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "gitlab")
}

func (d *driver) Configure(opts map[string]string) {
	d.mu.Lock()
	d.opts = opts
	d.mu.Unlock()
}

// Options lists the settings `securl config` offers for GitLab.
func (*driver) Options() []site.Option {
	return []site.Option{
		{Key: "login_method", Label: "Which accounts do your users sign in with?",
			Help:    "auto detects an LDAP tab on the sign-in page; standard forces local GitLab accounts; ldap forces the LDAP form.",
			Choices: []string{"auto", "ldap", "standard"}, Default: "auto"},
		{Key: "ldap_provider", Label: "LDAP provider name (leave empty to detect it)",
			Help: "Only needed when the LDAP form posts to something other than the name found on the page, e.g. ldapmain.", FreeText: true},
	}
}

func (d *driver) option(k string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return strings.TrimSpace(d.opts[k])
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

func (d *driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	c := site.JarClient(hc)
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	page, err := get(ctx, c, base, "/users/sign_in")
	if err != nil {
		return nil, err
	}
	loginPath, fields, err := d.form(page, creds)
	if err != nil {
		return nil, err
	}
	tok := csrfIn(page, loginPath)
	if tok == "" {
		return nil, fmt.Errorf("%w: gitlab sign-in page has no CSRF token (is this GitLab?)", site.ErrLoginRejected)
	}
	fields.Set("authenticity_token", tok)
	body, finalPath, err := post(ctx, c, base, loginPath, fields)
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
		body, finalPath, err = post(ctx, c, base, "/users/sign_in", url.Values{
			"authenticity_token": {csrfIn(body, "/users/sign_in")},
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

var ldapForm = regexp.MustCompile(`action=["'](/users/auth/(ldap[A-Za-z0-9_]*)/callback)["']`)

// form decides which sign-in form to use and builds its fields (without the CSRF token).
func (d *driver) form(page string, creds site.Credentials) (path string, fields url.Values, err error) {
	method := d.option("login_method")
	provider := d.option("ldap_provider")
	var found string
	if m := ldapForm.FindStringSubmatch(page); m != nil {
		found = m[2]
	}
	useLDAP := method == "ldap" || (method == "" || method == "auto") && found != ""
	if useLDAP {
		if provider == "" {
			provider = found
		}
		if provider == "" {
			provider = "ldapmain"
		}
		return "/users/auth/" + provider + "/callback", url.Values{
			"username": {creds["username"]}, "password": {creds["password"]}, "remember_me": {"0"}}, nil
	}
	return "/users/sign_in", url.Values{
		"user[login]": {creds["username"]}, "user[password]": {creds["password"]}, "user[remember_me]": {"0"}}, nil
}

// csrfIn extracts the authenticity token of the form posting to action (Rails may issue per-form tokens),
// falling back to any token on the page.
func csrfIn(body, action string) string {
	for _, m := range regexp.MustCompile(`(?s)<form[^>]*action=["']`+regexp.QuoteMeta(action)+`["'].*?</form>`).FindAllString(body, -1) {
		if t := csrf(m); t != "" {
			return t
		}
	}
	return csrf(body)
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

func post(ctx context.Context, c *http.Client, base *url.URL, path string, form url.Values) (body, finalPath string, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	finalPath = strings.TrimPrefix(resp.Request.URL.Path, base.Path)
	return site.ReadBody(resp), finalPath, nil
}

func (*driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
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

// Inspect reports, from the unauthenticated sign-in page, which form Login would use.
func (d *driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	page, err := get(ctx, site.JarClient(hc), base, "/users/sign_in")
	if err != nil {
		return nil, err
	}
	if csrf(page) == "" {
		return nil, fmt.Errorf("no CSRF token on %s/users/sign_in: not GitLab, or an unexpected page", base)
	}
	var out []string
	if m := ldapForm.FindStringSubmatch(page); m != nil {
		out = append(out, fmt.Sprintf("LDAP sign-in tab found (provider %q): LDAP accounts are logged in through /users/auth/%s/callback", m[2], m[2]))
	} else {
		out = append(out, "no LDAP tab: the standard form (/users/sign_in) will be used")
	}
	switch m := d.option("login_method"); m {
	case "ldap", "standard":
		out = append(out, "site_options.gitlab.login_method forces: "+m)
	}
	if strings.Contains(page, `name="user[login]"`) {
		out = append(out, "classic server-rendered sign-in page (GitLab before the Vue sign-in)")
	} else {
		out = append(out, "sign-in form is rendered by JavaScript (current GitLab); the driver posts the same fields")
	}
	out = append(out, "a TOTP prompt after the password is detected on both classic and Vue 2FA pages")
	return out, nil
}
