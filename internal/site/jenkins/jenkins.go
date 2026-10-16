// Package jenkins logs in to Jenkins through its login form (works with the built-in user database and
// with the LDAP plugin, which share the same form).
//
// Verified against the Jenkins 2.226 source: GET /login renders <form name="login" action=...> with
// j_username, j_password and from. In 2.226 the action is "j_acegi_security_check" (newer releases use
// "j_spring_security_check"), so the driver reads it from the page. A failed login redirects to /loginError;
// /whoAmI/api/json (an unprotected root action) tells whether the session is authenticated. The CSRF crumb
// of DefaultCrumbIssuer is tied to the session (and client IP), so it is fetched after login and returned
// as a header (Jenkins-Crumb) for the agent's POST requests.
//
// Core Jenkins has no second factor, and none is guessed here: if the form is accepted but the session is
// still anonymous (for instance because a 2FA plugin adds a step), the driver says so.
package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "jenkins" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "jenkins")
}

var (
	formTag   = regexp.MustCompile(`(?is)<form[^>]*\bname=["']login["'][^>]*>`)
	actionAtt = regexp.MustCompile(`(?i)\baction=["']([^"']+)["']`)
)

func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	c := site.JarClient(hc)
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	loginURL := base.String() + "/login?from=%2F"
	page, status, err := get(ctx, c, loginURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("%w: %s answered %d (is this Jenkins?)", site.ErrLoginRejected, loginURL, status)
	}
	action := "j_acegi_security_check"
	if tag := formTag.FindString(page); tag != "" {
		if m := actionAtt.FindStringSubmatch(tag); m != nil {
			action = m[1]
		}
	} else {
		return nil, fmt.Errorf("%w: no login form on %s (is this Jenkins, and is its security realm password based?)", site.ErrLoginRejected, loginURL)
	}
	lu, _ := url.Parse(loginURL)
	au, err := lu.Parse(action)
	if err != nil {
		return nil, fmt.Errorf("%w: bad login form action %q", site.ErrLoginRejected, action)
	}

	form := url.Values{"j_username": {creds["username"]}, "j_password": {creds["password"]}, "from": {"/"}, "Submit": {"Sign in"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, au.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	site.ReadBody(resp)
	finalPath := resp.Request.URL.Path
	if strings.HasSuffix(finalPath, "/loginError") {
		return nil, fmt.Errorf("%w: invalid username or password", site.ErrBadCredentials)
	}

	who, err := whoAmI(ctx, c, base)
	if err != nil {
		return nil, err
	}
	if !who.loggedIn() {
		return nil, fmt.Errorf("%w: the login form was accepted (ended at %s) but the session is still anonymous; a second login step (for example a 2FA plugin) is not supported", site.ErrLoginRejected, finalPath)
	}

	s := &site.Session{Cookies: site.CookiesFrom(c, base), Headers: map[string]string{}, Tokens: map[string]string{"user": who.Name}}
	if field, crumb := fetchCrumb(ctx, c, base); crumb != "" {
		s.Headers[field] = crumb
		s.Tokens["crumb"], s.Tokens["crumb_field"] = crumb, field
	}
	return s, nil
}

func get(ctx context.Context, c *http.Client, u string) (string, int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return site.ReadBody(resp), resp.StatusCode, nil
}

type who struct {
	Authenticated bool   `json:"authenticated"`
	Anonymous     bool   `json:"anonymous"`
	Name          string `json:"name"`
}

// loggedIn: an anonymous visitor is reported with authenticated=true too (anonymous tokens count as
// authenticated), so the separate anonymous flag (or the name "anonymous") decides.
func (w who) loggedIn() bool {
	return w.Authenticated && !w.Anonymous && w.Name != "" && w.Name != "anonymous"
}

func whoAmI(ctx context.Context, c *http.Client, base *url.URL) (*who, error) {
	body, status, err := get(ctx, c, base.String()+"/whoAmI/api/json")
	if err != nil {
		return nil, err
	}
	var w who
	if status != 200 || json.Unmarshal([]byte(body), &w) != nil {
		return nil, fmt.Errorf("%w: /whoAmI/api/json answered %d: %s", site.ErrLoginRejected, status, site.Clip(body, 120))
	}
	return &w, nil
}

// fetchCrumb returns the CSRF header name and value; empty when CSRF protection is off.
func fetchCrumb(ctx context.Context, c *http.Client, base *url.URL) (field, crumb string) {
	body, status, err := get(ctx, c, base.String()+"/crumbIssuer/api/json")
	if err != nil || status != 200 {
		return "", ""
	}
	var cr struct {
		Crumb string `json:"crumb"`
		Field string `json:"crumbRequestField"`
	}
	if json.Unmarshal([]byte(body), &cr) != nil || cr.Crumb == "" {
		return "", ""
	}
	if cr.Field == "" {
		cr.Field = "Jenkins-Crumb"
	}
	return cr.Field, cr.Crumb
}

// Probe checks that the session is still authenticated (anonymous read access can make other pages
// look fine even when it is not).
func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/whoAmI/api/json", nil)
	req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	resp, err := hc.Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	body := site.ReadBody(resp)
	if site.TemporaryStatus(resp.StatusCode) {
		return site.ProbeStatus("jenkins", resp.StatusCode)
	}
	var w who
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &w) != nil || !w.loggedIn() {
		return fmt.Errorf("jenkins session is no longer authenticated")
	}
	return nil
}

// Inspect reports the login form action and whether the session endpoint answers.
func (driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	c := site.JarClient(hc)
	page, status, err := get(ctx, c, base.String()+"/login?from=%2F")
	if err != nil {
		return nil, err
	}
	if status != 200 || !formTag.MatchString(page) {
		return nil, fmt.Errorf("%s/login did not return a Jenkins login form (HTTP %d): wrong URL (context path? use roots:) or a non-password security realm", base, status)
	}
	action := "j_acegi_security_check"
	if m := actionAtt.FindStringSubmatch(formTag.FindString(page)); m != nil {
		action = m[1]
	}
	out := []string{"login form found, it posts to " + action}
	if w, err := whoAmI(ctx, c, base); err == nil {
		out = append(out, fmt.Sprintf("/whoAmI/api/json answers (anonymous=%v): success will be decided by it", w.Anonymous))
	} else {
		out = append(out, "warning: "+err.Error())
	}
	return out, nil
}
