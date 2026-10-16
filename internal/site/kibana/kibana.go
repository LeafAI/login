// Package kibana logs in to Kibana's built-in basic (username/password) security provider.
//
// Verified against the Kibana source: POST /internal/security/login takes
// {providerType, providerName, currentURL, params:{username,password}} and answers {"location": ...} with the
// session cookie. providerName must match the configured provider (not always "basic"), so it is discovered
// from the unauthenticated GET /internal/security/login_state.
//
// The body depends on the Kibana version. 8.x takes the nested form above. 7.9.3 (checked against a live site: browser
// capture plus probes) takes a flat {username,password} and answers 400 "[request body.providerType]: definition for
// this key is missing" to the nested one. The version is read from the login page's injected metadata; when it cannot
// be read, that 400 names the key that is not accepted and the flat form is used. A 400 is a validation failure before
// any authentication, so it never counts as a failed login and cannot lock the account.
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
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/LeafAI/securl/internal/site"
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
	ptype, pname := loginProvider(ctx, c, base)
	style := loginStyle(ctx, c, base)
	status, body, err := attempt(ctx, c, base, ptype, pname, params, style)
	if err != nil {
		return nil, err
	}
	if status == 400 && style == styleNested && rejectsNestedBody(body) { // learned from the answer
		style = styleFlat
		if status, body, err = attempt(ctx, c, base, ptype, pname, params, style); err != nil {
			return nil, err
		}
	}
	if status == 401 && site.Looks2FA(body) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		params["otp"] = strings.TrimSpace(code["code"])
		if status, body, err = attempt(ctx, c, base, ptype, pname, params, style); err != nil {
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

// loginProvider returns the first provider that uses the login form (basic or token); "basic"/"basic"
// when the state endpoint is unavailable.
func loginProvider(ctx context.Context, c *http.Client, base *url.URL) (typ, name string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/internal/security/login_state", nil)
	req.Header.Set("x-elastic-internal-origin", "kibana")
	resp, err := c.Do(req)
	if err != nil {
		return "basic", "basic"
	}
	var st struct {
		Selector struct {
			Providers []struct {
				Type          string `json:"type"`
				Name          string `json:"name"`
				UsesLoginForm bool   `json:"usesLoginForm"`
			} `json:"providers"`
		} `json:"selector"`
	}
	if resp.StatusCode == 200 {
		json.Unmarshal([]byte(site.ReadBody(resp)), &st)
	} else {
		resp.Body.Close()
	}
	for _, p := range st.Selector.Providers {
		if p.UsesLoginForm && p.Name != "" {
			return p.Type, p.Name
		}
	}
	return "basic", "basic"
}

// Login body formats of POST /internal/security/login.
const (
	styleNested = iota // 8.x: {providerType, providerName, currentURL, params:{username,password}}
	styleFlat          // 7.x: {username, password}
)

var versionRe = regexp.MustCompile(`"version":"(\d+)\.(\d+)\.(\d+)"`)

// loginStyle reads the Kibana version from the login page (it is in the injected metadata) and picks the body
// format: flat before 8, nested from 8. Without a readable version the nested form is tried first.
func loginStyle(ctx context.Context, c *http.Client, base *url.URL) int {
	_, major, ok := kibanaVersion(ctx, c, base)
	if ok && major < 8 {
		return styleFlat
	}
	return styleNested
}

// kibanaVersion returns the version text shown on the login page, such as "7.9.3", and its major number.
func kibanaVersion(ctx context.Context, c *http.Client, base *url.URL) (string, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/login", nil)
	if err != nil {
		return "", 0, false
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, false
	}
	page := html.UnescapeString(site.ReadBody(resp))
	m := versionRe.FindStringSubmatch(page)
	if m == nil {
		return "", 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return m[1] + "." + m[2] + "." + m[3], n, true
}

// rejectsNestedBody reports whether a 400 says the nested provider keys are not accepted, or that username is
// missing at the top level: the signature of a Kibana that takes the flat body.
func rejectsNestedBody(body string) bool {
	return strings.Contains(body, "request body.providerType") || strings.Contains(body, "request body.username") ||
		strings.Contains(body, "request body.providerName") || strings.Contains(body, "request body.params")
}

func attempt(ctx context.Context, c *http.Client, base *url.URL, ptype, pname string, params map[string]string, style int) (int, string, error) {
	payload := map[string]any{"providerType": ptype, "providerName": pname, "currentURL": base.String() + "/login", "params": params}
	if style == styleFlat {
		payload = map[string]any{"username": params["username"], "password": params["password"]}
		if otp := params["otp"]; otp != "" {
			payload["otp"] = otp
		}
	}
	status, body, err := doLogin(ctx, c, base, "/internal/security/login", payload)
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
		return site.Unreachable(err)
	}
	resp.Body.Close()
	return site.ProbeStatus("kibana", resp.StatusCode)
}

// Inspect reports the login providers Kibana publishes, its version when the login page shows it, and which body
// format a login will use. It never attempts a login.
func (driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	c := site.JarClient(hc)
	typ, name := loginProvider(ctx, c, base)
	out := []string{fmt.Sprintf("login provider that will be used: type %q, name %q", typ, name)}
	if typ == "basic" && name == "basic" {
		out = append(out, "(this is also the fallback when /internal/security/login_state is unavailable)")
	}
	if version, major, ok := kibanaVersion(ctx, c, base); ok {
		form := "nested provider/params body (8.x)"
		if major < 8 {
			form = "flat {username,password} body (7.x)"
		}
		out = append(out, fmt.Sprintf("Kibana %s: the login uses the %s", version, form))
	} else {
		out = append(out, "Kibana version not shown on the login page: the nested body is tried first, and the flat one if Kibana rejects it")
	}
	return out, nil
}
