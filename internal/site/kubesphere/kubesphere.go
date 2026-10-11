// Package kubesphere logs in to KubeSphere 3.x.
//
// Verified against the KubeSphere v3.4.1 source:
//
//   - POST /oauth/token (grant_type=password) always authenticates against KubeSphere's *local* users:
//     the handler passes an empty identity provider. It needs client_id/client_secret (default kubesphere).
//
//   - Users of an external identity provider (LDAP) must use POST /oauth/login/{identityprovider} with
//     username/password, which answers the same token JSON.
//
//   - The configured providers are published at GET /kapis/config.kubesphere.io/v1alpha2/configs/oauth
//     as identityProviders: [{name, type: "LDAPIdentityProvider", ...}].
//
//   - What the web console really does (browser capture of POST /oauth/login/ldap): the body is JSON, and a
//     successful login answers 302 to "/" with the tokens only in Set-Cookie (token, refreshToken, expire in
//     milliseconds since the epoch). The body is {username, password, title} with title = the identity
//     provider's name (read from the console's login bundle); the password is sent as is, unlike the local
//     login, which encrypts it. A form-encoded body is not read, and then KubeSphere answers
//     200 {"status":500,"reason":"Internal Server Error"}, the same answer it gives for a wrong password or an
//     unreachable LDAP server. The driver therefore sends JSON to /oauth/login/{idp}, reads the cookies, and
//     words that answer so that it does not claim a cause it cannot know.
//
// Exactly one method is used per attempt, because failed attempts lock the account for a while.
// Option identity_provider: "" (auto: the first LDAP provider, else local), "local", or a provider name.
//
// Stock KubeSphere has no second factor. If an error response mentions OTP/MFA (custom setups) the driver
// asks for a "totp" round and retries with an "otp" field; that path is a guess.
package kubesphere

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct {
	mu   sync.RWMutex
	opts map[string]string
}

func init() { site.Register(&driver{}) }

func (*driver) Name() string     { return "kubesphere" }
func (*driver) NeedsLogin() bool { return true }
func (*driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "kubesphere")
}

func (d *driver) Configure(opts map[string]string) {
	d.mu.Lock()
	d.opts = opts
	d.mu.Unlock()
}

// Options lists the settings `login config` offers for KubeSphere.
func (*driver) Options() []site.Option {
	return []site.Option{
		{Key: "identity_provider", Label: "Which identity provider do your users log in with?",
			Help:    "auto uses the first LDAP provider KubeSphere publishes; local uses KubeSphere's built-in accounts; or type a provider name.",
			Choices: []string{"auto", "local"}, Default: "auto", FreeText: true},
	}
}

func (d *driver) option(k string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return strings.TrimSpace(d.opts[k])
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
	// The web console's error body: {"status":500,"reason":"Internal Server Error"} (HTTP status 200).
	WebStatus int    `json:"status"`
	Reason    string `json:"reason"`
}

func (d *driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	provider, err := d.provider(ctx, base, hc)
	if err != nil {
		return nil, err
	}
	form := url.Values{"username": {creds["username"]}, "password": {creds["password"]}}
	endpoint := "/oauth/token"
	if provider != "" {
		endpoint = "/oauth/login/" + url.PathEscape(provider)
	} else {
		form.Set("grant_type", "password")
		form.Set("client_id", "kubesphere")
		form.Set("client_secret", "kubesphere")
	}
	status, tr, raw, err := post(ctx, hc, base, endpoint, form, provider)
	if err != nil {
		return nil, err
	}
	if status != 200 && status != http.StatusFound && site.Looks2FA(raw) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		form.Set("otp", strings.TrimSpace(code["code"]))
		if status, tr, raw, err = post(ctx, hc, base, endpoint, form, provider); err != nil {
			return nil, err
		}
	}
	msg := site.Clip(firstNonEmpty(tr.Description, tr.Error, raw), 200)
	switch {
	case status == 200 && tr.AccessToken != "":
	case status == http.StatusFound && tr.AccessToken != "": // the web console's answer: tokens in Set-Cookie
	case status == 200 && tr.WebStatus >= 400:
		return nil, fmt.Errorf("%w: KubeSphere answered \"%s\" (status %d) for identity provider %q. It gives this same answer for a wrong username or password and for an LDAP server it cannot reach, so check the credentials first and, if they are right, that KubeSphere can reach LDAP",
			site.ErrLoginRejected, tr.Reason, tr.WebStatus, provider)
	case status == 429:
		return nil, fmt.Errorf("%w: too many failed attempts, KubeSphere has locked the account for a while (%s)", site.ErrLoginRejected, msg)
	case status == 400 && strings.Contains(strings.ToLower(msg), "not active"):
		return nil, fmt.Errorf("%w: the account is not active (%s)", site.ErrLoginRejected, msg)
	case status == 400 || status == 401 || status == 403:
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, msg)
	case status == 500 && provider != "":
		return nil, fmt.Errorf("%w: KubeSphere could not authenticate against identity provider %q (is LDAP reachable?): %s", site.ErrLoginRejected, provider, msg)
	default:
		return nil, fmt.Errorf("%w: kubesphere returned %d: %s", site.ErrLoginRejected, status, msg)
	}
	s := &site.Session{
		Headers: map[string]string{"Authorization": "Bearer " + tr.AccessToken},
		Tokens:  map[string]string{"access_token": tr.AccessToken, "refresh_token": tr.RefreshToken},
	}
	if provider != "" {
		s.Tokens["identity_provider"] = provider
	}
	if tr.ExpiresIn > 0 {
		s.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return s, nil
}

// provider returns the identity provider to log in with, "" meaning KubeSphere's local users.
func (d *driver) provider(ctx context.Context, base *url.URL, hc *http.Client) (string, error) {
	switch opt := d.option("identity_provider"); opt {
	case "local":
		return "", nil
	case "", "auto":
	default:
		return opt, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/kapis/config.kubesphere.io/v1alpha2/configs/oauth", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return "", nil // cannot discover: fall back to local users
	}
	var cfg struct {
		IdentityProviders []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"identityProviders"`
	}
	json.Unmarshal([]byte(site.ReadBody(resp)), &cfg)
	for _, p := range cfg.IdentityProviders {
		if p.Type == "LDAPIdentityProvider" && p.Name != "" {
			return p.Name, nil
		}
	}
	return "", nil
}

// post sends the login request. A non-empty provider selects the web endpoint /oauth/login/{provider}, which the
// console calls with a JSON body and answers with 302 + Set-Cookie; redirects are not followed so that the cookies
// of that answer can be read (they are what carry the tokens).
func post(ctx context.Context, hc *http.Client, base *url.URL, path string, form url.Values, provider string) (int, tokenResp, string, error) {
	var body, ct string
	if provider != "" {
		body, ct = jsonLoginBody(form, provider), "application/json"
	} else {
		body, ct = form.Encode(), "application/x-www-form-urlencoded"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	resp, err := site.NoRedirect(hc).Do(req)
	if err != nil {
		return 0, tokenResp{}, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	cookies := resp.Cookies()
	raw := site.ReadBody(resp)
	var tr tokenResp
	json.Unmarshal([]byte(raw), &tr)
	if resp.StatusCode == http.StatusFound {
		tr.fromCookies(cookies)
	}
	return resp.StatusCode, tr, raw, nil
}

// jsonLoginBody is the body of the console's LDAP login, read from its login bundle: {username, password, title}
// where title is the identity provider's name (the same name that is in the path). An otp field is added only when
// a one-time code was asked for.
func jsonLoginBody(form url.Values, provider string) string {
	m := map[string]string{"username": form.Get("username"), "password": form.Get("password"), "title": provider}
	if otp := form.Get("otp"); otp != "" {
		m["otp"] = otp
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// fromCookies reads the tokens the web console's login answer sets: token, refreshToken and expire
// (milliseconds since the epoch).
func (tr *tokenResp) fromCookies(cookies []*http.Cookie) {
	for _, c := range cookies {
		switch c.Name {
		case "token":
			tr.AccessToken = c.Value
		case "refreshToken":
			tr.RefreshToken = c.Value
		case "expire":
			if ms, err := strconv.ParseInt(c.Value, 10, 64); err == nil && ms > 0 {
				if secs := int(time.Until(time.UnixMilli(ms)).Seconds()); secs > 0 {
					tr.ExpiresIn = secs
				}
			}
		}
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// probePath is an authenticated API call every logged-in user may make: it lists the namespaces the user can see.
// It answers 200 for a valid token, 401 for a forged or revoked one and 403 for none (checked against a live
// v3.4.1). /oauth/userinfo is not usable: it is the OIDC endpoint for OAuth clients, and for a console token it
// redirects to the login page, which answers 200 to everybody.
const probePath = "/kapis/resources.kubesphere.io/v1alpha2/namespaces?limit=1"

// Probe checks the token with a real API call. Only a plain 200 counts as valid: redirects are not followed, so
// the login page can never be mistaken for a valid session.
func (*driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+probePath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", s.Headers["Authorization"])
	resp, err := site.NoRedirect(hc).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kubesphere token invalid: %s", resp.Status)
	}
	return nil
}

// Inspect reports which login method Login will use.
func (d *driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	p, err := d.provider(ctx, base, hc)
	if err != nil {
		return nil, err
	}
	if p == "" {
		return []string{"no LDAP identity provider found (or identity_provider: local): KubeSphere's local users are logged in through /oauth/token"}, nil
	}
	return []string{"identity provider " + p + " will be used: /oauth/login/" + p + " (LDAP users cannot use /oauth/token)"}, nil
}
