// Package kubesphere logs in to KubeSphere 3.x.
//
// Verified against the KubeSphere v3.4.1 source:
//   - POST /oauth/token (grant_type=password) always authenticates against KubeSphere's *local* users:
//     the handler passes an empty identity provider. It needs client_id/client_secret (default kubesphere).
//   - Users of an external identity provider (LDAP) must use POST /oauth/login/{identityprovider} with
//     username/password, which answers the same token JSON.
//   - The configured providers are published at GET /kapis/config.kubesphere.io/v1alpha2/configs/oauth
//     as identityProviders: [{name, type: "LDAPIdentityProvider", ...}].
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
	"strings"
	"sync"
	"time"

	"github.com/LeafAI/login/internal/site"
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
	status, tr, raw, err := post(ctx, hc, base, endpoint, form)
	if err != nil {
		return nil, err
	}
	if status != 200 && site.Looks2FA(raw) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		form.Set("otp", strings.TrimSpace(code["code"]))
		if status, tr, raw, err = post(ctx, hc, base, endpoint, form); err != nil {
			return nil, err
		}
	}
	msg := site.Clip(firstNonEmpty(tr.Description, tr.Error, raw), 200)
	switch {
	case status == 200 && tr.AccessToken != "":
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

func post(ctx context.Context, hc *http.Client, base *url.URL, path string, form url.Values) (int, tokenResp, string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, tokenResp{}, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	raw := site.ReadBody(resp)
	var tr tokenResp
	json.Unmarshal([]byte(raw), &tr)
	return resp.StatusCode, tr, raw, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// Probe asks the OIDC userinfo endpoint, which every authenticated user may call.
func (*driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", s.Headers["Authorization"])
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("kubesphere token invalid: %s", resp.Status)
	}
	return nil
}
