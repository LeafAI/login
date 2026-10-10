// Package kubesphere logs in to KubeSphere 3.x through the OAuth password grant.
//
// Stock KubeSphere has no second factor. If the token endpoint's error response mentions OTP/MFA
// (custom identity providers), the driver asks for a "totp" round and retries with an "otp" form field.
// That path is a guess that has never run against a real second factor.
package kubesphere

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LeafAI/login/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "kubesphere" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "kubesphere")
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"password"}, "username": {creds["username"]}, "password": {creds["password"]},
		"client_id": {"kubesphere"}, "client_secret": {"kubesphere"}}
	status, tr, raw, err := token(ctx, hc, base, form)
	if err != nil {
		return nil, err
	}
	if status != 200 && site.Looks2FA(raw) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		form.Set("otp", strings.TrimSpace(code["code"]))
		if status, tr, raw, err = token(ctx, hc, base, form); err != nil {
			return nil, err
		}
	}
	switch {
	case status == 200 && tr.AccessToken != "":
	case status == 400 || status == 401 || status == 403:
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, site.Clip(firstNonEmpty(tr.Description, tr.Error, raw), 200))
	default:
		return nil, fmt.Errorf("%w: kubesphere returned %d: %s", site.ErrLoginRejected, status, site.Clip(raw, 200))
	}
	s := &site.Session{
		Headers: map[string]string{"Authorization": "Bearer " + tr.AccessToken},
		Tokens:  map[string]string{"access_token": tr.AccessToken, "refresh_token": tr.RefreshToken},
	}
	if tr.ExpiresIn > 0 {
		s.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return s, nil
}

func token(ctx context.Context, hc *http.Client, base *url.URL, form url.Values) (int, tokenResp, string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/oauth/token", strings.NewReader(form.Encode()))
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

func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/kapis/resources.kubesphere.io/v1alpha3/namespaces?limit=1", nil)
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
