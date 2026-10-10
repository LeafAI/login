// Package nightingale logs in to Nightingale (n9e) v7.
//
// Nightingale answers {"dat":{...tokens...},"err":""}. If the error text indicates a second factor
// the driver asks for a "totp" round and retries with a "code" field (best effort, unverified
// against a live 2FA setup).
package nightingale

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

func (driver) Name() string     { return "nightingale" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	return strings.Contains(h, "nightingale") || strings.Contains(h, "n9e")
}

type loginResp struct {
	Dat struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"dat"`
	Err string `json:"err"`
}

func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	payload := map[string]string{"username": creds["username"], "password": creds["password"]}
	status, lr, raw, err := attempt(ctx, hc, base, payload)
	if err != nil {
		return nil, err
	}
	if lr.Dat.AccessToken == "" && site.Looks2FA(lr.Err+" "+raw) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		payload["code"] = strings.TrimSpace(code["code"])
		if status, lr, raw, err = attempt(ctx, hc, base, payload); err != nil {
			return nil, err
		}
	}
	if lr.Dat.AccessToken == "" {
		msg := site.Clip(firstNonEmpty(lr.Err, raw), 200)
		if status >= 500 {
			return nil, fmt.Errorf("%w: nightingale returned %d: %s", site.ErrLoginRejected, status, msg)
		}
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, msg)
	}
	return &site.Session{
		Headers: map[string]string{"Authorization": "Bearer " + lr.Dat.AccessToken},
		Tokens:  map[string]string{"access_token": lr.Dat.AccessToken, "refresh_token": lr.Dat.RefreshToken},
	}, nil
}

func attempt(ctx context.Context, hc *http.Client, base *url.URL, payload map[string]string) (int, loginResp, string, error) {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/api/n9e/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, loginResp{}, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	raw := site.ReadBody(resp)
	var lr loginResp
	json.Unmarshal([]byte(raw), &lr)
	return resp.StatusCode, lr, raw, nil
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/n9e/self/profile", nil)
	req.Header.Set("Authorization", s.Headers["Authorization"])
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("nightingale token invalid: %s", resp.Status)
	}
	return nil
}
