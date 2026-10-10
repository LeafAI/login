// Package noauth is the driver for sites without authentication (SkyWalking today).
package noauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/login/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string { return "skywalking" }

// Match recognises SkyWalking by hostname hint only; use the `site` argument otherwise.
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "skywalking")
}

func (driver) NeedsLogin() bool { return false }

func (d driver) Login(ctx context.Context, base *url.URL, _ site.Asker, hc *http.Client) (*site.Session, error) {
	s := &site.Session{Tokens: map[string]string{"auth": "none"}}
	return s, d.Probe(ctx, base, s, hc)
}

func (driver) Probe(ctx context.Context, base *url.URL, _ *site.Session, hc *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("skywalking: %s returned %s (site may need auth; use the generic driver)", base, resp.Status)
	}
	return nil
}
