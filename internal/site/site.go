// Package site defines the pluggable per-website login drivers.
package site

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors drivers wrap so callers can classify failures.
var (
	ErrBadCredentials = errors.New("bad credentials")
	ErrLoginRejected  = errors.New("login rejected by the site")
	ErrUnreachable    = errors.New("site unreachable")
)

// Unreachable marks a failure to ask a site at all (the connection was refused, timed out or could not be made) as
// ErrUnreachable, keeping what the transport said. A session probe that returns it tells the cache that nothing was learned
// about the session, so the session is kept; a probe that returns anything else means the site was asked and refused.
func Unreachable(err error) error {
	if err == nil || errors.Is(err, ErrUnreachable) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnreachable, err)
}

// TemporaryStatus reports whether an HTTP status says only that the site could not answer just now, which tells a session
// probe nothing about the session: 502 (the gateway in front of the site could not reach it), 503 (not available), 504 (it
// did not answer in time) and 429 (it asks to slow down).
//
// It is deliberately short. Every other status that is not a success counts as the site saying no, 500 included: some sites
// answer 500 for a session that has ended, and keeping such a session would hide the fact that it is dead. The list was
// checked against the real sites: with a session that is not valid GitLab, Kibana, Nightingale and KubeSphere answer 401,
// Archery 1.x answers a 302 to its login page, Jenkins answers 200 for an anonymous user; none of them uses one of these.
func TemporaryStatus(code int) bool {
	switch code {
	case 429, 502, 503, 504:
		return true
	}
	return false
}

// ProbeStatus is what a session probe answers for the status a site returned: nil for 200, a "could not ask" error for a
// temporary status (the session is kept) and a plain refusal for any other (the session is dropped). what names the
// driver, for the message.
func ProbeStatus(what string, code int) error {
	switch {
	case code == 200:
		return nil
	case TemporaryStatus(code):
		return fmt.Errorf("%w: %s answered HTTP %d, which says nothing about the session", ErrUnreachable, what, code)
	}
	return fmt.Errorf("%s session invalid: HTTP %d", what, code)
}

// Field describes one input the human is asked for in a round.
type Field struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Secret bool   `json:"secret,omitempty"`
	// Image is an optional data:image/(png|jpeg|gif);base64,... URL shown above the input (a captcha).
	Image string `json:"image,omitempty"`
}

// Credentials holds the decrypted values submitted in one round.
type Credentials map[string]string

// Session is the result handed back to the agent.
type Session struct {
	Cookies   []*http.Cookie    `json:"-"`
	Headers   map[string]string `json:"headers,omitempty"`
	Tokens    map[string]string `json:"tokens,omitempty"`
	ExpiresAt time.Time         `json:"expires_at,omitempty"`
}

// Driver implements the login flow of one kind of website.
type Driver interface {
	Name() string
	Match(u *url.URL) bool
	// NeedsLogin is false for sites without authentication (e.g. SkyWalking).
	NeedsLogin() bool
	Login(ctx context.Context, base *url.URL, ask Asker, hc *http.Client) (*Session, error)
	Probe(ctx context.Context, base *url.URL, s *Session, hc *http.Client) error
}

// Configurable drivers accept per-site options from the `site_options:` config section.
type Configurable interface {
	Configure(opts map[string]string)
}

// Inspector is implemented by drivers that can describe, without any credentials, what they will do against a
// given server (login method, product generation, challenges). It powers `securl doctor -site`.
type Inspector interface {
	Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error)
}

// Asker runs one human round (mode "login", "totp", ...) and returns the submitted fields.
type Asker interface {
	Ask(ctx context.Context, mode string, fields []Field) (Credentials, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Driver{}
)

// Register adds a driver; it panics on duplicate names (called from init()).
func Register(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[d.Name()]; dup {
		panic("site: duplicate driver " + d.Name())
	}
	registry[d.Name()] = d
}

// Key identifies a site instance: scheme://host[:port] plus its path prefix, if any.
func Key(u *url.URL) string { return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/") }

// Replace registers d, replacing any driver with the same name (used for config-defined sites).
func Replace(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	registry[d.Name()] = d
}

// Resolve picks a driver by explicit name, or by matching the URL.
func Resolve(name string, u *url.URL) (Driver, error) {
	mu.RLock()
	defer mu.RUnlock()
	if name != "" {
		if d, ok := registry[name]; ok {
			return d, nil
		}
		return nil, fmt.Errorf("unknown site %q (have %v)", name, namesLocked())
	}
	for _, n := range namesLocked() {
		if d := registry[n]; d.Match(u) {
			return d, nil
		}
	}
	return nil, fmt.Errorf("no driver matches %s; pass `site` explicitly (have %v)", u.Host, namesLocked())
}

// Names lists registered driver names.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	return namesLocked()
}

func namesLocked() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
