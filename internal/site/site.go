// Package site defines the pluggable per-website login drivers.
package site

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

// Errors drivers wrap so callers can classify failures.
var (
	ErrBadCredentials = errors.New("bad credentials")
	ErrLoginRejected  = errors.New("login rejected by the site")
	ErrUnreachable    = errors.New("site unreachable")
)

// Field describes one input the human is asked for in a round.
type Field struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Secret bool   `json:"secret,omitempty"`
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
