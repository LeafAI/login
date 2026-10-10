// Package session caches logged-in sessions in memory and revalidates them before reuse.
package session

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/LeafAI/login/internal/site"
)

type Entry struct {
	Site        string
	Base        string
	Driver      site.Driver
	Session     *site.Session
	ObtainedAt  time.Time
	ValidatedAt time.Time
}

type Cache struct {
	mu sync.Mutex
	m  map[string]*Entry
}

func New() *Cache { return &Cache{m: map[string]*Entry{}} }

// Key returns the cache key (scheme://host[:port]) for a URL.
func Key(u *url.URL) string { return u.Scheme + "://" + u.Host }

func (c *Cache) Put(u *url.URL, d site.Driver, s *site.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.m[Key(u)] = &Entry{Site: d.Name(), Base: Key(u), Driver: d, Session: s, ObtainedAt: now, ValidatedAt: now}
}

// Get returns a cached session after probing it; invalid or expired entries are dropped.
func (c *Cache) Get(ctx context.Context, u *url.URL, hc *http.Client) (*Entry, bool) {
	k := Key(u)
	c.mu.Lock()
	e := c.m[k]
	c.mu.Unlock()
	if e == nil {
		return nil, false
	}
	if !e.Session.ExpiresAt.IsZero() && time.Now().After(e.Session.ExpiresAt) {
		c.Delete(k)
		return nil, false
	}
	base, _ := url.Parse(e.Base)
	if err := e.Driver.Probe(ctx, base, e.Session, hc); err != nil {
		c.Delete(k)
		return nil, false
	}
	c.mu.Lock()
	e.ValidatedAt = time.Now()
	c.mu.Unlock()
	return e, true
}

func (c *Cache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.m[key]
	delete(c.m, key)
	return ok
}

func (c *Cache) Clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.m)
	c.m = map[string]*Entry{}
	return n
}

// List returns copies of the entries (the caller must not expose Session secrets).
func (c *Cache) List() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Entry, 0, len(c.m))
	for _, e := range c.m {
		out = append(out, *e)
	}
	return out
}
