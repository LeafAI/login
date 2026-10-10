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
	mu    sync.Mutex
	m     map[string]*Entry
	store *Store
	// Log receives persistence problems (never secrets).
	Log func(format string, args ...any)
}

func New() *Cache { return &Cache{m: map[string]*Entry{}} }

// NewPersistent returns a cache backed by an encrypted file store.
func NewPersistent(s *Store) *Cache { c := New(); c.store = s; return c }

func (c *Cache) logf(f string, a ...any) {
	if c.Log != nil {
		c.Log(f, a...)
	}
}

func (c *Cache) persist(fn func(map[string]record)) {
	if c.store == nil {
		return
	}
	if err := c.store.update(fn); err != nil {
		c.logf("session store: %v", err)
	}
}

// Key returns the cache key (scheme://host[:port]) for a URL.
func Key(u *url.URL) string { return u.Scheme + "://" + u.Host }

func (c *Cache) Put(u *url.URL, d site.Driver, s *site.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	e := &Entry{Site: d.Name(), Base: Key(u), Driver: d, Session: s, ObtainedAt: now, ValidatedAt: now}
	c.m[e.Base] = e
	c.persist(func(m map[string]record) { m[e.Base] = toRecord(e) })
}

// Get returns a cached session after probing it; invalid or expired entries are dropped.
func (c *Cache) Get(ctx context.Context, u *url.URL, hc *http.Client) (*Entry, bool) {
	k := Key(u)
	c.mu.Lock()
	e := c.m[k]
	c.mu.Unlock()
	if e == nil {
		e = c.fromStore(k)
	}
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

// fromStore adopts a session another process (or an earlier run) stored.
func (c *Cache) fromStore(key string) *Entry {
	if c.store == nil {
		return nil
	}
	r, ok := c.store.load()[key]
	if !ok {
		return nil
	}
	base, _ := url.Parse(r.Base)
	d, err := site.Resolve(r.Site, base)
	if err != nil {
		return nil
	}
	e := &Entry{Site: r.Site, Base: r.Base, Driver: d, Session: r.session(), ObtainedAt: r.ObtainedAt}
	c.mu.Lock()
	c.m[key] = e
	c.mu.Unlock()
	return e
}

func (c *Cache) Delete(key string) bool {
	c.mu.Lock()
	_, ok := c.m[key]
	delete(c.m, key)
	c.mu.Unlock()
	if c.store != nil {
		c.persist(func(m map[string]record) {
			if _, has := m[key]; has {
				ok = true
			}
			delete(m, key)
		})
	}
	return ok
}

func (c *Cache) Clear() int {
	c.mu.Lock()
	n := len(c.m)
	c.m = map[string]*Entry{}
	c.mu.Unlock()
	c.persist(func(m map[string]record) {
		if len(m) > n {
			n = len(m)
		}
		for k := range m {
			delete(m, k)
		}
	})
	return n
}

// List returns copies of the entries (the caller must not expose Session secrets).
func (c *Cache) List() []Entry {
	if c.store != nil { // pick up sessions stored by other processes
		for k := range c.store.load() {
			c.mu.Lock()
			_, have := c.m[k]
			c.mu.Unlock()
			if !have {
				c.fromStore(k)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Entry, 0, len(c.m))
	for _, e := range c.m {
		out = append(out, *e)
	}
	return out
}
