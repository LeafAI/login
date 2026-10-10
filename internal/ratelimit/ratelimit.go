// Package ratelimit protects people from being flooded with login requests by an over-eager agent. It counts
// only requests that actually reach a human (cache hits are free) and enforces, per site and overall, a
// sliding-window cap plus a cool-down after the human rejected a request.
package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// Config bounds human requests. A zero value disables the corresponding rule.
type Config struct {
	PerSite        int           // max requests to humans for one site per Window
	Total          int           // max requests to humans overall per Window
	Window         time.Duration // sliding window length
	RejectCooldown time.Duration // after a rejection, refuse that site for this long
}

// Limited says why and for how long a request is refused.
type Limited struct {
	Reason     string
	RetryAfter time.Duration
}

func (l *Limited) Error() string {
	return fmt.Sprintf("%s; retry in %s", l.Reason, l.RetryAfter.Round(time.Second))
}

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg Config
	now func() time.Time

	mu       sync.Mutex
	perSite  map[string][]time.Time
	all      []time.Time
	rejected map[string]time.Time
}

// New builds a limiter; pass a nil now for the real clock.
func New(cfg Config, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Hour
	}
	return &Limiter{cfg: cfg, now: now, perSite: map[string][]time.Time{}, rejected: map[string]time.Time{}}
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

func retryAfter(ts []time.Time, window time.Duration, now time.Time) time.Duration {
	if len(ts) == 0 {
		return 0
	}
	return ts[0].Add(window).Sub(now)
}

// Allow records a request to a human for site and returns nil, or a *Limited error without recording it.
func (l *Limiter) Allow(site string) *Limited {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if until, ok := l.rejected[site]; ok {
		if now.Before(until) {
			return &Limited{Reason: "the user recently rejected a login to " + site, RetryAfter: until.Sub(now)}
		}
		delete(l.rejected, site)
	}
	cutoff := now.Add(-l.cfg.Window)
	l.perSite[site] = prune(l.perSite[site], cutoff)
	l.all = prune(l.all, cutoff)
	if n := l.cfg.PerSite; n > 0 && len(l.perSite[site]) >= n {
		return &Limited{Reason: fmt.Sprintf("already asked a person to log in to %s %d times in %s", site, n, l.cfg.Window), RetryAfter: retryAfter(l.perSite[site], l.cfg.Window, now)}
	}
	if n := l.cfg.Total; n > 0 && len(l.all) >= n {
		return &Limited{Reason: fmt.Sprintf("already asked people to log in %d times in %s", n, l.cfg.Window), RetryAfter: retryAfter(l.all, l.cfg.Window, now)}
	}
	l.perSite[site] = append(l.perSite[site], now)
	l.all = append(l.all, now)
	return nil
}

// Rejected starts the cool-down for site after the human pressed Reject.
func (l *Limiter) Rejected(site string) {
	if l == nil || l.cfg.RejectCooldown <= 0 {
		return
	}
	l.mu.Lock()
	l.rejected[site] = l.now().Add(l.cfg.RejectCooldown)
	l.mu.Unlock()
}
