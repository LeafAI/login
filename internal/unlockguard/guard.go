// Package unlockguard slows down anyone who keeps guessing the vault passphrase.
//
// One Guard is shared by every way of trying a passphrase in a process, so that a second route (the page reached from
// a DingTalk link, a command on the same machine) does not give a fresh set of guesses.
package unlockguard

import (
	"fmt"
	"sync"
	"time"
)

// Config sets the penalty. Zero values take the defaults, which are strict.
type Config struct {
	FreeAttempts int           // wrong passphrases before the first penalty (default 3)
	BaseDelay    time.Duration // the first penalty (default 30 s); it doubles with each further failure
	MaxDelay     time.Duration // the cap of the penalty (default 15 min)
	Reset        time.Duration // how long without any attempt clears the count (default 1 h)
}

// Limited is returned while the guard is refusing attempts.
type Limited struct{ RetryAfter time.Duration }

func (l *Limited) Error() string {
	return fmt.Sprintf("too many wrong vault passphrases; retry in %s", l.RetryAfter.Round(time.Second))
}

// Status is a read-only view of the guard.
type Status struct {
	Failures   int
	Limited    bool
	RetryAfter time.Duration
}

// Guard counts failures and refuses attempts while a penalty runs. It is safe for concurrent use.
type Guard struct {
	cfg Config
	now func() time.Time

	mu       sync.Mutex
	failures int
	until    time.Time // no attempt before this moment
	last     time.Time // the last failure
}

// New returns a guard.
func New(cfg Config) *Guard {
	if cfg.FreeAttempts <= 0 {
		cfg.FreeAttempts = 3
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 30 * time.Second
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 15 * time.Minute
	}
	if cfg.Reset <= 0 {
		cfg.Reset = time.Hour
	}
	return &Guard{cfg: cfg, now: time.Now}
}

func (g *Guard) forgiveLocked() {
	if g.failures > 0 && g.now().Sub(g.last) >= g.cfg.Reset {
		g.failures, g.until = 0, time.Time{}
	}
}

// Allow says whether an attempt may be made now. Asking costs nothing; only Failed counts.
func (g *Guard) Allow() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.forgiveLocked()
	if wait := g.until.Sub(g.now()); wait > 0 {
		return &Limited{RetryAfter: wait}
	}
	return nil
}

// Failed records a wrong passphrase and starts the penalty that its count calls for.
func (g *Guard) Failed() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.forgiveLocked()
	g.failures++
	g.last = g.now()
	if over := g.failures - g.cfg.FreeAttempts; over >= 0 {
		d := g.cfg.BaseDelay
		for i := 0; i < over && d < g.cfg.MaxDelay; i++ {
			d *= 2
		}
		if d > g.cfg.MaxDelay {
			d = g.cfg.MaxDelay
		}
		g.until = g.now().Add(d)
	}
}

// Succeeded clears the count.
func (g *Guard) Succeeded() {
	g.mu.Lock()
	g.failures, g.until, g.last = 0, time.Time{}, time.Time{}
	g.mu.Unlock()
}

// Status reports the guard without changing it.
func (g *Guard) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.forgiveLocked()
	st := Status{Failures: g.failures}
	if wait := g.until.Sub(g.now()); wait > 0 {
		st.Limited, st.RetryAfter = true, wait
	}
	return st
}
