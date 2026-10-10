package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)} }

func TestPerSiteWindowSlides(t *testing.T) {
	c := newClock()
	l := New(Config{PerSite: 2, Window: time.Hour}, c.now)
	for i := 0; i < 2; i++ {
		if e := l.Allow("gitlab"); e != nil {
			t.Fatalf("request %d refused: %v", i, e)
		}
		c.add(10 * time.Minute)
	}
	e := l.Allow("gitlab")
	if e == nil {
		t.Fatal("third request inside the window must be refused")
	}
	if e.RetryAfter != 40*time.Minute {
		t.Errorf("retry after = %v, want 40m (the first request leaves the window then)", e.RetryAfter)
	}
	if l.Allow("kibana") != nil {
		t.Error("another site has its own budget")
	}
	c.add(41 * time.Minute)
	if l.Allow("gitlab") != nil {
		t.Error("the budget must come back once the oldest request leaves the window")
	}
}

func TestRefusedRequestsAreNotCounted(t *testing.T) {
	c := newClock()
	l := New(Config{PerSite: 1, Window: time.Hour}, c.now)
	l.Allow("a")
	for i := 0; i < 5; i++ {
		l.Allow("a") // refused; must not extend the penalty
		c.add(time.Minute)
	}
	c.add(56 * time.Minute) // 61 minutes after the only counted request
	if l.Allow("a") != nil {
		t.Error("hammering while limited must not push the retry time further out")
	}
}

func TestTotalCapAcrossSites(t *testing.T) {
	l := New(Config{Total: 3, Window: time.Hour}, newClock().now)
	for _, s := range []string{"a", "b", "c"} {
		if l.Allow(s) != nil {
			t.Fatalf("%s refused too early", s)
		}
	}
	if e := l.Allow("d"); e == nil || e.Reason == "" {
		t.Fatalf("overall cap not enforced: %v", e)
	}
}

func TestRejectCooldown(t *testing.T) {
	c := newClock()
	l := New(Config{RejectCooldown: 15 * time.Minute}, c.now)
	if l.Allow("gitlab") != nil {
		t.Fatal("no limits are set besides the cool-down")
	}
	l.Rejected("gitlab")
	c.add(5 * time.Minute)
	e := l.Allow("gitlab")
	if e == nil || e.RetryAfter != 10*time.Minute {
		t.Fatalf("cool-down: %v", e)
	}
	if l.Allow("kibana") != nil {
		t.Error("the cool-down is per site")
	}
	c.add(10 * time.Minute)
	if l.Allow("gitlab") != nil {
		t.Error("cool-down should have ended")
	}
}

func TestDisabledAndNil(t *testing.T) {
	var nilL *Limiter
	if nilL.Allow("x") != nil {
		t.Error("nil limiter allows everything")
	}
	nilL.Rejected("x")
	l := New(Config{}, nil)
	for i := 0; i < 100; i++ {
		if l.Allow("x") != nil {
			t.Fatal("zero config must not limit")
		}
	}
	l.Rejected("x") // zero cool-down: no effect
	if l.Allow("x") != nil {
		t.Error("zero cool-down must not block")
	}
}

func TestConcurrentUse(t *testing.T) {
	l := New(Config{PerSite: 50, Window: time.Hour}, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("s") == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 50 {
		t.Fatalf("allowed %d, want exactly 50", ok)
	}
}
