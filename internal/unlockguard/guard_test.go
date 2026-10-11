package unlockguard

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newGuard() (*Guard, *clock) {
	c := &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	g := New(Config{FreeAttempts: 3, BaseDelay: 30 * time.Second, MaxDelay: 15 * time.Minute, Reset: time.Hour})
	g.now = c.now
	return g, c
}

func TestAllowsTheFirstAttemptsFreely(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 3; i++ {
		if err := g.Allow(); err != nil {
			t.Fatalf("attempt %d must be allowed: %v", i+1, err)
		}
		g.Failed()
	}
}

func TestRefusesAfterTheFreeAttemptsAndSaysWhenToRetry(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 3; i++ {
		g.Allow()
		g.Failed()
	}
	err := g.Allow()
	var lim *Limited
	if !errors.As(err, &lim) {
		t.Fatalf("the fourth attempt must be refused: %v", err)
	}
	if lim.RetryAfter != 30*time.Second {
		t.Errorf("the first penalty is the base delay: %v", lim.RetryAfter)
	}
}

func TestTheDelayDoublesWithEachFurtherFailureUpToACap(t *testing.T) {
	g, c := newGuard()
	for i := 0; i < 3; i++ {
		g.Allow()
		g.Failed()
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range want {
		err := g.Allow()
		var lim *Limited
		if !errors.As(err, &lim) || lim.RetryAfter != w {
			t.Fatalf("penalty %d: want %v, got %v", i+1, w, err)
		}
		c.advance(w)
		if err := g.Allow(); err != nil {
			t.Fatalf("after waiting %v the next attempt is allowed: %v", w, err)
		}
		g.Failed()
	}
}

func TestWaitingShortensTheRetryTime(t *testing.T) {
	g, c := newGuard()
	for i := 0; i < 3; i++ {
		g.Allow()
		g.Failed()
	}
	c.advance(10 * time.Second)
	var lim *Limited
	if err := g.Allow(); !errors.As(err, &lim) || lim.RetryAfter != 20*time.Second {
		t.Errorf("the remaining wait: %v", err)
	}
}

func TestSuccessClearsTheCount(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 2; i++ {
		g.Allow()
		g.Failed()
	}
	g.Succeeded()
	for i := 0; i < 3; i++ {
		if err := g.Allow(); err != nil {
			t.Fatalf("after a success the free attempts are back: %v", err)
		}
		g.Failed()
	}
}

func TestAQuietHourForgivesOldFailures(t *testing.T) {
	g, c := newGuard()
	for i := 0; i < 5; i++ {
		g.Allow()
		g.Failed()
	}
	c.advance(2 * time.Hour)
	if err := g.Allow(); err != nil {
		t.Fatalf("an hour without attempts clears the slate: %v", err)
	}
}

// An attacker who keeps trying must not be forgiven just because the last attempt was long ago relative to the
// delay: only a long quiet time resets.
func TestKeepingOnTryingNeverResets(t *testing.T) {
	g, c := newGuard()
	for i := 0; i < 3; i++ {
		g.Allow()
		g.Failed()
	}
	for i := 0; i < 10; i++ {
		var lim *Limited
		err := g.Allow()
		if err == nil {
			g.Failed()
			continue
		}
		if !errors.As(err, &lim) {
			t.Fatal(err)
		}
		c.advance(lim.RetryAfter)
		if err := g.Allow(); err != nil {
			t.Fatal(err)
		}
		g.Failed()
	}
	if err := g.Allow(); err == nil {
		t.Error("persistent failures must keep the penalty at its cap, not reset")
	}
}

func TestAnAttemptInProgressIsNotAFailure(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 20; i++ {
		if err := g.Allow(); err != nil {
			t.Fatalf("asking for permission alone costs nothing: %v", err)
		}
	}
}

func TestStatusReportsWithoutChangingAnything(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 4; i++ {
		g.Allow()
		g.Failed()
	}
	a := g.Status()
	b := g.Status()
	if a != b || !a.Limited || a.RetryAfter <= 0 {
		t.Errorf("status must be a read-only view: %+v %+v", a, b)
	}
	if st := func() Status { g2, _ := newGuard(); return g2.Status() }(); st.Limited || st.Failures != 0 {
		t.Errorf("a fresh guard is not limited: %+v", st)
	}
}

func TestIsSafeForConcurrentUse(t *testing.T) {
	g, _ := newGuard()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Allow()
			g.Failed()
			g.Status()
		}()
	}
	wg.Wait()
	if g.Status().Failures != 50 {
		t.Errorf("every failure must be counted exactly once: %d", g.Status().Failures)
	}
}

func TestFailuresAreCountedNoMatterHowManyAreInFlight(t *testing.T) {
	g, _ := newGuard()
	// two attempts passed the check before either finished: both failures count
	if g.Allow() != nil || g.Allow() != nil {
		t.Fatal("setup")
	}
	g.Failed()
	g.Failed()
	if g.Status().Failures != 2 {
		t.Errorf("%+v", g.Status())
	}
}

func TestLimitedErrorSaysHowLongToWait(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 4; i++ {
		g.Allow()
		g.Failed()
	}
	err := g.Allow()
	if err == nil || !strings.Contains(err.Error(), "retry in") {
		t.Fatalf("the refusal must say how long to wait: %v", err)
	}
}

func TestDefaultsAreStrict(t *testing.T) {
	g := New(Config{})
	if g.cfg.FreeAttempts < 1 || g.cfg.FreeAttempts > 5 {
		t.Errorf("free attempts: %d", g.cfg.FreeAttempts)
	}
	if g.cfg.BaseDelay < 10*time.Second || g.cfg.MaxDelay < 5*time.Minute || g.cfg.Reset < 30*time.Minute {
		t.Errorf("a zero config must still protect: %+v", g.cfg)
	}
}

// A success must lift a running penalty as well as the count, or a person who finally types the right passphrase would
// be refused their next attempt.
func TestSuccessAlsoLiftsARunningPenalty(t *testing.T) {
	g, _ := newGuard()
	for i := 0; i < 5; i++ {
		g.Allow()
		g.Failed()
	}
	if g.Allow() == nil {
		t.Fatal("setup: a penalty must be running")
	}
	g.Succeeded()
	if err := g.Allow(); err != nil {
		t.Errorf("after a success nothing may still be refused: %v", err)
	}
	if st := g.Status(); st.Failures != 0 || st.Limited {
		t.Errorf("%+v", st)
	}
}

// The count is forgiven after the quiet hour; a penalty that is still running at that moment goes with it.
func TestTheQuietHourAlsoEndsAPenaltyThatWouldOtherwiseRun(t *testing.T) {
	g := New(Config{FreeAttempts: 1, BaseDelay: time.Hour * 5, MaxDelay: time.Hour * 5, Reset: time.Hour})
	c := &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	g.now = c.now
	g.Allow()
	g.Failed()
	if g.Allow() == nil {
		t.Fatal("setup: a five hour penalty is running")
	}
	c.advance(90 * time.Minute) // a quiet hour has passed, though the penalty was five
	if err := g.Allow(); err != nil {
		t.Errorf("a quiet period longer than the reset time clears everything, penalty included: %v", err)
	}
	g.Failed()
	if st := g.Status(); st.Failures != 1 {
		t.Errorf("the count started again from zero: %+v", st)
	}
}

func TestJustUnderTheResetTimeDoesNotForgive(t *testing.T) {
	g, c := newGuard()
	for i := 0; i < 4; i++ {
		g.Allow()
		g.Failed()
	}
	c.advance(59 * time.Minute)
	if g.Status().Failures != 4 {
		t.Errorf("59 minutes is not a quiet hour: %+v", g.Status())
	}
	c.advance(time.Minute)
	if g.Status().Failures != 0 {
		t.Errorf("exactly the reset time forgives: %+v", g.Status())
	}
}

// With a cap that is not a power-of-two multiple of the base, the penalty must still stop exactly at the cap.
func TestThePenaltyStopsExactlyAtTheCapEvenWhenItIsNotAMultiple(t *testing.T) {
	g := New(Config{FreeAttempts: 1, BaseDelay: 40 * time.Second, MaxDelay: 100 * time.Second, Reset: time.Hour})
	c := &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	g.now = c.now
	var last time.Duration
	for i := 0; i < 8; i++ {
		g.Allow()
		g.Failed()
		var lim *Limited
		if err := g.Allow(); errors.As(err, &lim) {
			last = lim.RetryAfter
			c.advance(lim.RetryAfter)
		}
	}
	if last != 100*time.Second {
		t.Errorf("the penalty must settle at the cap (40s, 80s, then 100s, never 160s): %v", last)
	}
}

func TestAHugeFailureCountDoesNotOverflowTheDelay(t *testing.T) {
	g := New(Config{FreeAttempts: 1, BaseDelay: time.Second, MaxDelay: time.Minute, Reset: 100 * time.Hour})
	c := &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	g.now = c.now
	for i := 0; i < 500; i++ {
		g.Failed() // the count really does reach hundreds; nobody waits, so nothing is forgiven
	}
	var lim *Limited
	if err := g.Allow(); !errors.As(err, &lim) || lim.RetryAfter != time.Minute {
		t.Errorf("after hundreds of failures the penalty is the cap, not an overflowed number: %v", err)
	}
}
