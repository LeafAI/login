package flow

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/keyring"
)

// waitFor is what every test in this package uses to wait for something another goroutine does. On a loaded CI runner
// under -race, making a key and sealing a link took 3.3 seconds, longer than the old three-second limit, and a test that
// was correct failed. A wait that has to be long enough for the slowest machine costs nothing when the machine is fast,
// because it returns the moment the condition holds.
func TestWaitForGivesASlowMachineLongEnoughAndReturnsAtOnceOnAFastOne(t *testing.T) {
	start := time.Now()
	ready := time.Now().Add(6 * time.Second) // twice the 3 s limit that failed in CI
	waitFor(t, "a slow condition", func() bool { return time.Now().After(ready) })
	if time.Since(start) < 6*time.Second {
		t.Fatal("returned before the condition held")
	}

	start = time.Now()
	waitFor(t, "a condition that already holds", func() bool { return true })
	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("a condition that already holds took %v", time.Since(start))
	}
}

// slowTunnels is a tunnel starter that takes as long to bring a tunnel up as a loaded CI runner took to make a key and
// open one: longer than the 150 ms the first version of afterRoundDriver allowed before it ended the round.
type slowTunnels struct {
	delay time.Duration
	trackedTunnels
}

func (s *slowTunnels) Start(ctx context.Context, port int) (Tunnel, error) {
	time.Sleep(s.delay)
	return s.trackedTunnels.Start(ctx, port)
}

// A login that ends after the round was sent must find the tunnel still up for the page to read the outcome, however slow
// the machine is. This is the same check as TestTunnelClosesRightAfterThePageReadsTheOutcome, with a tunnel that takes
// 400 ms to come up, so that it does not depend on how fast the machine running it happens to be.
func TestTheOutcomeIsReadableEvenWhenTheTunnelIsSlowToComeUp(t *testing.T) {
	ts := &slowTunnels{delay: 400 * time.Millisecond}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, Grace: time.Hour, OutcomeCap: time.Hour, FlushDelay: 50 * time.Millisecond})
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	f := m.Start(afterRoundDriver{}, u, "", http.DefaultClient, nil)
	<-f.Done()
	if n := ts.stillOpen(); n != 1 {
		t.Fatalf("the tunnel must stay up for the page to read the outcome, open=%d", n)
	}
}

// The test that failed in CI: with the unlock factor on, the link is sealed under every code of the window, and on a loaded
// runner under -race that took longer than the old three-second limit of waitFor. A key that takes four seconds to make
// stands in for the slow machine, so that the check does not depend on the speed of the one running it.
type slowKeys struct {
	inner *keyring.MemoryPool
	delay time.Duration
}

func (k *slowKeys) Acquire() (*keyring.Key, error) {
	time.Sleep(k.delay)
	return k.inner.Acquire()
}

func TestALinkThatIsSlowToMakeIsStillWaitedFor(t *testing.T) {
	ts := &trackedTunnels{}
	rec := &recNotifier{}
	m := NewManager(Config{Keys: &slowKeys{inner: keyring.NewMemoryPool(8, time.Hour), delay: 4 * time.Second}, Notifier: rec, Tunnels: ts,
		PageURL: "https://page.example/", TTL: 10 * time.Minute, Unlock: &codeSource{codes: []string{"11111111"}, digits: 8}})
	defer m.Close()
	u, _ := url.Parse("https://gitlab.corp.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
}
