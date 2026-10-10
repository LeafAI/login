package flow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/site"
)

type stubDriver struct{}

func (stubDriver) Name() string        { return "stub" }
func (stubDriver) Match(*url.URL) bool { return true }
func (stubDriver) NeedsLogin() bool    { return true }
func (stubDriver) Login(ctx context.Context, _ *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	if _, err := ask.Ask(ctx, "login", site.LoginFields); err != nil {
		return nil, err
	}
	return &site.Session{}, nil
}
func (stubDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }

type okNotifier struct{ err error }

func (n okNotifier) Markdown(context.Context, string, string) error { return n.err }

type fakeTunnels struct{ err error }

type fakeTunnel struct{}

func (fakeTunnel) PublicURL() string     { return "http://127.0.0.1:1" }
func (fakeTunnel) Done() <-chan struct{} { return nil }
func (fakeTunnel) Close()                {}

func (f fakeTunnels) Start(context.Context, int) (Tunnel, error) {
	if f.err != nil {
		return nil, f.err
	}
	return fakeTunnel{}, nil
}

func manager(t *testing.T, n Notifier, ts TunnelStarter, ttl time.Duration) *Manager {
	return NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: n, Tunnels: ts,
		PageURL: "https://page.example/", TTL: ttl, Grace: time.Millisecond})
}

func run(t *testing.T, m *Manager) Result {
	t.Helper()
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "r", http.DefaultClient, nil)
	select {
	case <-f.Done():
		return f.Result()
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not finish")
		return Result{}
	}
}

func TestHumanTimeout(t *testing.T) {
	r := run(t, manager(t, okNotifier{}, fakeTunnels{}, 50*time.Millisecond))
	if !errors.Is(r.Err, ErrHumanTimeout) {
		t.Fatalf("err = %v", r.Err)
	}
}

func TestNotifyFailure(t *testing.T) {
	r := run(t, manager(t, okNotifier{err: fmt.Errorf("boom")}, fakeTunnels{}, time.Second))
	if !errors.Is(r.Err, ErrNotify) {
		t.Fatalf("err = %v", r.Err)
	}
}

func TestTunnelFailure(t *testing.T) {
	r := run(t, manager(t, okNotifier{}, fakeTunnels{err: fmt.Errorf("no ssh")}, time.Second))
	if !errors.Is(r.Err, ErrTunnel) {
		t.Fatalf("err = %v", r.Err)
	}
}

func TestSingleFlightAndCancel(t *testing.T) {
	m := manager(t, okNotifier{}, fakeTunnels{}, time.Minute)
	u, _ := url.Parse("https://site.example")
	a := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	b := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	if a != b || m.Get(a.ID) != a {
		t.Fatal("concurrent logins for one site must share a flow")
	}
	if !m.CancelBase("https://site.example") {
		t.Fatal("cancel failed")
	}
	select {
	case <-a.Done():
		if a.Result().Err == nil {
			t.Error("cancelled flow should fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not end the flow")
	}
}

func TestMessageEscapesAgentText(t *testing.T) {
	u, _ := url.Parse("https://site.example")
	f := &Flow{Base: u, Reason: "[Click here to confirm](https://evil.example)\n# urgent"}
	msg := message(f, "login", 1, "https://page.example/#v=1", "ABCDEF0123456789ABCDEF", time.Now(), "")
	if strings.Contains(msg, "](https://evil") {
		t.Errorf("agent-supplied link survived:\n%s", msg)
	}
	if !strings.Contains(msg, "[Open the login page](https://page.example/#v=1)") {
		t.Errorf("real link missing:\n%s", msg)
	}
}

type closeCountTunnel struct{ closed *int }

func (closeCountTunnel) PublicURL() string     { return "http://127.0.0.1:1" }
func (closeCountTunnel) Done() <-chan struct{} { return nil }
func (c closeCountTunnel) Close()              { *c.closed++ }

type countingTunnels struct{ closed *int }

func (c countingTunnels) Start(context.Context, int) (Tunnel, error) {
	return closeCountTunnel{c.closed}, nil
}

func TestManagerCloseTearsDownPendingTunnel(t *testing.T) {
	closed := 0
	m := manager(t, okNotifier{}, countingTunnels{&closed}, time.Minute)
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	for i := 0; f.Snapshot().Phase != "waiting_human"; i++ { // wait until the tunnel is up and the human is being waited for
		if i > 200 {
			t.Fatal("flow never reached waiting_human")
		}
		time.Sleep(10 * time.Millisecond)
	}
	m.Close()
	if closed != 1 {
		t.Errorf("tunnel closed %d times, want 1", closed)
	}
	select {
	case <-f.Done():
	default:
		t.Error("flow still running after Close")
	}
}

// dyingTunnels hands out tunnels whose Done channels the test controls.
type dyingTunnels struct {
	mu      sync.Mutex
	started []*dyingTunnel
}

type dyingTunnel struct {
	url  string
	done chan struct{}
	once sync.Once
}

func (d *dyingTunnel) PublicURL() string     { return d.url }
func (d *dyingTunnel) Done() <-chan struct{} { return d.done }
func (d *dyingTunnel) Close()                { d.once.Do(func() { close(d.done) }) }

func (d *dyingTunnels) Start(context.Context, int) (Tunnel, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := &dyingTunnel{url: fmt.Sprintf("http://127.0.0.1:%d", 1000+len(d.started)), done: make(chan struct{})}
	d.started = append(d.started, t)
	return t, nil
}

func (d *dyingTunnels) count() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.started) }

type recNotifier struct {
	mu    sync.Mutex
	texts []string
}

func (r *recNotifier) Markdown(_ context.Context, _, text string) error {
	r.mu.Lock()
	r.texts = append(r.texts, text)
	r.mu.Unlock()
	return nil
}

func (r *recNotifier) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.texts...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTunnelRestartResendsLink(t *testing.T) {
	ts := &dyingTunnels{}
	rec := &recNotifier{}
	m := manager(t, rec, ts, time.Minute)
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "first message", func() bool { return len(rec.all()) == 1 })

	ts.started[0].Close() // the ssh process dies while the human has not answered
	waitFor(t, "replacement message", func() bool { return len(rec.all()) == 2 })
	msgs := rec.all()
	if !strings.Contains(msgs[1], "replaces the previous one") || strings.Contains(msgs[0], "replaces") {
		t.Errorf("messages:\n%s\n---\n%s", msgs[0], msgs[1])
	}
	if ts.count() != 2 || !strings.Contains(msgs[1], "127.0.0.1%3A1001") && !strings.Contains(msgs[1], "127.0.0.1:1001") {
		t.Errorf("new tunnel url not in the new link (tunnels=%d):\n%s", ts.count(), msgs[1])
	}
	if f.Snapshot().Phase != "waiting_human" {
		t.Errorf("phase %q", f.Snapshot().Phase)
	}
	m.Close()
}

func TestTunnelGivesUpAfterRepeatedDeaths(t *testing.T) {
	ts := &dyingTunnels{}
	rec := &recNotifier{}
	m := manager(t, rec, ts, time.Minute)
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	for i := 0; i < maxTunnelRestarts+1; i++ {
		i := i
		waitFor(t, "tunnel start", func() bool { return ts.count() > i })
		ts.mu.Lock()
		tn := ts.started[i]
		ts.mu.Unlock()
		tn.Close()
	}
	select {
	case <-f.Done():
		if !errors.Is(f.Result().Err, ErrTunnel) {
			t.Errorf("err = %v", f.Result().Err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not give up")
	}
}

type countingNotifier struct {
	mu sync.Mutex
	n  int
}

func (c *countingNotifier) Markdown(context.Context, string, string) error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil
}

func TestAdmitRefusalNeverBothersAHuman(t *testing.T) {
	n := &countingNotifier{}
	cfg := Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: n, Tunnels: fakeTunnels{},
		PageURL: "https://page.example/", TTL: time.Second, Grace: time.Millisecond,
		Admit: func(site.Driver, *url.URL, string) error { return errors.New("too many requests") }}
	m := NewManager(cfg)
	u, _ := url.Parse("https://site.example")
	called := false
	f := m.Start(stubDriver{}, u, "r", http.DefaultClient, func(*Flow, Result) { called = true })
	select {
	case <-f.Done():
	default:
		t.Fatal("a refused flow must already be finished")
	}
	if r := f.Result(); r.Err == nil || r.Err.Error() != "too many requests" {
		t.Fatalf("result = %+v", r)
	}
	time.Sleep(50 * time.Millisecond)
	if n.n != 0 || called {
		t.Fatalf("notified %d times, onDone called=%v; a refused flow must do nothing", n.n, called)
	}
	if m.CancelBase("https://site.example") {
		t.Error("a refused flow must not stay registered as running")
	}
}

func TestAdmitIsAskedOncePerNewFlowNotPerJoiner(t *testing.T) {
	asked := 0
	cfg := Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: okNotifier{}, Tunnels: fakeTunnels{},
		PageURL: "https://page.example/", TTL: time.Minute, Grace: time.Millisecond,
		Admit: func(site.Driver, *url.URL, string) error { asked++; return nil }}
	m := NewManager(cfg)
	u, _ := url.Parse("https://site.example")
	a := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	b := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	if a != b || asked != 1 {
		t.Fatalf("same flow=%v, Admit calls=%d; joining a running flow must not count again", a == b, asked)
	}
	m.Close()
}

func TestOnRoundReportsEachRoundOnceEvenAfterATunnelRestart(t *testing.T) {
	ts := &dyingTunnels{}
	rec := &recNotifier{}
	var mu sync.Mutex
	var got []string
	m := NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: rec, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, Grace: time.Millisecond,
		OnRound: func(f *Flow, mode string, round int) {
			mu.Lock()
			got = append(got, fmt.Sprintf("%s:%s:%d", f.Base.Host, mode, round))
			mu.Unlock()
		}})
	u, _ := url.Parse("https://site.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "first message", func() bool { return len(rec.all()) == 1 })
	ts.started[0].Close() // a replacement link is sent for the SAME round
	waitFor(t, "replacement message", func() bool { return len(rec.all()) == 2 })
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "site.example:login:1" {
		t.Fatalf("OnRound calls = %v; one round, even with a replacement link, is reported once", got)
	}
	m.Close()
}
