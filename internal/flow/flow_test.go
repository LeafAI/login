package flow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	msg := message(f, "login", 1, "https://page.example/#v=1", "ABCDEF0123456789ABCDEF", time.Now())
	if strings.Contains(msg, "](https://evil") {
		t.Errorf("agent-supplied link survived:\n%s", msg)
	}
	if !strings.Contains(msg, "[Open the login page](https://page.example/#v=1)") {
		t.Errorf("real link missing:\n%s", msg)
	}
}
