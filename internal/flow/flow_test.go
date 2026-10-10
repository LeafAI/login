package flow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// reachable is a local server that answers 404 to every path, as the login API does to an unknown token. The fake
// tunnels below use its address as their "public" address, so the check that a tunnel carries traffic passes for them.
var reachable = func() *httptest.Server { return httptest.NewServer(http.NotFoundHandler()) }()

type fakeTunnels struct{ err error }

type fakeTunnel struct{}

func (fakeTunnel) PublicURL() string     { return reachable.URL }
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

func (closeCountTunnel) PublicURL() string     { return reachable.URL }
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
	t := &dyingTunnel{url: reachable.URL + fmt.Sprintf("/t%d", len(d.started)), done: make(chan struct{})}
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
	if ts.count() != 2 || !strings.Contains(msgs[1], "%2Ft1") && !strings.Contains(msgs[1], "/t1") {
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

// trackedTunnels counts the tunnels a flow opened and how many are still open, so a test can say what a finished
// flow must have left behind: nothing.
type trackedTunnels struct {
	mu     sync.Mutex
	opened int
	open   map[int]bool
}

type trackedTunnel struct {
	ts   *trackedTunnels
	id   int
	done chan struct{}
	once sync.Once
}

func (t *trackedTunnel) PublicURL() string     { return reachable.URL + fmt.Sprintf("/t%d", t.id) }
func (t *trackedTunnel) Done() <-chan struct{} { return t.done }
func (t *trackedTunnel) Close() {
	t.once.Do(func() {
		t.ts.mu.Lock()
		delete(t.ts.open, t.id)
		t.ts.mu.Unlock()
		close(t.done)
	})
}

func (ts *trackedTunnels) Start(context.Context, int) (Tunnel, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.open == nil {
		ts.open = map[int]bool{}
	}
	ts.opened++
	t := &trackedTunnel{ts: ts, id: ts.opened, done: make(chan struct{})}
	ts.open[t.id] = true
	return t, nil
}

func (ts *trackedTunnels) stillOpen() int { ts.mu.Lock(); defer ts.mu.Unlock(); return len(ts.open) }
func (ts *trackedTunnels) total() int     { ts.mu.Lock(); defer ts.mu.Unlock(); return ts.opened }

// afterRoundDriver brings up a round (key, API server, tunnel, link) and then ends the login the way the test says,
// as if the person had answered and the site had replied. A nil result is a successful login.
type afterRoundDriver struct{ result error }

func (afterRoundDriver) Name() string        { return "stub" }
func (afterRoundDriver) Match(*url.URL) bool { return true }
func (afterRoundDriver) NeedsLogin() bool    { return true }
func (d afterRoundDriver) Login(ctx context.Context, _ *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { time.Sleep(150 * time.Millisecond); cancel() }() // "the person answered": stop waiting for them
	ask.Ask(rctx, "login", site.LoginFields)                     // brings the tunnel up and sends the link
	if d.result != nil {
		return nil, d.result
	}
	return &site.Session{}, nil
}
func (afterRoundDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error {
	return nil
}

// A tunnel serves exactly one login, so it must be gone once the login ended, however it ended. Grace is long here
// so that the test proves the old 30 s grace is not what closes it. When a page was listening the tunnel may outlive
// the login by at most OutcomeCap (the page's next poll reads the outcome); every other ending closes it at once.
func TestEveryEndOfALoginClosesItsTunnel(t *testing.T) {
	cases := map[string]struct {
		driver Driver
		ttl    time.Duration
		cancel bool
		notify error
	}{
		"success":       {driver: afterRoundDriver{}},
		"site refused":  {driver: afterRoundDriver{result: site.ErrLoginRejected}},
		"bad password":  {driver: afterRoundDriver{result: site.ErrBadCredentials}},
		"human timeout": {driver: stubDriver{}, ttl: 60 * time.Millisecond},
		"cancelled":     {driver: stubDriver{}, cancel: true},
		"notify failed": {driver: stubDriver{}, notify: fmt.Errorf("dingtalk down")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ts := &trackedTunnels{}
			ttl := c.ttl
			if ttl == 0 {
				ttl = time.Minute
			}
			m := NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: okNotifier{err: c.notify}, Tunnels: ts,
				PageURL: "https://page.example/", TTL: ttl, Grace: time.Hour, OutcomeCap: 250 * time.Millisecond})
			u, _ := url.Parse("https://site.example")
			f := m.Start(c.driver, u, "", http.DefaultClient, nil)
			if c.cancel {
				waitFor(t, "the person being waited for", func() bool { return f.Snapshot().Phase == "waiting_human" })
				m.CancelBase("https://site.example")
			}
			select {
			case <-f.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("flow did not finish")
			}
			waitFor(t, "the tunnel to be closed", func() bool { return ts.stillOpen() == 0 })
			if n := ts.stillOpen(); n != 0 {
				t.Errorf("%d tunnel(s) still open after the login ended (opened %d): a tunnel is one-shot", n, ts.total())
			}
		})
	}
}

// Driver is what the table above needs from a site driver.
type Driver = site.Driver

// The page learns the outcome by polling the tunnel, so the tunnel has to stay up just long enough for that. Once the
// page has read the final state the tunnel is no longer needed and must be closed at once; if nobody ever reads it,
// a short cap closes it anyway. Neither may wait for the old 30 s grace.
func TestTunnelClosesRightAfterThePageReadsTheOutcome(t *testing.T) {
	ts := &trackedTunnels{}
	m := NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, Grace: time.Hour, OutcomeCap: time.Hour, FlushDelay: 50 * time.Millisecond})
	u, _ := url.Parse("https://site.example")
	f := m.Start(afterRoundDriver{}, u, "", http.DefaultClient, nil)
	<-f.Done()
	if ts.stillOpen() != 1 {
		t.Fatalf("the tunnel must stay up for the page to read the outcome, open=%d", ts.stillOpen())
	}
	// The page polls the round's status over the (local end of the) tunnel and reads the final state.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/%s/status", f.port, f.cur.Token))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitFor(t, "the tunnel to close after the outcome was read", func() bool { return ts.stillOpen() == 0 })
}

func TestTunnelClosesAtTheCapWhenNobodyReadsTheOutcome(t *testing.T) {
	ts := &trackedTunnels{}
	m := NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, Grace: time.Hour, OutcomeCap: 200 * time.Millisecond})
	u, _ := url.Parse("https://site.example")
	f := m.Start(afterRoundDriver{}, u, "", http.DefaultClient, nil)
	<-f.Done()
	start := time.Now()
	waitFor(t, "the cap to close the tunnel", func() bool { return ts.stillOpen() == 0 })
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("closed after %v; the cap is 200 ms", d)
	}
}

// reachTunnels hands out tunnels whose public address either reaches a server (answering 404 to any path, as the real
// API does for an unknown token) or is a dead route (502, as localhost.run answers for a name without a tunnel).
type reachTunnels struct {
	mu      sync.Mutex
	plan    []string // per start: "ok" | "dead" | "unreachable"
	servers []*httptest.Server
	started []*trackedTunnel
	ts      trackedTunnels
}

func (r *reachTunnels) Start(ctx context.Context, port int) (Tunnel, error) {
	r.mu.Lock()
	kind := "ok"
	if len(r.started) < len(r.plan) {
		kind = r.plan[len(r.started)]
	}
	r.mu.Unlock()
	tn, err := r.ts.Start(ctx, port)
	if err != nil {
		return nil, err
	}
	t := tn.(*trackedTunnel)
	var h http.Handler
	switch kind {
	case "ok":
		h = http.NotFoundHandler()
	case "dead":
		h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no tunnel", http.StatusBadGateway) })
	}
	url := "http://127.0.0.1:1" // unreachable
	if h != nil {
		srv := httptest.NewServer(h)
		r.mu.Lock()
		r.servers = append(r.servers, srv)
		r.mu.Unlock()
		url = srv.URL
	}
	r.mu.Lock()
	r.started = append(r.started, t)
	r.mu.Unlock()
	return &urlTunnel{trackedTunnel: t, url: url}, nil
}

type urlTunnel struct {
	*trackedTunnel
	url string
}

func (u *urlTunnel) PublicURL() string { return u.url }

func (r *reachTunnels) close() {
	for _, s := range r.servers {
		s.Close()
	}
}

func reachManager(t *testing.T, ts TunnelStarter, n Notifier) *Manager {
	return NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: n, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, OutcomeCap: 200 * time.Millisecond, ProbeTimeout: 2 * time.Second})
}

// A link to a tunnel that does not carry traffic is worse than no link: the person opens it, the page gets a 502,
// and the agent waits for ever. So the tunnel is checked from outside before anyone is told, and a dead one is
// closed and replaced, with the person never seeing it.
func TestADeadTunnelIsReplacedBeforeTheLinkIsSent(t *testing.T) {
	rt := &reachTunnels{plan: []string{"dead", "ok"}}
	defer rt.close()
	rec := &recNotifier{}
	m := reachManager(t, rt, rec)
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	if rt.ts.total() != 2 {
		t.Errorf("%d tunnels started; the dead one must be replaced by a second", rt.ts.total())
	}
	if rt.ts.stillOpen() != 1 {
		t.Errorf("%d tunnels open; the dead one must have been closed, leaving only the working one", rt.ts.stillOpen())
	}
	if msg := rec.all()[0]; !strings.Contains(msg, "127.0.0.1") {
		t.Errorf("the link must carry the working tunnel's address: %s", msg)
	}
	if f.Snapshot().Phase != "waiting_human" {
		t.Errorf("phase %q", f.Snapshot().Phase)
	}
}

func TestEveryTunnelDeadMeansNoLinkAndNothingLeftOpen(t *testing.T) {
	rt := &reachTunnels{plan: []string{"dead", "unreachable", "dead", "dead"}} // as many as one attempt may open
	defer rt.close()
	rec := &recNotifier{}
	m := reachManager(t, rt, rec)
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	select {
	case <-f.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("flow did not finish")
	}
	if !errors.Is(f.Result().Err, ErrTunnel) {
		t.Fatalf("err = %v, want a tunnel error", f.Result().Err)
	}
	if len(rec.all()) != 0 {
		t.Errorf("%d messages sent; a link to a tunnel that does not work must never be sent", len(rec.all()))
	}
	if rt.ts.stillOpen() != 0 {
		t.Errorf("%d tunnels left open", rt.ts.stillOpen())
	}
}

func TestAWorkingTunnelIsNotReplaced(t *testing.T) {
	rt := &reachTunnels{plan: []string{"ok"}}
	defer rt.close()
	rec := &recNotifier{}
	m := reachManager(t, rt, rec)
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	if rt.ts.total() != 1 {
		t.Errorf("%d tunnels for a working one", rt.ts.total())
	}
}

type namedTunnels struct{ reachTunnels }

type namedTunnel struct {
	*urlTunnel
	name string
}

func (n namedTunnel) ProviderName() string { return n.name }

func (n *namedTunnels) Start(ctx context.Context, port int) (Tunnel, error) {
	tn, err := n.reachTunnels.Start(ctx, port)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	idx := len(n.started) - 1
	n.mu.Unlock()
	return namedTunnel{tn.(*urlTunnel), []string{"localhost.run", "pinggy"}[idx%2]}, nil
}

// Which provider carried a link, and how many tunnels were opened to find one that works, is reported, so the next
// "which tunnel was that?" has an answer that is not a guess.
func TestTheTunnelThatCarriedTheLinkIsReported(t *testing.T) {
	nt := &namedTunnels{reachTunnels{plan: []string{"dead", "ok"}}}
	defer nt.close()
	type report struct {
		provider string
		attempts int
	}
	var mu sync.Mutex
	var got []report
	rec := &recNotifier{}
	m := NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: rec, Tunnels: nt,
		PageURL: "https://page.example/", TTL: time.Minute, ProbeTimeout: 2 * time.Second,
		OnTunnel: func(_ *Flow, p string, n int) { mu.Lock(); got = append(got, report{p, n}); mu.Unlock() }})
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].provider != "pinggy" || got[0].attempts != 2 {
		t.Fatalf("reports = %+v, want one: pinggy after 2 attempts (the first, localhost.run, was dead)", got)
	}
}

// The response that carries the final state must reach the page before the tunnel and the server are torn down:
// closing them the instant the handler returns can cut the answer off, and the page then reports "lost contact"
// although the login succeeded. So reading the final state starts a short delay (FlushDelay), it does not close.
func TestTheFinalAnswerIsDeliveredBeforeTheTunnelCloses(t *testing.T) {
	ts := &trackedTunnels{}
	m := NewManager(Config{Keys: keyring.NewPool(t.TempDir(), 8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, Grace: time.Hour, OutcomeCap: time.Hour, FlushDelay: 400 * time.Millisecond})
	u, _ := url.Parse("https://site.example")
	f := m.Start(afterRoundDriver{}, u, "", http.DefaultClient, nil)
	<-f.Done()
	statusURL := fmt.Sprintf("http://127.0.0.1:%d/%s/status", f.port, f.cur.Token)
	resp, err := http.Get(statusURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ts.stillOpen() != 1 {
		t.Fatalf("the tunnel was closed the instant the final state was read (open=%d); the answer may not have arrived", ts.stillOpen())
	}
	// A second poll inside the delay must still be answered (the page may poll again before it renders).
	resp, err = http.Get(statusURL)
	if err != nil {
		t.Fatalf("a poll right after the first read failed: %v", err)
	}
	resp.Body.Close()
	waitFor(t, "the tunnel to close after the flush delay", func() bool { return ts.stillOpen() == 0 })
}
