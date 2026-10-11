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

	"github.com/LeafAI/securl/internal/keyring"
	"github.com/LeafAI/securl/internal/site"
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
	return NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: n, Tunnels: ts,
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
	msg := message(f, "login", 1, "https://page.example/#v=1", "ABCDEF0123456789ABCDEF", time.Now(), "", false, false)
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
	cfg := Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: n, Tunnels: fakeTunnels{},
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
	cfg := Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: okNotifier{}, Tunnels: fakeTunnels{},
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
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: ts,
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
			m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: okNotifier{err: c.notify}, Tunnels: ts,
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
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
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
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
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
	return NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: n, Tunnels: ts,
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
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: nt,
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
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: okNotifier{}, Tunnels: ts,
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

// ---- the two TOTP factors ----

// codeSource is a Factors stand-in: it hands out fixed codes and records the spans it was asked about.
type codeSource struct {
	mu     sync.Mutex
	codes  []string
	digits int
	spans  [][2]time.Time
}

func (c *codeSource) Window(from, to time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spans = append(c.spans, [2]time.Time{from, to})
	return c.codes
}
func (c *codeSource) Digits() int { return c.digits }
func (c *codeSource) last() [2]time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spans[len(c.spans)-1]
}

func linkOf(msg string) string {
	i := strings.Index(msg, "](")
	j := strings.Index(msg[i:], ")")
	return msg[i+2 : i+j]
}

// With the unlock factor configured, the DingTalk message carries a link whose secret parameters are encrypted: neither
// the site, nor the tunnel address, nor the one-shot password is in it.
func TestTheDingTalkLinkIsEncryptedWithTheUnlockFactor(t *testing.T) {
	ts := &trackedTunnels{}
	rec := &recNotifier{}
	unlock := &codeSource{codes: []string{"11111111", "22222222"}, digits: 8}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: ts,
		PageURL: "https://page.example/", TTL: 10 * time.Minute, Unlock: unlock})
	defer m.Close()
	u, _ := url.Parse("https://gitlab.corp.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	msg := rec.all()[0]
	link := linkOf(msg)
	// The message text names the site on purpose (the person must see at a glance what is being asked); what is hidden
	// is the LINK: the site, the tunnel address and the one-shot password must not be in it, in any form.
	for _, leak := range []string{"gitlab", "corp.example", "127.0.0.1", "%2Ft0", "/t1", "site=", "u=", "s="} {
		if strings.Contains(link, leak) {
			t.Errorf("the link carries %q: %s", leak, link)
		}
	}
	frag, _ := url.ParseQuery(link[strings.Index(link, "#")+1:])
	if frag.Get("e") == "" || frag.Get("c") != "8" || frag.Get("u") != "" || frag.Get("s") != "" {
		t.Errorf("the link is not encrypted as expected: %v", frag)
	}
	// the candidates cover the whole life of the link: from now to its expiry (the person may open it any time then)
	span := unlock.last()
	if d := span[1].Sub(span[0]); d < 9*time.Minute || d > 11*time.Minute {
		t.Errorf("the unlock codes cover %v, want about the link's lifetime (10 minutes)", d)
	}
	if !strings.Contains(msg, "Unlock code") {
		t.Errorf("the message must tell the person that an unlock code is needed:\n%s", msg)
	}
}

// Without it the link is a plain one and says nothing about codes.
func TestWithoutTheUnlockFactorTheLinkIsPlain(t *testing.T) {
	rec := &recNotifier{}
	m := manager(t, rec, &trackedTunnels{}, time.Minute)
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	msg := rec.all()[0]
	frag, _ := url.ParseQuery(linkOf(msg)[strings.Index(linkOf(msg), "#")+1:])
	if frag.Get("e") != "" || frag.Get("site") == "" {
		t.Errorf("a plain link was expected: %v", frag)
	}
	if strings.Contains(msg, "Unlock code") || strings.Contains(msg, "Sealing code") {
		t.Errorf("the message mentions codes that are not in use:\n%s", msg)
	}
}

// The sealing factor is installed on the round's server, and the link announces its length.
func TestTheSealingFactorIsRequiredAndAnnounced(t *testing.T) {
	rec := &recNotifier{}
	seal := &codeSource{codes: []string{"123456"}, digits: 6}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: &trackedTunnels{},
		PageURL: "https://page.example/", TTL: time.Minute, Seal: seal})
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	frag, _ := url.ParseQuery(linkOf(rec.all()[0])[strings.Index(linkOf(rec.all()[0]), "#")+1:])
	if frag.Get("t") != "6" {
		t.Errorf("the link must announce the sealing code length, got t=%q", frag.Get("t"))
	}
	if f.srv == nil || f.srv.FactorDigits() != 6 {
		t.Errorf("the server must require the sealing factor")
	}
	if !strings.Contains(rec.all()[0], "Sealing code") {
		t.Errorf("the message must tell the person that a sealing code is needed:\n%s", rec.all()[0])
	}
}

// A factor that is switched on but cannot do its job must stop the login: sending a plain link would make the person
// believe the parameters are hidden. Here the source offers no codes at all.
func TestAnUnusableUnlockFactorSendsNoLink(t *testing.T) {
	rec := &recNotifier{}
	ts := &trackedTunnels{}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: ts,
		PageURL: "https://page.example/", TTL: time.Minute, Unlock: &codeSource{codes: nil, digits: 8}})
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	f := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	select {
	case <-f.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the flow did not stop")
	}
	if f.Result().Err == nil {
		t.Fatal("the login succeeded without an unlock code")
	}
	if len(rec.all()) != 0 {
		t.Errorf("%d messages sent; a link must not be sent when its protection cannot be applied", len(rec.all()))
	}
	waitFor(t, "the tunnel to be closed", func() bool { return ts.stillOpen() == 0 })
}

// With both factors, each does its own job and neither is confused with the other.
func TestBothFactorsTogether(t *testing.T) {
	rec := &recNotifier{}
	unlock := &codeSource{codes: []string{"11111111"}, digits: 8}
	seal := &codeSource{codes: []string{"222222"}, digits: 6}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: &trackedTunnels{},
		PageURL: "https://page.example/", TTL: time.Minute, Unlock: unlock, Seal: seal})
	defer m.Close()
	u, _ := url.Parse("https://site.example")
	m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	waitFor(t, "the link", func() bool { return len(rec.all()) == 1 })
	frag, _ := url.ParseQuery(linkOf(rec.all()[0])[strings.Index(linkOf(rec.all()[0]), "#")+1:])
	if frag.Get("c") != "8" || frag.Get("t") != "6" {
		t.Errorf("c=%q t=%q, want the unlock length 8 and the sealing length 6", frag.Get("c"), frag.Get("t"))
	}
}

func TestNotifyFailureDoesNotCarryWebhookSecrets(t *testing.T) {
	leaky := fmt.Errorf(`Post "https://oapi.dingtalk.com/robot/send?access_token=TOK123&sign=SIG&timestamp=17": refused`)
	r := run(t, manager(t, okNotifier{err: leaky}, fakeTunnels{}, time.Second))
	if !errors.Is(r.Err, ErrNotify) {
		t.Fatalf("err = %v", r.Err)
	}
	for _, bad := range []string{"TOK123", "sign=", "access_token", "timestamp="} {
		if strings.Contains(r.Err.Error(), bad) {
			t.Errorf("flow error leaks %q: %v", bad, r.Err)
		}
	}
	if !strings.Contains(r.Err.Error(), "refused") {
		t.Errorf("the cause must stay visible: %v", r.Err)
	}
}

// A flow can say what it is for, so that the message a person receives names the real request. The vault unlock is not
// a login to a site, and "Login request: vault" would send people looking for the wrong thing.
func TestPurposeChangesTheTitleAndTheWordingOfTheMessage(t *testing.T) {
	rec := &titledNotifier{}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: fakeTunnels{}, PageURL: "https://page.example/",
		TTL: time.Second, Log: func(string, ...any) {},
		Purpose: &Purpose{Title: "Vault unlock", Heading: "Unlock the vault", Step: "vault passphrase", Warning: "Only type it if you asked for this."}})
	u, _ := url.Parse("https://vault.invalid")
	f := m.Start(askOnce{}, u, "the agent needs a credential", http.DefaultClient, nil)
	<-f.Done()
	if len(rec.titles) == 0 || !strings.Contains(rec.titles[0], "Vault unlock") || strings.Contains(rec.titles[0], "Login request") {
		t.Errorf("title: %v", rec.titles)
	}
	text := rec.msgs[0]
	for _, want := range []string{"Unlock the vault", "vault passphrase", "Only type it if you asked for this."} {
		if !strings.Contains(text, want) {
			t.Errorf("the message lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "username & password") || strings.Contains(text, "### Login request") {
		t.Errorf("login wording must not leak into an unlock message:\n%s", text)
	}
}

func TestWithoutAPurposeTheMessageIsTheLoginRequestItAlwaysWas(t *testing.T) {
	rec := &titledNotifier{}
	m := NewManager(Config{Keys: keyring.NewMemoryPool(8, time.Hour), Notifier: rec, Tunnels: fakeTunnels{}, PageURL: "https://page.example/",
		TTL: time.Second, Log: func(string, ...any) {}})
	u, _ := url.Parse("https://site.example")
	f := m.Start(askOnce{}, u, "r", http.DefaultClient, nil)
	<-f.Done()
	if !strings.Contains(rec.titles[0], "Login request: site.example") || !strings.Contains(rec.msgs[0], "### Login request: site.example") {
		t.Errorf("%v\n%s", rec.titles, rec.msgs[0])
	}
}

// titledNotifier records title and text of every message.
type titledNotifier struct {
	mu     sync.Mutex
	titles []string
	msgs   []string
}

func (r *titledNotifier) Markdown(_ context.Context, title, text string) error {
	r.mu.Lock()
	r.titles, r.msgs = append(r.titles, title), append(r.msgs, text)
	r.mu.Unlock()
	return nil
}

// askOnce asks one custom round with a single secret field.
type askOnce struct{}

func (askOnce) Name() string        { return "askonce" }
func (askOnce) NeedsLogin() bool    { return true }
func (askOnce) Match(*url.URL) bool { return false }
func (askOnce) Login(ctx context.Context, _ *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	_, err := ask.Ask(ctx, "custom", []site.Field{{Name: "passphrase", Label: "Vault passphrase", Secret: true}})
	return nil, err
}
func (askOnce) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }

func TestRunningFindsTheLiveFlowOfASite(t *testing.T) {
	m := manager(t, okNotifier{}, fakeTunnels{}, time.Minute)
	u, _ := url.Parse("https://site.example")
	if m.Running(u) != nil {
		t.Fatal("nothing runs yet")
	}
	a := m.Start(stubDriver{}, u, "", http.DefaultClient, nil)
	if got := m.Running(u); got != a {
		t.Errorf("a live flow must be found by its site: %v", got)
	}
	other, _ := url.Parse("https://other.example")
	if m.Running(other) != nil {
		t.Error("another site has no flow")
	}
	m.CancelBase("https://site.example")
	<-a.Done()
	deadline := time.Now().Add(2 * time.Second)
	for m.Running(u) != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.Running(u) != nil {
		t.Error("a finished flow is not running any more")
	}
}
