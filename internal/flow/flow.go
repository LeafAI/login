// Package flow runs one login request end to end: key, API server, tunnel, DingTalk message(s),
// human rounds, and the site driver's login.
package flow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LeafAI/login/internal/api"
	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/notify"
	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/web"
)

// Errors surfaced to the MCP layer.
var (
	ErrHumanTimeout = errors.New("nobody completed the login step before it expired")
	ErrNotify       = errors.New("could not notify the human")
	ErrTunnel       = errors.New("tunnel unavailable")
	// ErrFactor means a configured TOTP factor could not be applied to the link, so no link was sent.
	ErrFactor = errors.New("a configured one-time-code factor could not be applied")
)

// RejectedError is returned when the human pressed Reject.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string {
	if e.Reason == "" {
		return "the user rejected the login request"
	}
	return "the user rejected the login request: " + e.Reason
}

type Notifier interface {
	Markdown(ctx context.Context, title, text string) error
}

type TunnelStarter interface {
	Start(ctx context.Context, localPort int) (Tunnel, error)
}

// CodeSource is a time-based code (a TOTP): the codes valid between two moments, and how many digits they have.
type CodeSource interface {
	Window(from, to time.Time) []string
	Digits() int
}

type Tunnel interface {
	PublicURL() string
	Done() <-chan struct{}
	Close()
}

type Config struct {
	Keys     *keyring.Pool
	Notifier Notifier
	Tunnels  TunnelStarter
	PageURL  string
	TTL      time.Duration // per round
	Grace    time.Duration // deprecated: the tunnel now closes when the page has read the outcome, or at OutcomeCap
	// OutcomeCap is the longest the tunnel stays up after a login that ended while a page was listening (default
	// 10 s): enough for the page's next poll to read the outcome. Every other ending closes the tunnel at once.
	OutcomeCap time.Duration
	// Unlock, when set, is the long-period factor: the secret parameters of every link (site, tunnel address, one-shot
	// password) are encrypted in the DingTalk message and the person needs its code to read them in the page.
	Unlock CodeSource
	// Seal, when set, is the short-period factor: the page seals the credential with its code before anything leaves
	// the browser, and the server opens it with the code it computes itself.
	Seal CodeSource
	// FlushDelay is how long the tunnel stays up after the page has read the final state, so that the response that
	// carried it is delivered and a repeated poll is still answered (default 3 s). It is a delay, not a grace for
	// waiting: the tunnel is closed when it ends.
	FlushDelay time.Duration
	// ProbeTimeout bounds the check that a new tunnel really carries traffic before its link is sent (default 8 s).
	ProbeTimeout time.Duration
	// OnTunnel, when set, is told which provider carries a flow's tunnel (for the audit log).
	OnTunnel func(f *Flow, provider string, attempts int)
	Log      func(format string, args ...any)
	// Admit, when set, is asked before a NEW flow bothers a human (a request that joins a running flow is
	// not asked again). A non-nil error refuses the flow: Start returns it already finished with that error.
	Admit func(d site.Driver, base *url.URL, reason string) error
	// OnRound, when set, is told once per human round (login, totp, ...) after its DingTalk message was
	// sent. A replacement link after a tunnel restart is the same round and is not reported again.
	OnRound func(f *Flow, mode string, round int)
}

type Manager struct {
	cfg Config

	mu     sync.Mutex
	flows  map[string]*Flow // by id
	byBase map[string]*Flow // running flow per site base URL
}

func NewManager(cfg Config) *Manager {
	if cfg.TTL == 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.Grace == 0 {
		cfg.Grace = 30 * time.Second
	}
	if cfg.OutcomeCap == 0 {
		cfg.OutcomeCap = 10 * time.Second
	}
	if cfg.FlushDelay == 0 {
		cfg.FlushDelay = 3 * time.Second
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 8 * time.Second
	}
	return &Manager{cfg: cfg, flows: map[string]*Flow{}, byBase: map[string]*Flow{}}
}

// Snapshot is the externally visible state of a flow.
type Snapshot struct {
	Phase     string // starting | waiting_human | working | done
	Mode      string
	Round     int
	ExpiresAt time.Time
}

type Result struct {
	Session *site.Session
	Err     error
}

type Flow struct {
	ID     string
	Site   string
	Base   *url.URL
	Reason string

	m      *Manager
	cancel context.CancelFunc
	done   chan struct{}
	result Result

	mu   sync.Mutex
	snap Snapshot

	// lazily created by the first Ask
	key    *keyring.Key
	srv    *api.Server
	port   int
	tn     Tunnel
	cur    *api.Round
	rounds int

	closeOnce sync.Once
}

// shutdown stops the tunnel and API server (idempotent).
func (f *Flow) shutdown() {
	f.closeOnce.Do(func() {
		if f.tn != nil {
			f.tn.Close()
		}
		if f.srv != nil {
			f.srv.Close()
		}
	})
}

// Start launches (or joins) the login flow for a site. onDone runs once with the result.
func (m *Manager) Start(d site.Driver, base *url.URL, reason string, hc *http.Client, onDone func(*Flow, Result)) *Flow {
	key := site.Key(base)
	m.mu.Lock()
	if f := m.byBase[key]; f != nil {
		m.mu.Unlock()
		return f
	}
	if adm := m.cfg.Admit; adm != nil {
		if err := adm(d, base, reason); err != nil {
			m.mu.Unlock()
			return refused(d, base, reason, err)
		}
	}
	var idb [8]byte
	rand.Read(idb[:])
	ctx, cancel := context.WithCancel(context.Background())
	f := &Flow{ID: "lg_" + hex.EncodeToString(idb[:]), Site: d.Name(), Base: base, Reason: reason,
		m: m, cancel: cancel, done: make(chan struct{}), snap: Snapshot{Phase: "starting"}}
	m.flows[f.ID] = f
	m.byBase[key] = f
	m.mu.Unlock()

	go func() {
		sess, err := d.Login(ctx, base, f, hc)
		f.finish(sess, err)
		if onDone != nil {
			onDone(f, f.result)
		}
		m.mu.Lock()
		delete(m.byBase, key)
		m.mu.Unlock()
		go func() { // keep flows addressable for a while so login_wait can fetch the result
			time.Sleep(10 * time.Minute)
			m.mu.Lock()
			delete(m.flows, f.ID)
			m.mu.Unlock()
		}()
	}()
	return f
}

// refused is a flow that never started: it is already done and carries the reason.
func refused(d site.Driver, base *url.URL, reason string, err error) *Flow {
	f := &Flow{Site: d.Name(), Base: base, Reason: reason, cancel: func() {}, done: make(chan struct{}),
		snap: Snapshot{Phase: "done"}, result: Result{Err: err}}
	close(f.done)
	return f
}

func (m *Manager) Get(id string) *Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flows[id]
}

// Close cancels every running flow and tears down all tunnels immediately.
func (m *Manager) Close() {
	m.mu.Lock()
	flows := make([]*Flow, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, f)
	}
	m.mu.Unlock()
	for _, f := range flows {
		f.cancel()
	}
	for _, f := range flows {
		select {
		case <-f.done:
		case <-time.After(2 * time.Second):
		}
		f.shutdown()
	}
}

// CancelBase cancels a running flow for the given site base URL.
func (m *Manager) CancelBase(key string) bool {
	m.mu.Lock()
	f := m.byBase[key]
	m.mu.Unlock()
	if f == nil {
		return false
	}
	f.cancel()
	return true
}

func (f *Flow) Done() <-chan struct{} { return f.done }
func (f *Flow) Result() Result        { return f.result }

func (f *Flow) Snapshot() Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap
}

func (f *Flow) set(s Snapshot) {
	f.mu.Lock()
	f.snap = s
	f.mu.Unlock()
}

func (f *Flow) logf(format string, a ...any) {
	if f.m.cfg.Log != nil {
		f.m.cfg.Log(format, a...)
	}
}

// setup starts the key, API server and tunnel on first use.
func (f *Flow) setup(ctx context.Context) error {
	if f.srv != nil {
		return nil
	}
	key, err := f.m.cfg.Keys.Acquire()
	if err != nil {
		return fmt.Errorf("key pool: %w", err)
	}
	srv := api.NewServer(key)
	if f.m.cfg.Seal != nil {
		srv.SetFactor(f.m.cfg.Seal)
	}
	port, err := srv.Start()
	if err != nil {
		return err
	}
	tn, err := f.openTunnel(ctx, port)
	if err != nil {
		srv.Close()
		return err
	}
	f.key, f.srv, f.port, f.tn = key, srv, port, tn
	return nil
}

// maxTunnelStarts bounds how many tunnels one attempt may open and discard looking for one that works.
const maxTunnelStarts = 4

// openTunnel starts a tunnel and checks, from the outside, that it really carries traffic to this flow's API before
// the caller may put its address in a link. A tunnel whose ssh process is alive but whose public name is not routed
// (a 502 "no tunnel", seen on a free provider) is closed at once and replaced; a link is only ever built for a tunnel
// that answered.
func (f *Flow) openTunnel(ctx context.Context, port int) (Tunnel, error) {
	var last error
	for i := 1; i <= maxTunnelStarts; i++ {
		tn, err := f.m.cfg.Tunnels.Start(ctx, port)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTunnel, err)
		}
		if err := f.probeTunnel(ctx, tn.PublicURL()); err != nil {
			f.logf("tunnel %s does not carry traffic (%v); replacing it", tn.PublicURL(), err)
			tn.Close()
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if cb := f.m.cfg.OnTunnel; cb != nil {
			cb(f, providerOf(tn), i)
		}
		return tn, nil
	}
	return nil, fmt.Errorf("%w: %d tunnels were opened and none carried traffic (last: %v)", ErrTunnel, maxTunnelStarts, last)
}

// providerOf names the provider behind a tunnel when it says so.
func providerOf(tn Tunnel) string {
	if p, ok := tn.(interface{ ProviderName() string }); ok {
		return p.ProviderName()
	}
	return ""
}

// probeTunnel asks the tunnel's public address for a path that does not exist. Our API answers that with 404; a dead
// route is answered by the provider itself (502, 503, 530...) or not at all. Anything but a 404 means the tunnel does
// not reach this server.
func (f *Flow) probeTunnel(ctx context.Context, publicURL string) error {
	pctx, cancel := context.WithTimeout(ctx, f.m.cfg.ProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, strings.TrimRight(publicURL, "/")+"/tunnel-check", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("answered %d, not our API", resp.StatusCode)
	}
	return nil
}

const maxTunnelRestarts = 2

// tunnelDown reports whether the current tunnel process has exited.
func (f *Flow) tunnelDown() bool {
	select {
	case <-f.tn.Done():
		return true
	default:
		return false
	}
}

// restartTunnel replaces a dead tunnel; the API server (and its tokens) stay the same.
func (f *Flow) restartTunnel(ctx context.Context) error {
	f.tn.Close()
	tn, err := f.openTunnel(ctx, f.port)
	if err != nil {
		return fmt.Errorf("%w: restart failed: %v", ErrTunnel, err)
	}
	f.tn = tn
	return nil
}

// Ask implements site.Asker: it runs one human round.
func (f *Flow) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	f.set(Snapshot{Phase: "starting", Mode: mode, Round: f.rounds + 1})
	if err := f.setup(ctx); err != nil {
		return nil, err
	}
	restarts := 0
	if f.tunnelDown() { // died between rounds
		if err := f.restartTunnel(ctx); err != nil {
			return nil, err
		}
		restarts++
	}
	if f.cur != nil { // previous round succeeded; tell its page to wait for the next link
		f.cur.SetStatus(api.StateNextRound, "")
	}
	f.rounds++
	round := f.srv.NewRoundAt(web.BoundSite(f.Base.Host), mode, f.rounds, time.Now())
	f.cur = round

	pub, err := f.key.PublicKeyBinary()
	if err != nil {
		return nil, err
	}
	var cf []web.Field
	if mode == "custom" {
		for _, x := range fields {
			cf = append(cf, web.Field{Name: x.Name, Label: x.Label, Secret: x.Secret, Image: x.Image})
		}
	}
	expires := time.Now().Add(f.m.cfg.TTL)
	send := func(note string) error {
		wr := web.Round{
			Site: f.Base.Host, Mode: mode, N: f.rounds,
			APIBase:   strings.TrimRight(f.tn.PublicURL(), "/") + "/" + round.Token,
			PublicKey: pub, Fingerprint: f.key.Fingerprint(), Password: round.Password(), Fields: cf,
		}
		if sealSrc := f.m.cfg.Seal; sealSrc != nil {
			wr.FactorDigits = sealSrc.Digits()
		}
		if unlock := f.m.cfg.Unlock; unlock != nil {
			// The person may open the link at any moment of its life, so the codes of every window from now until it
			// expires are candidates; the page tries them against the code the person types.
			wr.LinkCodes = unlock.Window(time.Now(), expires)
			wr.LinkDigits = unlock.Digits()
		}
		// A factor that is switched on but cannot be applied stops the login here. A plain link would make the person
		// believe that the parameters are hidden.
		link, err := web.LinkChecked(f.m.cfg.PageURL, wr)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrFactor, err)
		}
		if err := f.m.cfg.Notifier.Markdown(ctx, "Login request: "+f.Base.Host, message(f, mode, f.rounds, link, f.key.Fingerprint(), expires, note, f.m.cfg.Unlock != nil, f.m.cfg.Seal != nil)); err != nil {
			return fmt.Errorf("%w: %v", ErrNotify, err)
		}
		return nil
	}
	if err := send(""); err != nil {
		return nil, err
	}
	if cb := f.m.cfg.OnRound; cb != nil {
		cb(f, mode, f.rounds)
	}
	f.set(Snapshot{Phase: "waiting_human", Mode: mode, Round: f.rounds, ExpiresAt: expires})
	f.logf("waiting for human: %s round %d (%s)", f.Base.Host, f.rounds, mode)

	wctx, cancel := context.WithTimeout(ctx, f.m.cfg.TTL)
	defer cancel()
	type res struct {
		sub api.Submission
		err error
	}
	ch := make(chan res, 1)
	go func() { s, err := round.Wait(wctx); ch <- res{s, err} }()
	for {
		select {
		case r := <-ch:
			if r.err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				round.SetStatus(api.StateFailed, "expired")
				return nil, ErrHumanTimeout
			}
			if r.sub.Action == api.ActionReject {
				round.SetStatus(api.StateRejected, "")
				return nil, &RejectedError{Reason: r.sub.Reason}
			}
			f.set(Snapshot{Phase: "working", Mode: mode, Round: f.rounds})
			return site.Credentials(r.sub.Fields), nil
		case <-f.tn.Done():
			// The tunnel died while the human had not answered yet: bring up a new one and send a
			// replacement link for the same round (same token and key, new public address).
			if restarts >= maxTunnelRestarts {
				return nil, fmt.Errorf("%w: ssh tunnel exited %d times", ErrTunnel, restarts+1)
			}
			restarts++
			f.logf("tunnel died; restarting (%d/%d)", restarts, maxTunnelRestarts)
			if err := f.restartTunnel(ctx); err != nil {
				return nil, err
			}
			if err := send("The tunnel connection dropped and was re-created. This link replaces the previous one."); err != nil {
				return nil, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// finish records the result and ends the tunnel's life. A tunnel serves exactly one login:
//   - when a page is listening (a human round was open) the tunnel stays only until that page has read the final
//     state, or OutcomeCap passes if nobody reads it;
//   - in every other case (no round was open: cancelled early, notification failed, no tunnel yet) it is closed
//     right now.
func (f *Flow) finish(sess *site.Session, err error) {
	f.result = Result{Session: sess, Err: err}
	f.set(Snapshot{Phase: "done"})
	listening := false
	if f.cur != nil {
		var rj *RejectedError
		switch {
		case err == nil:
			f.cur.SetStatus(api.StateDone, "")
			listening = true
		case errors.As(err, &rj):
			f.cur.SetStatus(api.StateRejected, "")
			listening = true
		case errors.Is(err, site.ErrBadCredentials):
			f.cur.SetStatus(api.StateFailed, "Wrong username or password.")
			listening = true
		case errors.Is(err, site.ErrLoginRejected), errors.Is(err, site.ErrUnreachable):
			f.cur.SetStatus(api.StateFailed, "The site refused the login. Details were sent to the AI agent.")
			listening = true
		default:
			f.cur.SetStatus(api.StateFailed, "The site refused the login. Details were sent to the AI agent.")
		}
	}
	close(f.done)
	if f.srv == nil && f.tn == nil {
		return
	}
	if !listening || !f.pageIsListening() {
		f.shutdown()
		return
	}
	f.cur.OnFinalRead(func() { time.AfterFunc(f.m.cfg.FlushDelay, f.shutdown) })
	time.AfterFunc(f.m.cfg.OutcomeCap, f.shutdown)
}

// pageIsListening reports whether a human round was open when the login ended, so a page may still poll.
func (f *Flow) pageIsListening() bool { return f.cur != nil && f.tn != nil }

func message(f *Flow, mode string, n int, link, fpr string, expires time.Time, note string, unlockOn, sealOn bool) string {
	step := map[string]string{"login": "username & password", "totp": "two-factor code", "custom": "additional information"}[mode]
	if step == "" {
		step = mode
	}
	reason := notify.Escape(f.Reason, 200)
	if reason == "" {
		reason = "(not given)"
	}
	short := strings.ToUpper(fpr)
	if len(short) > 16 {
		short = short[len(short)-16:]
	}
	var groups []string // "8885 4F38 DA77 58C0": identical to the verification code the page shows
	for i := 0; i+4 <= len(short); i += 4 {
		groups = append(groups, short[i:i+4])
	}
	short = strings.Join(groups, " ")
	return note + fmt.Sprintf("### Login request: %s\n\n"+
		"- **Step %d**: %s\n- **Requested by AI agent**: %s\n- **Expires**: %s\n- **Key code** (compare it with the page): `%s`\n\n"+
		"%s"+
		"[Open the login page](%s)\n\n"+
		"You can also press **Reject** on the page and give a reason. "+
		"If you did not expect this, ignore it.",
		notify.Escape(f.Base.Host, 100), n, step, reason, expires.Format("15:04:05"), short, codeNotes(unlockOn, sealOn), link)
}

// codeNotes tells the person which codes they will be asked for. The codes themselves are never in a message: they are
// in the person's authenticator.
func codeNotes(unlockOn, sealOn bool) string {
	var b strings.Builder
	if unlockOn {
		b.WriteString("- **Unlock code** needed: the details of this login are encrypted in the link. Type the code from your authenticator (the long-period one) in the page to read them.\n")
	}
	if sealOn {
		b.WriteString("- **Sealing code** needed: the page also asks for the short-period code from your authenticator and seals what you type with it.\n")
	}
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

// HostPort is a small helper for tests.
func HostPort(u string) string {
	p, _ := url.Parse(u)
	h, _, err := net.SplitHostPort(p.Host)
	if err != nil {
		return p.Host
	}
	return h
}
