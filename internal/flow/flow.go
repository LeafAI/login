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
	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/web"
)

// Errors surfaced to the MCP layer.
var (
	ErrHumanTimeout = errors.New("nobody completed the login step before it expired")
	ErrNotify       = errors.New("could not notify the human")
	ErrTunnel       = errors.New("tunnel unavailable")
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
	Grace    time.Duration // keep the API up after the end so the page can show the result
	Log      func(format string, args ...any)
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
	tn     Tunnel
	cur    *api.Round
	rounds int
}

// Start launches (or joins) the login flow for a site. onDone runs once with the result.
func (m *Manager) Start(d site.Driver, base *url.URL, reason string, hc *http.Client, onDone func(*Flow, Result)) *Flow {
	key := base.Scheme + "://" + base.Host
	m.mu.Lock()
	if f := m.byBase[key]; f != nil {
		m.mu.Unlock()
		return f
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

func (m *Manager) Get(id string) *Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flows[id]
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
	port, err := srv.Start()
	if err != nil {
		return err
	}
	tn, err := f.m.cfg.Tunnels.Start(ctx, port)
	if err != nil {
		srv.Close()
		return fmt.Errorf("%w: %v", ErrTunnel, err)
	}
	f.key, f.srv, f.tn = key, srv, tn
	return nil
}

// Ask implements site.Asker: it runs one human round.
func (f *Flow) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	f.set(Snapshot{Phase: "starting", Mode: mode, Round: f.rounds + 1})
	if err := f.setup(ctx); err != nil {
		return nil, err
	}
	if f.cur != nil { // previous round succeeded; tell its page to wait for the next link
		f.cur.SetStatus(api.StateNextRound, "")
	}
	f.rounds++
	round := f.srv.NewRound(mode, f.rounds)
	f.cur = round

	pub, err := f.key.PublicKeyBinary()
	if err != nil {
		return nil, err
	}
	var cf []web.Field
	if mode == "custom" {
		for _, x := range fields {
			cf = append(cf, web.Field{Name: x.Name, Label: x.Label, Secret: x.Secret})
		}
	}
	link := web.Link(f.m.cfg.PageURL, web.Round{
		Site: f.Base.Host, Mode: mode, N: f.rounds,
		APIBase:   strings.TrimRight(f.tn.PublicURL(), "/") + "/" + round.Token,
		PublicKey: pub, Fingerprint: f.key.Fingerprint(), Fields: cf,
	})
	expires := time.Now().Add(f.m.cfg.TTL)
	if err := f.m.cfg.Notifier.Markdown(ctx, "Login request: "+f.Base.Host, message(f, mode, f.rounds, link, f.key.Fingerprint(), expires)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotify, err)
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
		return nil, fmt.Errorf("%w: ssh tunnel exited", ErrTunnel)
	}
}

// finish records the result, publishes the final status to the page and tears everything down.
func (f *Flow) finish(sess *site.Session, err error) {
	f.result = Result{Session: sess, Err: err}
	f.set(Snapshot{Phase: "done"})
	if f.cur != nil {
		var rj *RejectedError
		switch {
		case err == nil:
			f.cur.SetStatus(api.StateDone, "")
		case errors.As(err, &rj):
			f.cur.SetStatus(api.StateRejected, "")
		case errors.Is(err, site.ErrBadCredentials):
			f.cur.SetStatus(api.StateFailed, "Wrong username or password.")
		default:
			f.cur.SetStatus(api.StateFailed, "The site refused the login. Details were sent to the AI agent.")
		}
	}
	close(f.done)
	if f.srv != nil {
		go func() {
			time.Sleep(f.m.cfg.Grace)
			f.tn.Close()
			f.srv.Close()
		}()
	}
}

func message(f *Flow, mode string, n int, link, fpr string, expires time.Time) string {
	step := map[string]string{"login": "username & password", "totp": "two-factor code", "custom": "additional information"}[mode]
	if step == "" {
		step = mode
	}
	reason := f.Reason
	if reason == "" {
		reason = "(not given)"
	}
	short := fpr
	if len(short) > 16 {
		short = short[len(short)-16:]
	}
	return fmt.Sprintf("### Login request: %s\n\n"+
		"- **Step %d**: %s\n- **Requested by AI agent**: %s\n- **Expires**: %s\n- **Key**: `%s`\n\n"+
		"[Open the login page](%s)\n\n"+
		"You can also press **Reject** on the page and give a reason. "+
		"If you did not expect this, ignore it.",
		f.Base.Host, n, step, reason, expires.Format("15:04:05"), short, link)
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
