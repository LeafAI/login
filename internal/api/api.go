// Package api is the one-shot JSON API exposed through the SSH tunnel.
//
// Each authentication round has its own random token and accepts exactly one valid, encrypted
// submission. The API never serves HTML or scripts.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/seal"
)

const (
	ActionSubmit = "submit"
	ActionReject = "reject"

	StateWaiting   = "waiting"
	StateWorking   = "working"
	StateDone      = "done"
	StateFailed    = "failed"
	StateRejected  = "rejected"
	StateNextRound = "next_round"
)

// Envelope is what the OpenPGP layer carries: the submission sealed under the round's one-shot password
// (AES-256-GCM, see package seal) and the nonce that is bound into the seal. The nonce is repeated in the clear
// inside the OpenPGP layer only so that the server knows what the seal was bound to; the seal fails to open if it
// was swapped.
type Envelope struct {
	Sealed string `json:"sealed"`
	Nonce  string `json:"nonce"`
}

// Submission is the decrypted content of one round.
type Submission struct {
	Action string            `json:"action"`
	Fields map[string]string `json:"fields,omitempty"`
	Reason string            `json:"reason,omitempty"` // for reject
	Nonce  string            `json:"nonce"`
	TS     int64             `json:"ts"`
	Mode   string            `json:"mode"`
	Round  int               `json:"round"`
}

// Status is returned by GET /<token>/status.
type Status struct {
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// Factor is a second secret that the person holds in their authenticator (a long-period TOTP code) and that is mixed
// into the key of every seal. The server never receives the code: it computes the codes that are valid now and tries
// them as keys, so a submission sealed under any other code simply does not open.
type Factor interface {
	// Window returns the codes of every window between from and to: the person reads the code some time after the link
	// was made and the submission arrives later still, so all of those windows' codes may be the one that was used.
	Window(from, to time.Time) []string
	// Digits is the length of a code, announced to the page so that it can check what the person typed.
	Digits() int
}

type Server struct {
	key *keyring.Key
	srv *http.Server
	ln  net.Listener

	mu     sync.Mutex
	rounds map[string]*Round
	nonces map[string]struct{}
	now    func() time.Time

	factor Factor // nil: seals need no second factor
}

// SetFactor requires every submission to be sealed with the second factor too. Without it, plain seals are accepted;
// with it, ONLY factor seals are, so the factor cannot be skipped.
func (s *Server) SetFactor(f Factor) {
	s.mu.Lock()
	s.factor = f
	s.mu.Unlock()
}

// FactorDigits is the code length of the configured factor, or 0 when there is none.
func (s *Server) FactorDigits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.factor == nil {
		return 0
	}
	return s.factor.Digits()
}

func NewServer(key *keyring.Key) *Server {
	return &Server{key: key, rounds: map[string]*Round{}, nonces: map[string]struct{}{}, now: time.Now}
}

// Start listens on 127.0.0.1 with a random port and returns it.
func (s *Server) Start() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	s.ln = ln
	s.srv = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	go s.srv.Serve(ln)
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (s *Server) Close() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.srv.Shutdown(ctx)
	}
}

// Round is one authentication step (login, totp, ...).
type Round struct {
	Token string
	Site  string
	Mode  string
	N     int

	// password is the round's one-shot seal password (see package seal). It is generated with the round, travels only
	// in the link, and is wiped as soon as the round has been used.
	password []byte
	made     time.Time // when the link of this round was made

	mu       sync.Mutex
	status   Status
	attempts int
	done     bool
	ch       chan Submission

	onFinalRead func()
}

// NewRoundFor registers a new round for a site with a fresh random token and a fresh one-shot seal password.
func (s *Server) NewRoundFor(site, mode string, n int) *Round {
	return s.NewRoundAt(site, mode, n, s.now())
}

// NewRoundAt is NewRoundFor with the moment the round's link was made (the start of the span of codes to try).
func (s *Server) NewRoundAt(site, mode string, n int, made time.Time) *Round {
	var b [16]byte
	rand.Read(b[:])
	pw, err := seal.NewPassword()
	if err != nil {
		panic(err) // the system's random source is broken: nothing safe can be done
	}
	r := &Round{Token: hex.EncodeToString(b[:]), Site: site, Mode: mode, N: n, password: pw, made: made,
		ch: make(chan Submission, 1), status: Status{State: StateWaiting}}
	s.mu.Lock()
	s.rounds[r.Token] = r
	s.mu.Unlock()
	return r
}

// Password returns the round's one-shot seal password, for the link. It is empty once the round has been used.
func (r *Round) Password() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.password
}

// wipe destroys the one-shot password: it has done its job once the round's submission was accepted.
func (r *Round) wipe() {
	r.mu.Lock()
	seal.Wipe(r.password)
	r.mu.Unlock()
}

// Wait blocks until the round receives a valid submission or ctx ends.
func (r *Round) Wait(ctx context.Context) (Submission, error) {
	select {
	case sub := <-r.ch:
		return sub, nil
	case <-ctx.Done():
		return Submission{}, ctx.Err()
	}
}

// SetStatus updates what the page sees when polling.
func (r *Round) SetStatus(state, msg string) {
	r.mu.Lock()
	r.status = Status{State: state, Message: msg}
	r.mu.Unlock()
}

func (r *Round) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// OnFinalRead registers fn, called once when the page has read a final state (done, failed, rejected) of this round
// by polling status. The tunnel is only needed until then.
func (r *Round) OnFinalRead(fn func()) {
	r.mu.Lock()
	r.onFinalRead = fn
	r.mu.Unlock()
}

func (r *Round) noteRead(st Status) {
	switch st.State {
	case StateDone, StateFailed, StateRejected:
	default:
		return
	}
	r.mu.Lock()
	fn := r.onFinalRead
	r.onFinalRead = nil
	r.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if req.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, req)
		return
	}
	round := s.lookup(parts[0])
	if round == nil {
		http.NotFound(w, req)
		return
	}
	switch {
	case parts[1] == "status" && req.Method == http.MethodGet:
		st := round.Status()
		writeJSON(w, http.StatusOK, st)
		round.noteRead(st)
	case parts[1] == "submit" && req.Method == http.MethodPost:
		s.submit(w, req, round)
	default:
		http.NotFound(w, req)
	}
}

func (s *Server) lookup(token string) *Round {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, r := range s.rounds {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			return r
		}
	}
	return nil
}

func (s *Server) submit(w http.ResponseWriter, req *http.Request, r *Round) {
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "round already completed"})
		return
	}
	r.attempts++
	tooMany := r.attempts > 20
	r.mu.Unlock()
	if tooMany {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read failed"})
		return
	}
	outer, err := s.key.Decrypt(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot decrypt (wrong public key?)"})
		return
	}
	s.mu.Lock()
	factor := s.factor
	s.mu.Unlock()
	plain, ok := r.open(outer, factor, s.now())
	zero(outer)
	if !ok {
		// One answer for every way a seal can fail (not sealed, wrong password, other round or site, tampering), so
		// that a probing client learns nothing about which layer rejected it.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "submission refused"})
		return
	}
	var sub Submission
	if err := json.Unmarshal(plain, &sub); err != nil {
		zero(plain)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed payload"})
		return
	}
	zero(plain)
	if msg := s.validate(req, r, &sub); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}

	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "round already completed"})
		return
	}
	r.done = true
	r.status = Status{State: StateWorking}
	r.mu.Unlock()
	r.wipe()
	r.ch <- sub
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// open takes the OpenPGP-decrypted envelope and opens the seal under this round's password, bound to this round's
// site, step and number and to the envelope's nonce. It reports false for anything but a valid seal for this round.
func (r *Round) open(outer []byte, factor Factor, now time.Time) ([]byte, bool) {
	made := r.made
	var env Envelope
	if err := json.Unmarshal(outer, &env); err != nil || env.Sealed == "" || env.Nonce == "" {
		return nil, false
	}
	r.mu.Lock()
	pw := r.password
	r.mu.Unlock()
	c := seal.Context{Site: r.Site, Mode: r.Mode, Round: r.N, Nonce: env.Nonce}
	var plain []byte
	var err error
	if factor != nil {
		plain, err = seal.OpenWithFactor(pw, factor.Window(made, now), c, env.Sealed)
	} else {
		plain, err = seal.Open(pw, c, env.Sealed)
	}
	if err != nil {
		return nil, false
	}
	return plain, true
}

func (s *Server) validate(req *http.Request, r *Round, sub *Submission) string {
	q := req.URL.Query()
	if sub.Action != ActionSubmit && sub.Action != ActionReject {
		return "unknown action"
	}
	if sub.Mode != r.Mode || sub.Round != r.N || q.Get("mode") != r.Mode || q.Get("round") != strconv.Itoa(r.N) {
		return "mode/round mismatch"
	}
	if d := s.now().Sub(time.Unix(sub.TS, 0)); d > 2*time.Minute || d < -2*time.Minute {
		return "stale timestamp (check the clock)"
	}
	if sub.Nonce == "" {
		return "missing nonce"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.nonces[sub.Nonce]; dup {
		return "replayed nonce"
	}
	s.nonces[sub.Nonce] = struct{}{}
	return ""
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

var ErrRejected = errors.New("rejected by user")
