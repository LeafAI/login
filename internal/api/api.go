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

type Server struct {
	key *keyring.Key
	srv *http.Server
	ln  net.Listener

	mu     sync.Mutex
	rounds map[string]*Round
	nonces map[string]struct{}
	now    func() time.Time
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
	Mode  string
	N     int

	mu       sync.Mutex
	status   Status
	attempts int
	done     bool
	ch       chan Submission
}

// NewRound registers a new round with a fresh random token.
func (s *Server) NewRound(mode string, n int) *Round {
	var b [16]byte
	rand.Read(b[:])
	r := &Round{Token: hex.EncodeToString(b[:]), Mode: mode, N: n, ch: make(chan Submission, 1), status: Status{State: StateWaiting}}
	s.mu.Lock()
	s.rounds[r.Token] = r
	s.mu.Unlock()
	return r
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
		writeJSON(w, http.StatusOK, round.Status())
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
	plain, err := s.key.Decrypt(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot decrypt (wrong public key?)"})
		return
	}
	var sub Submission
	if err := json.Unmarshal(plain, &sub); err != nil {
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
	r.ch <- sub
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
