package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/LeafAI/securl/internal/keyring"
	"github.com/LeafAI/securl/internal/seal"
)

type env struct {
	srv  *Server
	base string
	ents openpgp.EntityList
}

func setup(t *testing.T) *env {
	t.Helper()
	k, err := keyring.NewPool(t.TempDir(), 8, time.Hour).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := k.PublicKeyBinary()
	ents, _ := openpgp.ReadKeyRing(bytes.NewReader(pub))
	s := NewServer(k)
	port, err := s.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return &env{s, fmt.Sprintf("http://127.0.0.1:%d", port), ents}
}

func (e *env) encrypt(t *testing.T, sub Submission) []byte {
	t.Helper()
	plain, _ := json.Marshal(sub)
	return e.encryptRaw(t, plain)
}

func (e *env) encryptRaw(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	aw, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
	w, err := openpgp.Encrypt(aw, e.ents, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plain)
	w.Close()
	aw.Close()
	return buf.Bytes()
}

// sealedBody is what the page posts: the submission is sealed under the round's one-shot password (bound to the site,
// step, round and nonce), put in an envelope, and the envelope is encrypted to the OpenPGP key.
func (e *env) sealedBody(t *testing.T, r *Round, site string, sub Submission) []byte {
	t.Helper()
	plain, _ := json.Marshal(sub)
	sealed, err := seal.Seal(r.Password(), seal.Context{Site: site, Mode: sub.Mode, Round: sub.Round, Nonce: sub.Nonce}, plain)
	if err != nil {
		t.Fatal(err)
	}
	return e.encryptRaw(t, mustJSON(t, Envelope{Sealed: sealed, Nonce: sub.Nonce}))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(t *testing.T, url string, body []byte) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const site = "gitlab.corp.example"

func TestSubmitAndReplay(t *testing.T) {
	e := setup(t)
	r := e.srv.NewRoundFor(site, "login", 1)
	url := e.base + "/" + r.Token + "/submit?mode=login&round=1"
	sub := Submission{Action: ActionSubmit, Fields: map[string]string{"username": "u", "password": "p"}, Nonce: "n1", TS: time.Now().Unix(), Mode: "login", Round: 1}

	if code, _ := post(t, url, e.sealedBody(t, r, site, sub)); code != 200 {
		t.Fatalf("submit: %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := r.Wait(ctx)
	if err != nil || got.Fields["password"] != "p" {
		t.Fatalf("wait: %+v %v", got, err)
	}
	// second submission to the same round (even a fresh nonce) is refused
	sub.Nonce = "n2"
	if code, _ := post(t, url, e.sealedBody(t, r, site, sub)); code != 409 {
		t.Errorf("second submit: want 409 got %d", code)
	}
	// replay of the same nonce on another round is refused
	r2 := e.srv.NewRoundFor(site, "login", 2)
	sub.Round, sub.Nonce = 2, "n1"
	if code, _ := post(t, e.base+"/"+r2.Token+"/submit?mode=login&round=2", e.sealedBody(t, r2, site, sub)); code != 400 {
		t.Errorf("replayed nonce: want 400 got %d", code)
	}
}

func TestRejectAndValidation(t *testing.T) {
	e := setup(t)
	r := e.srv.NewRoundFor(site, "totp", 2)
	url := e.base + "/" + r.Token + "/submit?mode=totp&round=2"
	now := time.Now().Unix()

	bad := []Submission{
		{Action: ActionSubmit, Nonce: "a", TS: now, Mode: "login", Round: 2},      // mode mismatch
		{Action: ActionSubmit, Nonce: "b", TS: now, Mode: "totp", Round: 1},       // round mismatch
		{Action: ActionSubmit, Nonce: "c", TS: now - 600, Mode: "totp", Round: 2}, // stale
		{Action: "other", Nonce: "d", TS: now, Mode: "totp", Round: 2},            // action
		{Action: ActionSubmit, Nonce: "", TS: now, Mode: "totp", Round: 2},        // nonce
	}
	for i, s := range bad {
		if code, _ := post(t, url, e.sealedBody(t, r, site, s)); code != 400 {
			t.Errorf("bad[%d]: want 400 got %d", i, code)
		}
	}
	if code, _ := post(t, url, []byte("not pgp")); code != 400 {
		t.Errorf("garbage: %d", code)
	}
	rej := Submission{Action: ActionReject, Reason: "not me", Nonce: "z", TS: now, Mode: "totp", Round: 2}
	if code, _ := post(t, url, e.sealedBody(t, r, site, rej)); code != 200 {
		t.Fatalf("reject: %d", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, _ := r.Wait(ctx)
	if got.Action != ActionReject || got.Reason != "not me" {
		t.Errorf("got %+v", got)
	}
}

func TestStatusAndCORS(t *testing.T) {
	e := setup(t)
	r := e.srv.NewRoundFor(site, "login", 1)
	r.SetStatus(StateNextRound, "check DingTalk")
	resp, err := http.Get(e.base + "/" + r.Token + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var st Status
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.State != StateNextRound || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("status=%+v headers=%v", st, resp.Header)
	}
	for _, p := range []string{"/", "/nope/status", "/" + r.Token, "/" + r.Token + "/x"} {
		resp, _ := http.Get(e.base + p)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s: want 404 got %d", p, resp.StatusCode)
		}
	}
}

// The tunnel is only needed until the page has read the final state, so reading it by polling must tell the owner,
// exactly once, and an in-progress state must not.
func TestFinalStateReadNotifiesOnceAndOnlyWhenFinal(t *testing.T) {
	e := setup(t)
	r := e.srv.NewRoundFor(site, "login", 1)
	calls := 0
	r.OnFinalRead(func() { calls++ })
	get := func() {
		resp, err := http.Get(e.base + "/" + r.Token + "/status")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	get() // waiting
	r.SetStatus(StateWorking, "")
	get()
	r.SetStatus(StateNextRound, "")
	get()
	if calls != 0 {
		t.Fatalf("callback ran %d times for states that are not final", calls)
	}
	r.SetStatus(StateDone, "")
	get()
	get()
	if calls != 1 {
		t.Fatalf("callback ran %d times for a final state read twice, want exactly 1", calls)
	}
	for _, st := range []string{StateFailed, StateRejected} {
		r2 := e.srv.NewRoundFor(site, "login", 1)
		n := 0
		r2.OnFinalRead(func() { n++ })
		r2.SetStatus(st, "x")
		resp, _ := http.Get(e.base + "/" + r2.Token + "/status")
		resp.Body.Close()
		if n != 1 {
			t.Errorf("%s is a final state: callback ran %d times", st, n)
		}
	}
}

func newRound(t *testing.T, e *env, mode string, n int) (*Round, string) {
	t.Helper()
	r := e.srv.NewRoundFor(site, mode, n)
	return r, fmt.Sprintf("%s/%s/submit?mode=%s&round=%d", e.base, r.Token, mode, n)
}

func okSub(mode string, round int, nonce string) Submission {
	return Submission{Action: ActionSubmit, Fields: map[string]string{"username": "u", "password": "p"}, Nonce: nonce, TS: time.Now().Unix(), Mode: mode, Round: round}
}

// Every round has its own random one-shot password, and the page learns it only through the link.
func TestEveryRoundHasItsOwnOneShotPassword(t *testing.T) {
	e := setup(t)
	a, b := e.srv.NewRoundFor(site, "login", 1), e.srv.NewRoundFor(site, "login", 2)
	if len(a.Password()) != seal.PasswordSize || len(b.Password()) != seal.PasswordSize {
		t.Fatalf("password sizes %d, %d; want %d", len(a.Password()), len(b.Password()), seal.PasswordSize)
	}
	if bytes.Equal(a.Password(), b.Password()) {
		t.Fatal("two rounds share a password")
	}
}

// A submission that is only OpenPGP-encrypted, as the previous protocol sent it, is refused: accepting it would let a
// stale page, or an attacker who skips the seal, undo the extra layer silently.
func TestAnUnsealedSubmissionIsRefused(t *testing.T) {
	e := setup(t)
	r, url := newRound(t, e, "login", 1)
	code, body := post(t, url, e.encrypt(t, okSub("login", 1, "u1")))
	if code != 400 {
		t.Fatalf("an unsealed submission got %d, want 400: %s", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.Wait(ctx); err == nil {
		t.Fatal("the unsealed submission was delivered to the login flow")
	}
}

// Sealed under another round's password (or any wrong password): refused, and the answer must not say which part
// failed.
func TestASealUnderTheWrongPasswordIsRefusedWithoutSayingWhy(t *testing.T) {
	e := setup(t)
	r1, url1 := newRound(t, e, "login", 1)
	r2, _ := newRound(t, e, "login", 2)
	sub := okSub("login", 1, "w1")
	plain, _ := json.Marshal(sub)
	sealed, _ := seal.Seal(r2.Password(), seal.Context{Site: site, Mode: "login", Round: 1, Nonce: "w1"}, plain) // wrong password
	code, body := post(t, url1, e.encryptRaw(t, mustJSON(t, Envelope{Sealed: sealed, Nonce: "w1"})))
	if code != 400 {
		t.Fatalf("got %d, want 400", code)
	}
	if strings.Contains(body, "password") || strings.Contains(body, "tag") || strings.Contains(body, "GCM") {
		t.Errorf("the answer reveals why the seal failed: %s", body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r1.Wait(ctx); err == nil {
		t.Fatal("a seal under the wrong password was delivered")
	}
}

// A sealed value is bound to its round: captured from one round and posted to another (even one that has the same
// password, which cannot happen, so here by lying about the site) it does not open.
func TestASealCannotBeReplayedIntoAnotherRoundOrSite(t *testing.T) {
	e := setup(t)
	r, url := newRound(t, e, "login", 1)
	sub := okSub("login", 1, "rp1")
	plain, _ := json.Marshal(sub)
	for name, c := range map[string]seal.Context{
		"another site":  {Site: "evil.example", Mode: "login", Round: 1, Nonce: "rp1"},
		"another mode":  {Site: site, Mode: "totp", Round: 1, Nonce: "rp1"},
		"another round": {Site: site, Mode: "login", Round: 2, Nonce: "rp1"},
	} {
		sealed, _ := seal.Seal(r.Password(), c, plain)
		if code, _ := post(t, url, e.encryptRaw(t, mustJSON(t, Envelope{Sealed: sealed, Nonce: "rp1"}))); code != 400 {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
	// the envelope's nonce is part of what is sealed: swapping it for another is detected too
	sealed, _ := seal.Seal(r.Password(), seal.Context{Site: site, Mode: "login", Round: 1, Nonce: "rp1"}, plain)
	if code, _ := post(t, url, e.encryptRaw(t, mustJSON(t, Envelope{Sealed: sealed, Nonce: "rp-OTHER"}))); code != 400 {
		t.Errorf("a swapped envelope nonce: got %d, want 400", code)
	}
}

// Failed attempts must not burn the round: after wrong guesses the right submission still works, so a hostile
// request cannot lock the person out; and the password is wiped once the round has been used.
func TestAfterBadAttemptsTheRightSealStillWorksAndThePasswordIsWipedAfterUse(t *testing.T) {
	e := setup(t)
	r, url := newRound(t, e, "login", 1)
	for i := 0; i < 3; i++ {
		post(t, url, e.encrypt(t, okSub("login", 1, fmt.Sprintf("bad%d", i))))
	}
	if code, body := post(t, url, e.sealedBody(t, r, site, okSub("login", 1, "good"))); code != 200 {
		t.Fatalf("the right submission after bad ones: %d %s", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := r.Wait(ctx)
	if err != nil || got.Fields["password"] != "p" {
		t.Fatalf("wait: %+v %v", got, err)
	}
	for _, b := range r.Password() {
		if b != 0 {
			t.Fatal("the one-shot password was not wiped after the round was used")
		}
	}
}

// ---- second factor (a long-period TOTP code) ----

// fixedFactor stands in for the TOTP: it offers the codes the server may try, and records what it was asked.
type fixedFactor struct {
	codes    []string
	digits   int
	calls    int
	from, to time.Time
}

func (f *fixedFactor) Window(from, to time.Time) []string {
	f.calls++
	f.from, f.to = from, to
	return f.codes
}
func (f *fixedFactor) Digits() int { return f.digits }

func (e *env) factorBody(t *testing.T, r *Round, factor string, sub Submission) []byte {
	t.Helper()
	plain, _ := json.Marshal(sub)
	sealed, err := seal.SealWithFactor(r.Password(), factor, seal.Context{Site: site, Mode: sub.Mode, Round: sub.Round, Nonce: sub.Nonce}, plain)
	if err != nil {
		t.Fatal(err)
	}
	return e.encryptRaw(t, mustJSON(t, Envelope{Sealed: sealed, Nonce: sub.Nonce}))
}

func TestWithAFactorTheRightCodeIsAccepted(t *testing.T) {
	e := setup(t)
	e.srv.SetFactor(&fixedFactor{codes: []string{"12345678"}, digits: 8})
	r, url := newRound(t, e, "login", 1)
	if code, body := post(t, url, e.factorBody(t, r, "12345678", okSub("login", 1, "f1"))); code != 200 {
		t.Fatalf("the right code: %d %s", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := r.Wait(ctx); err != nil || got.Fields["password"] != "p" {
		t.Fatalf("wait: %+v %v", got, err)
	}
}

// Near a window boundary the previous window's code is a candidate: any candidate may be the right one.
func TestWithAFactorTheNeighbouringWindowsCodeIsAccepted(t *testing.T) {
	e := setup(t)
	e.srv.SetFactor(&fixedFactor{codes: []string{"22222222", "11111111"}, digits: 8})
	r, url := newRound(t, e, "login", 1)
	if code, body := post(t, url, e.factorBody(t, r, "11111111", okSub("login", 1, "f2"))); code != 200 {
		t.Fatalf("the second candidate: %d %s", code, body)
	}
}

func TestWithAFactorAWrongCodeIsRefusedWithoutSayingWhich(t *testing.T) {
	e := setup(t)
	e.srv.SetFactor(&fixedFactor{codes: []string{"12345678"}, digits: 8})
	r, url := newRound(t, e, "login", 1)
	code, body := post(t, url, e.factorBody(t, r, "00000000", okSub("login", 1, "f3")))
	if code != 400 || strings.Contains(strings.ToLower(body), "code") || strings.Contains(body, "totp") {
		t.Fatalf("a wrong code: %d %q; the answer must not tell a wrong code from any other failure", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.Wait(ctx); err == nil {
		t.Fatal("a submission with a wrong code was delivered")
	}
	// the round is not burned: the right code still works afterwards
	if code, _ := post(t, url, e.factorBody(t, r, "12345678", okSub("login", 1, "f3b"))); code != 200 {
		t.Fatalf("the right code after a wrong one: %d", code)
	}
}

// Turning the factor on must not leave a way around it: a seal without the factor, however valid, is refused.
func TestWithAFactorRequiredAPlainSealIsRefused(t *testing.T) {
	e := setup(t)
	e.srv.SetFactor(&fixedFactor{codes: []string{"12345678"}, digits: 8})
	r, url := newRound(t, e, "login", 1)
	if code, _ := post(t, url, e.sealedBody(t, r, site, okSub("login", 1, "f4"))); code != 400 {
		t.Fatalf("a plain seal while a factor is required: %d, want 400", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.Wait(ctx); err == nil {
		t.Fatal("a plain seal was delivered although a factor is required")
	}
}

// And the other way round: without a factor configured, a v2 seal is not accepted (the sides must agree).
func TestWithoutAFactorAFactorSealIsRefused(t *testing.T) {
	e := setup(t)
	r, url := newRound(t, e, "login", 1)
	if code, _ := post(t, url, e.factorBody(t, r, "12345678", okSub("login", 1, "f5"))); code != 400 {
		t.Fatalf("a factor seal while none is configured: %d, want 400", code)
	}
}

// A factor seal is bound to its round like a plain one.
func TestAFactorSealCannotBeReplayedIntoAnotherRound(t *testing.T) {
	e := setup(t)
	e.srv.SetFactor(&fixedFactor{codes: []string{"12345678"}, digits: 8})
	r1, _ := newRound(t, e, "login", 1)
	_, url2 := newRound(t, e, "login", 2)
	body := e.factorBody(t, r1, "12345678", okSub("login", 1, "f6")) // sealed for round 1 under round 1's password
	if code, _ := post(t, url2, body); code != 400 {
		t.Fatalf("a factor seal replayed into another round: %d", code)
	}
}

// The code length is announced to the page (so it can check what the person typed), and only when a factor is set.
func TestTheServerAnnouncesTheFactorDigits(t *testing.T) {
	e := setup(t)
	if d := e.srv.FactorDigits(); d != 0 {
		t.Errorf("no factor configured but digits = %d", d)
	}
	e.srv.SetFactor(&fixedFactor{codes: []string{"x"}, digits: 8})
	if d := e.srv.FactorDigits(); d != 8 {
		t.Errorf("digits = %d, want 8", d)
	}
}

// The codes to try are those of every window between the moment the link was made (the person read the code some time
// after that, but never before) and now, so a code read just before a window ended still works when the submission
// arrives in the next one. The round records when its link was made.
func TestTheServerAsksForTheCodesBetweenTheLinkAndNow(t *testing.T) {
	e := setup(t)
	f := &fixedFactor{codes: []string{"12345678"}, digits: 8}
	e.srv.SetFactor(f)
	made := time.Now().Add(-90 * time.Second)
	e.srv.now = func() time.Time { return made.Add(90 * time.Second) }
	r := e.srv.NewRoundAt(site, "login", 1, made)
	url := fmt.Sprintf("%s/%s/submit?mode=login&round=1", e.base, r.Token)
	if code, body := post(t, url, e.factorBody(t, r, "12345678", Submission{Action: ActionSubmit, Fields: map[string]string{"username": "u", "password": "p"}, Nonce: "sp1", TS: e.srv.now().Unix(), Mode: "login", Round: 1})); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if !f.from.Equal(made) {
		t.Errorf("the span starts at %v, want when the link was made (%v)", f.from, made)
	}
	if !f.to.Equal(e.srv.now()) {
		t.Errorf("the span ends at %v, want now (%v)", f.to, e.srv.now())
	}
}
