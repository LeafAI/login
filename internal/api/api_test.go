package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/LeafAI/login/internal/keyring"
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

func TestSubmitAndReplay(t *testing.T) {
	e := setup(t)
	r := e.srv.NewRound("login", 1)
	url := e.base + "/" + r.Token + "/submit?mode=login&round=1"
	sub := Submission{Action: ActionSubmit, Fields: map[string]string{"username": "u", "password": "p"}, Nonce: "n1", TS: time.Now().Unix(), Mode: "login", Round: 1}

	if code, _ := post(t, url, e.encrypt(t, sub)); code != 200 {
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
	if code, _ := post(t, url, e.encrypt(t, sub)); code != 409 {
		t.Errorf("second submit: want 409 got %d", code)
	}
	// replay of the same nonce on another round is refused
	r2 := e.srv.NewRound("login", 2)
	sub.Round, sub.Nonce = 2, "n1"
	if code, _ := post(t, e.base+"/"+r2.Token+"/submit?mode=login&round=2", e.encrypt(t, sub)); code != 400 {
		t.Errorf("replayed nonce: want 400 got %d", code)
	}
}

func TestRejectAndValidation(t *testing.T) {
	e := setup(t)
	r := e.srv.NewRound("totp", 2)
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
		if code, _ := post(t, url, e.encrypt(t, s)); code != 400 {
			t.Errorf("bad[%d]: want 400 got %d", i, code)
		}
	}
	if code, _ := post(t, url, []byte("not pgp")); code != 400 {
		t.Errorf("garbage: %d", code)
	}
	rej := Submission{Action: ActionReject, Reason: "not me", Nonce: "z", TS: now, Mode: "totp", Round: 2}
	if code, _ := post(t, url, e.encrypt(t, rej)); code != 200 {
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
	r := e.srv.NewRound("login", 1)
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
	r := e.srv.NewRound("login", 1)
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
		r2 := e.srv.NewRound("login", 1)
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
