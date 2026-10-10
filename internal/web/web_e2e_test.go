package web_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/api"
	"github.com/LeafAI/login/internal/browsertest"
	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/web"
)

// drive runs the real page in headless Chromium against a real round API and returns what the Go
// side received.
func drive(t *testing.T, mode string, fields []web.Field, action, values, reason string) (browsertest.Result, api.Submission, error) {
	t.Helper()
	browsertest.Require(t)
	k, err := keyring.NewPool(t.TempDir(), 8, time.Hour).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(k)
	port, err := srv.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	round := srv.NewRound(mode, 1)
	pub, _ := k.PublicKeyBinary()
	dir := t.TempDir()
	if err := web.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	link := web.Link("file://"+dir+"/index.html", web.Round{
		Site: "gitlab.example", Mode: mode, N: 1, APIBase: fmt.Sprintf("http://127.0.0.1:%d/%s", port, round.Token),
		PublicKey: pub, Fingerprint: k.Fingerprint(), Fields: fields,
	})

	// Act as the Go side: wait for the submission, then report success like the flow does.
	subCh := make(chan api.Submission, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s, err := round.Wait(ctx); err == nil {
			round.SetStatus(api.StateDone, "ok")
			subCh <- s
		}
	}()
	res := browsertest.Drive(t, dir, browsertest.Fragment(link), action, values, reason)
	select {
	case s := <-subCh:
		return res, s, nil
	case <-time.After(2 * time.Second):
		return res, api.Submission{}, fmt.Errorf("no submission received")
	}
}

func TestBrowserLoginSubmit(t *testing.T) {
	res, sub, err := drive(t, "login", nil, "submit", `{"username":"alice","password":"s3cr3t!"}`, "")
	if err != nil {
		t.Fatalf("%v (page said %+v)", err, res)
	}
	if sub.Action != api.ActionSubmit || sub.Fields["username"] != "alice" || sub.Fields["password"] != "s3cr3t!" {
		t.Errorf("submission %+v", sub)
	}
	if res.HashAfter != "" {
		t.Errorf("fragment not cleared from address bar: %q", res.HashAfter)
	}
	if len(res.Errors) > 0 {
		t.Errorf("page errors: %v", res.Errors)
	}
}

func TestBrowserTOTPAndCustom(t *testing.T) {
	_, sub, err := drive(t, "totp", nil, "submit", `{"code":"123456"}`, "")
	if err != nil || sub.Fields["code"] != "123456" {
		t.Fatalf("totp: %+v %v", sub, err)
	}
	fields := []web.Field{{Name: "captcha", Label: "Captcha"}, {Name: "pin", Label: "PIN", Secret: true}}
	_, sub, err = drive(t, "custom", fields, "submit", `{"captcha":"abcd","pin":"9"}`, "")
	if err != nil || sub.Fields["captcha"] != "abcd" || sub.Fields["pin"] != "9" {
		t.Fatalf("custom: %+v %v", sub, err)
	}
}

func TestBrowserReject(t *testing.T) {
	_, sub, err := drive(t, "login", nil, "reject", ``, "I did not ask for this")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Action != api.ActionReject || sub.Reason != "I did not ask for this" || len(sub.Fields) != 0 {
		t.Errorf("reject %+v", sub)
	}
}

func TestBrowserRefusesMismatchedKey(t *testing.T) {
	// A provider-substituted key (fingerprint differs from the one in the link) must be refused.
	browsertest.Require(t)
	k, _ := keyring.NewPool(t.TempDir(), 8, time.Hour).Acquire()
	other, _ := keyring.NewPool(t.TempDir(), 8, time.Hour).Acquire()
	pub, _ := other.PublicKeyBinary()
	dir := t.TempDir()
	web.WriteTo(dir)
	link := web.Link("file://"+dir+"/index.html", web.Round{Mode: "login", N: 1, APIBase: "http://127.0.0.1:1/tok", PublicKey: pub, Fingerprint: k.Fingerprint()})
	res := browsertest.Drive(t, dir, browsertest.Fragment(link), "mismatch", "", "")
	if !res.MainHidden || res.Msg == "" {
		t.Errorf("page did not refuse: %+v", res)
	}
}
