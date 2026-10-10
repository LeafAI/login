package web_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/api"
	"github.com/LeafAI/login/internal/browsertest"
	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/web"
)

// rig is a real round API plus a link to the real static page for it.
type rig struct {
	t     *testing.T
	dir   string
	round *api.Round
	frag  string // link fragment
	key   *keyring.Key
}

func newRig(t *testing.T, mode string, fields []web.Field) *rig {
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
	t.Cleanup(srv.Close)
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
	return &rig{t: t, dir: dir, round: round, frag: browsertest.Fragment(link), key: k}
}

// mutate rewrites parameters of the link fragment (to craft hostile links).
func (r *rig) mutate(fn func(url.Values)) string {
	v, err := url.ParseQuery(r.frag)
	if err != nil {
		r.t.Fatal(err)
	}
	fn(v)
	return v.Encode()
}

// answer reports success to the page once the Go side received a submission.
func (r *rig) answer() <-chan api.Submission {
	ch := make(chan api.Submission, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s, err := r.round.Wait(ctx); err == nil {
			r.round.SetStatus(api.StateDone, "ok")
			ch <- s
		}
	}()
	return ch
}

func (r *rig) drive(frag, action, values, reason string) (browsertest.Result, api.Submission, error) {
	r.t.Helper()
	sub := r.answer()
	res := browsertest.Drive(r.t, r.dir, frag, action, values, reason)
	select {
	case s := <-sub:
		return res, s, nil
	case <-time.After(2 * time.Second):
		return res, api.Submission{}, fmt.Errorf("no submission received")
	}
}

func TestBrowserLoginSubmit(t *testing.T) {
	r := newRig(t, "login", nil)
	res, sub, err := r.drive(r.frag, "submit", `{"username":"alice","password":"s3cr3t!"}`, "")
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
	if !strings.Contains(res.Title, "Sign in") {
		t.Errorf("document title %q", res.Title)
	}
	// the code shown to the human is the tail of the fingerprint, grouped like the DingTalk message
	fp := r.key.Fingerprint()
	if want := strings.Join([]string{fp[len(fp)-16 : len(fp)-12], fp[len(fp)-12 : len(fp)-8], fp[len(fp)-8 : len(fp)-4], fp[len(fp)-4:]}, " "); res.Code != want {
		t.Errorf("verification code %q, want %q", res.Code, want)
	}
	// password managers must not file credentials under this page's origin
	for _, ac := range res.Autocomplete {
		if ac != "off" {
			t.Errorf("autocomplete = %q, want off", ac)
		}
	}
}

func TestBrowserTOTPAndCustom(t *testing.T) {
	r := newRig(t, "totp", nil)
	res, sub, err := r.drive(r.frag, "submit", `{"code":"123456"}`, "")
	if err != nil || sub.Fields["code"] != "123456" {
		t.Fatalf("totp: %+v %v", sub, err)
	}
	if len(res.Autocomplete) != 1 || res.Autocomplete[0] != "one-time-code" {
		t.Errorf("totp autocomplete %v", res.Autocomplete)
	}
	r = newRig(t, "custom", []web.Field{{Name: "captcha", Label: "Captcha"}, {Name: "pin", Label: "PIN", Secret: true}})
	_, sub, err = r.drive(r.frag, "submit", `{"captcha":"abcd","pin":"9"}`, "")
	if err != nil || sub.Fields["captcha"] != "abcd" || sub.Fields["pin"] != "9" {
		t.Fatalf("custom: %+v %v", sub, err)
	}
}

func TestBrowserReject(t *testing.T) {
	r := newRig(t, "login", nil)
	_, sub, err := r.drive(r.frag, "reject", ``, "I did not ask for this")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Action != api.ActionReject || sub.Reason != "I did not ask for this" || len(sub.Fields) != 0 {
		t.Errorf("reject %+v", sub)
	}
}

// The verification code gate: Submit stays disabled until the human confirms the code, and again if unticked.
func TestBrowserSubmitNeedsVerification(t *testing.T) {
	r := newRig(t, "login", nil)
	res := browsertest.Drive(t, r.dir, r.frag, "probe", "", "")
	if !res.SubmitDisabledBefore || res.SubmitDisabledAfter || !res.SubmitDisabledUnticked {
		t.Errorf("gate: before=%v after=%v unticked=%v (want true,false,true)", res.SubmitDisabledBefore, res.SubmitDisabledAfter, res.SubmitDisabledUnticked)
	}
}

// Links are refused rather than interpreted when anything is off; the page then falls back to the paste box.
func TestBrowserRefusesHostileOrBrokenLinks(t *testing.T) {
	r := newRig(t, "login", nil)
	other := newRig(t, "login", nil) // a different key whose fingerprint does not match this link's `f`
	otherPub, _ := other.key.PublicKeyBinary()
	cases := map[string]func(url.Values){
		"userinfo hides the real host": func(v url.Values) { v.Set("u", "http://corp.example@127.0.0.1:1/tok") },
		"query in api address":         func(v url.Values) { v.Set("u", v.Get("u")+"?x=1") },
		"non-http scheme":              func(v url.Values) { v.Set("u", "ftp://127.0.0.1/tok") },
		"missing fingerprint":          func(v url.Values) { v.Del("f") },
		"short fingerprint":            func(v url.Values) { v.Set("f", "ABCD") },
		"round with trailing junk":     func(v url.Values) { v.Set("round", "1abc") },
		"round zero":                   func(v url.Values) { v.Set("round", "0") },
		"unknown mode":                 func(v url.Values) { v.Set("mode", "wipe") },
		"wrong version":                func(v url.Values) { v.Set("v", "2") },
		"key not matching fingerprint": func(v url.Values) { v.Set("k", browsertestB64(otherPub)) },
		"garbage key":                  func(v url.Values) { v.Set("k", "AAAA") },
	}
	for name, fn := range cases {
		res := browsertest.Drive(t, r.dir, r.mutate(fn), "refuse", "", "")
		if !res.MainHidden || strings.TrimSpace(res.Msg) == "" {
			t.Errorf("%s: page did not refuse: %+v", name, res)
		}
		if res.HashAfter != "" {
			t.Errorf("%s: fragment left in the address bar", name)
		}
	}
	// duplicate custom field names are refused as well
	c := newRig(t, "custom", []web.Field{{Name: "a", Label: "A"}, {Name: "a", Label: "A again"}})
	if res := browsertest.Drive(t, c.dir, c.frag, "refuse", "", ""); !res.MainHidden {
		t.Errorf("duplicate field names accepted: %+v", res)
	}
}

// Once a link is accepted, the page may only talk to the tunnel origin named in it.
func TestBrowserConnectionsAreLockedToTheTunnel(t *testing.T) {
	r := newRig(t, "login", nil)
	res := browsertest.Drive(t, r.dir, r.frag, "csp", "", "")
	if !res.Violated || !res.OtherBlocked {
		t.Errorf("a foreign origin was reachable: violated=%v blocked=%v (%+v)", res.Violated, res.OtherBlocked, res)
	}
}

// Regression: opening the reject box used to disable validation, so Submit then sent empty credentials.
func TestBrowserEmptySubmitSendsNothing(t *testing.T) {
	r := newRig(t, "login", nil)
	res, _, err := r.drive(r.frag, "emptysubmit", "", "")
	if err == nil {
		t.Fatal("an empty submission reached the server")
	}
	if !strings.Contains(res.Msg, "Please fill in") {
		t.Errorf("message %q", res.Msg)
	}
	for _, d := range res.FieldsDisabled {
		if d {
			t.Error("fields were disabled although nothing was sent")
		}
	}
}

const png1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func TestBrowserRendersCaptchaImageAndDropsHostileOnes(t *testing.T) {
	fields := []web.Field{
		{Name: "username", Label: "Username"},
		{Name: "verifyvalue", Label: "Captcha", Image: "data:image/png;base64," + png1x1},
		{Name: "other", Label: "Other", Image: "https://evil.example/track.png"},     // not a data: image: must be dropped
		{Name: "third", Label: "Third", Image: "data:image/svg+xml;base64,PHN2Zy8+"}, // svg is not allowed
	}
	r := newRig(t, "custom", fields)
	res, sub, err := r.drive(r.frag, "submit", `{"username":"alice","verifyvalue":"7","other":"x","third":"y"}`, "")
	if err != nil || sub.Fields["verifyvalue"] != "7" {
		t.Fatalf("submit: %+v %v", sub, err)
	}
	if len(res.Imgs) != 1 || res.Imgs[0].W != 1 || res.Imgs[0].Src != "data:image/png;base64," {
		t.Errorf("rendered images: %+v (want exactly the one data:image/png, loaded)", res.Imgs)
	}
	if len(res.Errors) > 0 {
		t.Errorf("page errors (CSP?): %v", res.Errors)
	}
}
