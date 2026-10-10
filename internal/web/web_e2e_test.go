package web_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/api"
	"github.com/LeafAI/login/internal/browsertest"
	"github.com/LeafAI/login/internal/keyring"
	"github.com/LeafAI/login/internal/seal"
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
	return newRigWithFactor(t, mode, fields, nil)
}

// newRigWithFactor is newRig for a server that requires a second factor (a code the person types).
func newRigWithFactor(t *testing.T, mode string, fields []web.Field, f api.Factor) *rig {
	return newRigFull(t, mode, fields, f, nil, 0)
}

// newRigFull also encrypts the link parameters under the unlock codes (the long-period TOTP), if given.
func newRigFull(t *testing.T, mode string, fields []web.Field, f api.Factor, linkCodes []string, linkDigits int) *rig {
	t.Helper()
	browsertest.Require(t)
	k, err := keyring.NewPool(t.TempDir(), 8, time.Hour).Acquire()
	if err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(k)
	if f != nil {
		srv.SetFactor(f)
	}
	port, err := srv.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	round := srv.NewRoundFor("gitlab.example", mode, 1)
	pub, _ := k.PublicKeyBinary()
	dir := t.TempDir()
	if err := web.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	link := web.Link("file://"+dir+"/index.html", web.Round{
		Site: "gitlab.example", Mode: mode, N: 1, APIBase: fmt.Sprintf("http://127.0.0.1:%d/%s", port, round.Token),
		PublicKey: pub, Fingerprint: k.Fingerprint(), Password: round.Password(), FactorDigits: srv.FactorDigits(),
		LinkCodes: linkCodes, LinkDigits: linkDigits, Fields: fields,
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
		"previous link version":        func(v url.Values) { v.Set("v", "1") }, // the single-layer protocol: refused, never downgraded to
		"unknown link version":         func(v url.Values) { v.Set("v", "3") },
		"missing seal password":        func(v url.Values) { v.Del("s") },
		"empty seal password":          func(v url.Values) { v.Set("s", "") },
		"seal password too short":      func(v url.Values) { v.Set("s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") },
		"seal password too long":       func(v url.Values) { v.Set("s", strings.Repeat("A", 60)) },
		"seal password not base64url":  func(v url.Values) { v.Set("s", "!!!!"+strings.Repeat("A", 40)) },
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

// The seal binds the site name, and the page keeps only the first 200 characters of it. A host name can be longer, so
// both sides must bind the same cut value, or a perfectly valid login would be refused. Checked in a real browser with
// a site name past the limit.
func TestBrowserSealsWithAVeryLongSiteName(t *testing.T) {
	browsertest.Require(t)
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".example.com"
	if len(long) <= web.MaxSiteLen {
		t.Fatalf("test setup: the name must be longer than %d, got %d", web.MaxSiteLen, len(long))
	}
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
	round := srv.NewRoundFor(web.BoundSite(long), "login", 1)
	pub, _ := k.PublicKeyBinary()
	dir := t.TempDir()
	if err := web.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	link := web.Link("file://"+dir+"/index.html", web.Round{
		Site: long, Mode: "login", N: 1, APIBase: fmt.Sprintf("http://127.0.0.1:%d/%s", port, round.Token),
		PublicKey: pub, Fingerprint: k.Fingerprint(), Password: round.Password(),
	})
	r := &rig{t: t, dir: dir, round: round, frag: browsertest.Fragment(link), key: k}
	_, sub, err := r.drive(r.frag, "submit", `{"username":"alice","password":"p"}`, "")
	if err != nil || sub.Fields["username"] != "alice" {
		t.Fatalf("a long site name broke the seal: %+v %v", sub, err)
	}
}

// What leaves the browser is only ciphertext: the credential does not appear in the request body, and the body is
// an OpenPGP message whose plaintext is the envelope, not the credential. The request is captured on the wire.
func TestBrowserRequestCarriesNoPlaintextAndTheEnvelopeHidesTheCredential(t *testing.T) {
	r := newRig(t, "login", nil)
	res, sub, err := r.drive(r.frag, "submit", `{"username":"alice-unique","password":"s3cr3t-unique"}`, "")
	if err != nil || sub.Fields["password"] != "s3cr3t-unique" {
		t.Fatalf("%+v %v (page %+v)", sub, err, res)
	}
	for _, needle := range []string{"alice-unique", "s3cr3t-unique", `"sealed"`, "v1."} {
		if strings.Contains(res.RequestBody, needle) {
			t.Errorf("the request body contains %q in the clear", needle)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(res.RequestBody), "-----BEGIN PGP MESSAGE-----") {
		t.Errorf("the request body is not an OpenPGP message: %.60q", res.RequestBody)
	}
}

// openOnTheWire reads a request body captured from the page the way the server does, and returns the sealed value
// it carried (the OpenPGP layer decrypted with the round's key, the envelope parsed, the seal left closed).
func openOnTheWire(t *testing.T, r *rig, body string) api.Envelope {
	t.Helper()
	plain, err := r.key.Decrypt([]byte(body))
	if err != nil {
		t.Fatalf("the captured request is not an OpenPGP message for this key: %v", err)
	}
	var env api.Envelope
	if err := json.Unmarshal(plain, &env); err != nil || env.Sealed == "" {
		t.Fatalf("the OpenPGP layer does not carry an envelope: %v %q", err, plain)
	}
	return env
}

// A reused IV breaks AES-GCM, and the browser is where the IV is made. Two submissions of identical content, sealed
// under identical key material, must carry different IVs. The page is driven twice with the same link parameters
// (a new round each time would hide a fixed IV, because the key would differ; here the key material is identical).
func TestBrowserUsesAFreshIVForEverySeal(t *testing.T) {
	ivs := map[string]bool{}
	for i := 0; i < 4; i++ {
		r := newRig(t, "login", nil)
		res, _, err := r.drive(r.frag, "submit", `{"username":"alice","password":"p"}`, "")
		if err != nil {
			t.Fatalf("%v (%+v)", err, res)
		}
		env := openOnTheWire(t, r, res.RequestBody)
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env.Sealed, seal.Prefix))
		if err != nil || len(raw) < 12+16 {
			t.Fatalf("the sealed value is malformed: %q (%v)", env.Sealed, err)
		}
		iv := hex.EncodeToString(raw[:12])
		if ivs[iv] {
			t.Fatalf("the browser produced the IV %s twice", iv)
		}
		ivs[iv] = true
		if iv == strings.Repeat("0", 24) {
			t.Fatal("the browser used an all-zero IV")
		}
	}
}

// staticFactor offers fixed codes, like api's own test double.
type staticFactor struct {
	codes  []string
	digits int
}

func (f staticFactor) Window(from, to time.Time) []string { return f.codes }
func (f staticFactor) Digits() int                        { return f.digits }

// With a second factor the page asks for the code, checks its length, and seals with it; the server opens it with the
// code it computed itself. The code is typed in the page and never appears in the request.
func TestBrowserSealsWithTheSecondFactorAndTheServerOpensIt(t *testing.T) {
	r := newRigWithFactor(t, "login", nil, staticFactor{codes: []string{"12345678"}, digits: 8})
	res, sub, err := r.drive(r.frag, "submit", `{"username":"alice-unique","password":"s3cr3t-unique","factor":"12345678"}`, "")
	if err != nil || sub.Fields["password"] != "s3cr3t-unique" {
		t.Fatalf("%+v %v (page %+v)", sub, err, res)
	}
	if _, leaked := sub.Fields["factor"]; leaked {
		t.Errorf("the factor must not be part of the submitted fields: %+v", sub.Fields)
	}
	for _, needle := range []string{"12345678", "alice-unique", "s3cr3t-unique", "v2."} {
		if strings.Contains(res.RequestBody, needle) {
			t.Errorf("the request body contains %q in the clear", needle)
		}
	}
	env := openOnTheWire(t, r, res.RequestBody)
	if !strings.HasPrefix(env.Sealed, seal.PrefixFactor) {
		t.Errorf("with a factor the seal must use the v2 format, got %.6q", env.Sealed)
	}
}

// A wrong code produces a seal that the server cannot open: the page reports the refusal, and nothing is delivered.
func TestBrowserWithAWrongCodeIsRefusedByTheServer(t *testing.T) {
	r := newRigWithFactor(t, "login", nil, staticFactor{codes: []string{"12345678"}, digits: 8})
	res := browsertest.Drive(t, r.dir, r.frag, "submit", `{"username":"a","password":"b","factor":"00000000"}`, "")
	if !strings.Contains(res.Msg, "refused") && !strings.Contains(res.Msg, "failed") {
		t.Errorf("the page did not report the refusal: %q", res.Msg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if got, err := r.round.Wait(ctx); err == nil {
		t.Fatalf("a submission with a wrong code was delivered: %+v", got)
	}
}

// The page checks what the person typed before it does any work: a code of the wrong length or with letters is
// refused on the page, and nothing is sent.
func TestBrowserRefusesAMalformedCodeBeforeSending(t *testing.T) {
	// "too long" is not a case: the input field caps the length at the code's digits, so a longer paste is cut and the
	// page sees a code of the right length (which is then correct or wrong for the server to say).
	for name, code := range map[string]string{"too short": "1234567", "letters": "abcdefgh", "empty": "", "spaces": "1234 567"} {
		r := newRigWithFactor(t, "login", nil, staticFactor{codes: []string{"12345678"}, digits: 8})
		res := browsertest.Drive(t, r.dir, r.frag, "submit", fmt.Sprintf(`{"username":"a","password":"b","factor":%q}`, code), "")
		if res.RequestBody != "" {
			t.Errorf("%s: something was sent for a malformed code", name)
		}
	}
}

// Without a factor the page asks for nothing extra and keeps the plain format.
func TestBrowserWithoutAFactorShowsNoCodeField(t *testing.T) {
	r := newRig(t, "login", nil)
	res, _, err := r.drive(r.frag, "submit", `{"username":"alice","password":"p"}`, "")
	if err != nil {
		t.Fatalf("%v (%+v)", err, res)
	}
	if res.FactorShown {
		t.Error("the page asked for a code although no factor is configured")
	}
	if env := openOnTheWire(t, r, res.RequestBody); !strings.HasPrefix(env.Sealed, seal.Prefix) {
		t.Errorf("without a factor the seal must be v1, got %.6q", env.Sealed)
	}
}

// Link validation for the factor parameter: only 6, 7 or 8 digits.
func TestBrowserRefusesALinkWithABadFactorLength(t *testing.T) {
	r := newRigWithFactor(t, "login", nil, staticFactor{codes: []string{"12345678"}, digits: 8})
	for name, v := range map[string]string{"zero": "0", "five": "5", "nine": "9", "negative": "-8", "text": "eight", "trailing junk": "8abc", "huge": "99999999999"} {
		res := browsertest.Drive(t, r.dir, r.mutate(func(q url.Values) { q.Set("t", v) }), "refuse", "", "")
		if !res.MainHidden || strings.TrimSpace(res.Msg) == "" {
			t.Errorf("%s: the page did not refuse t=%q: %+v", name, v, res)
		}
	}
}

// Byte-exact interoperability: the keys the page derives from fixed inputs are the ones Go and Python derive.
func TestBrowserDerivesTheSameKeysAsGo(t *testing.T) {
	browsertest.Require(t)
	r := newRig(t, "login", nil)
	res := browsertest.Drive(t, r.dir, r.frag, "derive", `{"password":"`+strings.Repeat("11", 32)+`","factor":"12345678","site":"gitlab.corp.example","mode":"login","round":1}`, "")
	if res.Derived.Stretched != seal.VectorStretched || res.Derived.PlainKey != seal.VectorPlainKey || res.Derived.Key != seal.VectorKey {
		t.Fatalf("the page derived different keys than Go:\n got stretched %s\nwant stretched %s\n got plain %s\nwant plain %s\n got key %s\nwant key %s",
			res.Derived.Stretched, seal.VectorStretched, res.Derived.PlainKey, seal.VectorPlainKey, res.Derived.Key, seal.VectorKey)
	}
}

// ---- the unlock code: the link parameters are encrypted and the page needs the long-period code to read them ----

func unlockRig(t *testing.T) *rig {
	return newRigFull(t, "login", nil, nil, []string{"11111111", "22222222"}, 8)
}

// The page shows the key code first and asks for the unlock code; the form appears only after the right code.
func TestBrowserUnlocksTheLinkWithTheRightCodeAndSubmits(t *testing.T) {
	r := unlockRig(t)
	res, sub, err := r.drive(r.frag, "unlock-submit", `{"unlock":"22222222","username":"alice-unique","password":"s3cr3t-unique"}`, "")
	if err != nil || sub.Fields["password"] != "s3cr3t-unique" {
		t.Fatalf("%+v %v (page %+v)", sub, err, res)
	}
	for _, needle := range []string{"alice-unique", "s3cr3t-unique", "22222222"} {
		if strings.Contains(res.RequestBody, needle) {
			t.Errorf("the request body contains %q in the clear", needle)
		}
	}
	if res.HashAfter != "" {
		t.Errorf("the fragment (with the encrypted blob) was left in the address bar: %q", res.HashAfter)
	}
	if res.UnlockLeft != "" {
		t.Errorf("the unlock code is still in the page after unlocking: %q", res.UnlockLeft)
	}
}

// Before the code is typed nothing about the site or the tunnel is shown, and no form exists.
func TestBrowserShowsNothingSecretBeforeTheUnlockCode(t *testing.T) {
	r := unlockRig(t)
	res := browsertest.Drive(t, r.dir, r.frag, "locked", "", "")
	if !res.UnlockShown || res.FormShown {
		t.Fatalf("before the code the page must show the unlock box and no form: %+v", res)
	}
	for _, leak := range []string{"gitlab", "127.0.0.1", "corp.example"} {
		if strings.Contains(res.PageText, leak) {
			t.Errorf("the locked page shows %q", leak)
		}
	}
	// the key code is shown (the person compares it with DingTalk before typing anything), and it is the right one
	fp := r.key.Fingerprint()
	if want := strings.Join([]string{fp[len(fp)-16 : len(fp)-12], fp[len(fp)-12 : len(fp)-8], fp[len(fp)-8 : len(fp)-4], fp[len(fp)-4:]}, " "); !strings.Contains(res.PageText, want) {
		t.Errorf("the locked page does not show the key code %q", want)
	}
}

// While the page is locked it does not know where to talk to, and it must not make any network request at all, not even
// while the person types a wrong code: a locked page that sent something would be a page that can leak what it was
// handed. (The page's Content-Security-Policy cannot be closed completely for this: policies intersect, so closing it
// would also stop the page from talking to the tunnel after unlocking. The guarantee is that no code path sends.)
func TestBrowserSendsNothingWhileLocked(t *testing.T) {
	r := unlockRig(t)
	res := browsertest.Drive(t, r.dir, r.frag, "locked", "", "")
	if len(res.RequestsWhileLocked) > 0 {
		t.Errorf("the locked page made requests: %v", res.RequestsWhileLocked)
	}
	if !res.UnlockShown || res.FormShown {
		t.Errorf("the page should still be locked after a wrong code: %+v", res)
	}
}

// A wrong code unlocks nothing and says so without telling why; the person can try again with the right one.
func TestBrowserWithAWrongUnlockCodeStaysLockedAndCanRetry(t *testing.T) {
	r := unlockRig(t)
	res := browsertest.Drive(t, r.dir, r.frag, "unlock-wrong-then-right", `{"wrong":"00000000","right":"11111111"}`, "")
	if !strings.Contains(res.Msg, "could not be unlocked") {
		t.Errorf("the page did not report the failed unlock: %q", res.Msg)
	}
	if strings.Contains(strings.ToLower(res.Msg), "tamper") || strings.Contains(strings.ToLower(res.Msg), "forged") {
		t.Errorf("the message guesses at a cause it cannot know: %q", res.Msg)
	}
	if !res.FormShown {
		t.Errorf("after the wrong code and then the right one the form must be shown: %+v", res)
	}
}

// A damaged or foreign blob cannot be told apart from a wrong code: the page says the same thing.
func TestBrowserTreatsADamagedBlobLikeAWrongCode(t *testing.T) {
	r := unlockRig(t)
	frag := r.mutate(func(v url.Values) { e := v.Get("e"); v.Set("e", e[:len(e)-4]+"AAAA") })
	res := browsertest.Drive(t, r.dir, frag, "unlock-submit-expect-fail", `{"unlock":"11111111"}`, "")
	if !strings.Contains(res.Msg, "could not be unlocked") || res.FormShown {
		t.Fatalf("a damaged blob: %+v", res)
	}
}

// The unlock code is checked for length before any work is done.
func TestBrowserRefusesAMalformedUnlockCode(t *testing.T) {
	r := unlockRig(t)
	for name, code := range map[string]string{"short": "1111111", "letters": "abcdefgh", "empty": ""} {
		res := browsertest.Drive(t, r.dir, r.frag, "unlock-expect-refused", fmt.Sprintf(`{"unlock":%q}`, code), "")
		if res.FormShown || !strings.Contains(res.Msg, "8-digit") {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

// Link validation for the new parameters: c is 6 to 8, e must be present with it, and the clear parameters must not
// be accepted alongside the encrypted ones (the page could otherwise be steered by a link that carries both).
func TestBrowserRefusesInconsistentEncryptedLinks(t *testing.T) {
	r := unlockRig(t)
	cases := map[string]func(url.Values){
		"c without e":         func(v url.Values) { v.Del("e") },
		"e without c":         func(v url.Values) { v.Del("c") },
		"c five":              func(v url.Values) { v.Set("c", "5") },
		"c nine":              func(v url.Values) { v.Set("c", "9") },
		"c text":              func(v url.Values) { v.Set("c", "eight") },
		"e wrong prefix":      func(v url.Values) { v.Set("e", "x9."+v.Get("e")[3:]) },
		"clear u beside e":    func(v url.Values) { v.Set("u", "http://127.0.0.1:1/tok") },
		"clear s beside e":    func(v url.Values) { v.Set("s", strings.Repeat("A", 43)) },
		"clear site beside e": func(v url.Values) { v.Set("site", "evil.example") },
	}
	for name, fn := range cases {
		res := browsertest.Drive(t, r.dir, r.mutate(fn), "refuse", "", "")
		if !res.MainHidden || strings.TrimSpace(res.Msg) == "" {
			t.Errorf("%s: the page did not refuse: %+v", name, res)
		}
	}
}

// Both factors together: the unlock code opens the link, the sealing code seals the credential.
func TestBrowserWithBothCodes(t *testing.T) {
	r := newRigFull(t, "login", nil, staticFactor{codes: []string{"87654321"}, digits: 8}, []string{"11111111"}, 8)
	res, sub, err := r.drive(r.frag, "unlock-submit", `{"unlock":"11111111","username":"alice","password":"s3cr3t","factor":"87654321"}`, "")
	if err != nil || sub.Fields["password"] != "s3cr3t" {
		t.Fatalf("%+v %v (page %+v)", sub, err, res)
	}
	env := openOnTheWire(t, r, res.RequestBody)
	if !strings.HasPrefix(env.Sealed, seal.PrefixFactor) {
		t.Errorf("with the sealing code the seal must be v2, got %.6q", env.Sealed)
	}
	for _, needle := range []string{"11111111", "87654321"} {
		if strings.Contains(res.RequestBody, needle) {
			t.Errorf("a code appears in the request in the clear: %q", needle)
		}
	}
}

// Byte-exact interoperability for the link layer: the page derives the same keys as Go and Python.
func TestBrowserDerivesTheSameLinkKeysAsGo(t *testing.T) {
	r := unlockRig(t)
	res := browsertest.Drive(t, r.dir, r.frag, "derive-link", `{"code":"12345678","fingerprint":"`+strings.Repeat("AB", 20)+`","mode":"login","round":1}`, "")
	if res.Derived.LinkStretched != seal.VectorLinkStretched || res.Derived.LinkSlotKey != seal.VectorLinkSlotKey {
		t.Fatalf("the page derived different link keys than Go:\n got stretched %s\nwant stretched %s\n got slot key %s\nwant slot key %s",
			res.Derived.LinkStretched, seal.VectorLinkStretched, res.Derived.LinkSlotKey, seal.VectorLinkSlotKey)
	}
}
