package configcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/totp"
)

var fixedNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// runAt is run with a fixed clock, so codes are predictable.
func runAt(t *testing.T, path, answers string, args ...string) result {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "login", "config.yaml")
	}
	var out, errb bytes.Buffer
	env := Env{Path: path, In: strings.NewReader(answers), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }}
	code := Run(args, env)
	return result{code, out.String(), errb.String(), path}
}

func secretOf(t *testing.T, cfgPath, name string) []byte {
	t.Helper()
	b, err := totp.LoadSecret(filepath.Join(filepath.Dir(cfgPath), "totp", name+".secret"))
	if err != nil {
		t.Fatalf("secret %s: %v", name, err)
	}
	return b
}

// init creates the secrets, turns the factors on, and shows each secret so it can be registered in an authenticator.
func TestTOTPInitCreatesBothFactors(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	if r.code != 0 {
		t.Fatalf("exit %d: %s%s", r.code, r.out, r.err)
	}
	link, seal := secretOf(t, r.path, "link"), secretOf(t, r.path, "seal")
	if string(link) == string(seal) {
		t.Fatal("the two factors share a secret")
	}
	c := load(t, r.path)
	if !c.Security.LinkTOTP.Enabled || !c.Security.SealTOTP.Enabled {
		t.Fatalf("the factors must be switched on: %+v", c.Security)
	}
	// each secret is shown (text form, and the otpauth URI with its period) so it can be registered
	for _, want := range []string{totp.FormatSecret(link), totp.FormatSecret(seal), "otpauth://totp/", "period=600", "period=30"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the output lacks %q:\n%s", want, r.out)
		}
	}
	// the files are private
	for _, f := range []string{"link", "seal"} {
		st, err := os.Stat(filepath.Join(filepath.Dir(r.path), "totp", f+".secret"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s secret: %v %v", f, st, err)
		}
	}
}

// Never replace a secret that has been registered: running init again must not lock anybody out.
func TestTOTPInitDoesNotReplaceExistingSecrets(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	before := secretOf(t, r.path, "link")
	r2 := runAt(t, r.path, "", "totp", "init")
	if r2.code == 0 {
		t.Fatalf("a second init succeeded:\n%s", r2.out)
	}
	if !strings.Contains(r2.err, "already") {
		t.Errorf("the refusal must say why: %q", r2.err)
	}
	if string(secretOf(t, r.path, "link")) != string(before) {
		t.Fatal("an existing secret was replaced")
	}
}

// `code` prints the code of the moment, for people whose authenticator cannot do the long period.
func TestTOTPCodePrintsTheCurrentCodes(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	link, seal := secretOf(t, r.path, "link"), secretOf(t, r.path, "seal")
	out := runAt(t, r.path, "", "totp", "code")
	if out.code != 0 {
		t.Fatalf("exit %d: %s", out.code, out.err)
	}
	wantLink := totp.Code(link, fixedNow, 10*time.Minute, 8)
	wantSeal := totp.Code(seal, fixedNow, 30*time.Second, 8)
	for _, want := range []string{wantLink, wantSeal} {
		if !strings.Contains(out.out, want) {
			t.Errorf("the output lacks the code %s:\n%s", want, out.out)
		}
	}
	// and says how long each is valid, so nobody types a code that is about to change
	if !strings.Contains(out.out, "valid for") {
		t.Errorf("the output should say how long each code is valid:\n%s", out.out)
	}
	// one factor at a time
	one := runAt(t, r.path, "", "totp", "code", "link")
	if !strings.Contains(one.out, wantLink) || strings.Contains(one.out, wantSeal) {
		t.Errorf("`code link` should print only the unlock code:\n%s", one.out)
	}
}

func TestTOTPStatusShowsSettingsButNeverTheSecretOrACode(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	link := secretOf(t, r.path, "link")
	st := runAt(t, r.path, "", "totp", "status")
	if st.code != 0 {
		t.Fatalf("%s", st.err)
	}
	for _, leak := range []string{totp.FormatSecret(link), totp.Code(link, fixedNow, 10*time.Minute, 8)} {
		if strings.Contains(st.out, leak) {
			t.Errorf("status leaks %q:\n%s", leak, st.out)
		}
	}
	for _, want := range []string{"unlock", "sealing", "10m0s", "30s", "8 digits"} {
		if !strings.Contains(st.out, want) {
			t.Errorf("status lacks %q:\n%s", want, st.out)
		}
	}
}

func TestTOTPStatusWhenNothingIsConfigured(t *testing.T) {
	st := runAt(t, "", "", "totp", "status")
	if st.code != 0 || !strings.Contains(st.out, "off") {
		t.Fatalf("%d %q %q", st.code, st.out, st.err)
	}
}

// off switches a factor off but keeps its secret: the person's authenticator entry stays valid for turning it back on.
func TestTOTPOffKeepsTheSecret(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	before := secretOf(t, r.path, "link")
	if off := runAt(t, r.path, "", "totp", "off", "link"); off.code != 0 {
		t.Fatalf("%s", off.err)
	}
	c := load(t, r.path)
	if c.Security.LinkTOTP.Enabled || !c.Security.SealTOTP.Enabled {
		t.Fatalf("only the unlock factor should be off: %+v", c.Security)
	}
	if string(secretOf(t, r.path, "link")) != string(before) {
		t.Fatal("switching a factor off removed its secret")
	}
	if on := runAt(t, r.path, "", "totp", "on", "link"); on.code != 0 || !load(t, r.path).Security.LinkTOTP.Enabled {
		t.Fatalf("on: %d %s", on.code, on.err)
	}
}

// Each factor can be set up on its own.
func TestTOTPInitOneFactor(t *testing.T) {
	r := runAt(t, "", "", "totp", "init", "seal")
	c := load(t, r.path)
	if c.Security.LinkTOTP.Enabled || !c.Security.SealTOTP.Enabled {
		t.Fatalf("only the sealing factor should be on: %+v", c.Security)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.path), "totp", "link.secret")); err == nil {
		t.Error("a secret was created for the factor that was not asked for")
	}
}

func TestTOTPUnknownFactorOrCommand(t *testing.T) {
	for _, args := range [][]string{{"totp"}, {"totp", "bogus"}, {"totp", "init", "nope"}, {"totp", "code", "nope"}, {"totp", "off"}} {
		if r := runAt(t, "", "", args...); r.code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
}

// `on` without a secret must refuse rather than switch on a factor that cannot work (the server would not start).
func TestTOTPOnWithoutASecretIsRefused(t *testing.T) {
	r := runAt(t, "", "", "totp", "on", "link")
	if r.code == 0 {
		t.Fatalf("a factor was switched on without a secret:\n%s", r.out)
	}
	if !strings.Contains(r.err, "init") {
		t.Errorf("the refusal should point at `totp init`: %q", r.err)
	}
}

// The command checks every secret before it creates any, so a refused init leaves nothing behind. This is only visible
// when the secret that exists comes LATER in the order than one that does not: then an implementation that checks as it
// goes would already have created the earlier one when it hits the later. (The unlock factor is handled first, so the
// sealing secret is the one that exists here.)
func TestTOTPInitIsAllOrNothing(t *testing.T) {
	r := runAt(t, "", "", "totp", "init", "seal") // only the sealing secret exists now
	linkFile := filepath.Join(filepath.Dir(r.path), "totp", "link.secret")
	if fileExists(linkFile) {
		t.Fatal("test setup: the unlock secret should not exist yet")
	}
	both := runAt(t, r.path, "", "totp", "init") // asks for both; the sealing one exists
	if both.code == 0 {
		t.Fatal("init succeeded although one of the secrets already exists")
	}
	if fileExists(linkFile) {
		t.Fatal("init made the unlock secret before noticing that the sealing secret exists: a half-done state")
	}
	if c := load(t, r.path); c.Security.LinkTOTP.Enabled {
		t.Fatal("the unlock factor was switched on by a refused init")
	}
}

// The secrets of the two factors are independent random values: made one after the other, never the same.
func TestTOTPInitMakesIndependentSecrets(t *testing.T) {
	for i := 0; i < 5; i++ {
		r := runAt(t, "", "", "totp", "init")
		if string(secretOf(t, r.path, "link")) == string(secretOf(t, r.path, "seal")) {
			t.Fatal("the two factors got the same secret")
		}
	}
}
