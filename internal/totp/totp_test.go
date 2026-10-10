package totp

import (
	"encoding/base32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors for HMAC-SHA1. The seed is the ASCII string "12345678901234567890", the period is
// 30 s and the codes have 8 digits. These are the only external ground truth: a code that disagrees with them is wrong
// whatever the rest of the tests say.
var rfcSeed = []byte("12345678901234567890")

func TestRFC6238AppendixBVectors(t *testing.T) {
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		got := Code(rfcSeed, time.Unix(v.unix, 0), 30*time.Second, 8)
		if got != v.code {
			t.Errorf("T=%d: code %s, want %s", v.unix, got, v.code)
		}
	}
}

// The same algorithm with a long period: the counter is floor(unix / period), so 8 hours is 28800 s. Checked against
// the RFC's own definition by computing the 30 s vector at the matching counter: counter 1 at period 30 is T=30..59,
// and counter 1 at period 28800 is T=28800..57599, both must give the same code for the same counter.
func TestLongPeriodUsesTheSameCounterRule(t *testing.T) {
	short := Code(rfcSeed, time.Unix(59, 0), 30*time.Second, 8)  // counter 1
	long := Code(rfcSeed, time.Unix(28800+5, 0), 8*time.Hour, 8) // counter 1
	if short != long {
		t.Errorf("counter 1 gave %s at 30 s and %s at 8 h; the period only scales the counter", short, long)
	}
	// inside one 8-hour window the code does not change, and it changes at the boundary
	a := Code(rfcSeed, time.Unix(28800, 0), 8*time.Hour, 8)
	b := Code(rfcSeed, time.Unix(57599, 0), 8*time.Hour, 8)
	c := Code(rfcSeed, time.Unix(57600, 0), 8*time.Hour, 8)
	if a != b {
		t.Errorf("the code changed inside one window: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("the code did not change at the window boundary")
	}
}

func TestDigits(t *testing.T) {
	for _, d := range []int{6, 7, 8} {
		got := Code(rfcSeed, time.Unix(59, 0), 30*time.Second, d)
		if len(got) != d {
			t.Errorf("%d digits: got %q", d, got)
		}
	}
	// leading zeros are kept: the 8-digit vector at 1111111109 is 07081804
	if got := Code(rfcSeed, time.Unix(1111111109, 0), 30*time.Second, 8); !strings.HasPrefix(got, "0") {
		t.Errorf("a leading zero was dropped: %q", got)
	}
}

func TestNewSecretIsRandomAndLongEnough(t *testing.T) {
	a, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSecret()
	if len(a) < 20 {
		t.Fatalf("secret is %d bytes, RFC 4226 asks for at least 160 bits", len(a))
	}
	if string(a) == string(b) {
		t.Fatal("two secrets were equal")
	}
}

func TestSecretTextRoundTripAndTolerance(t *testing.T) {
	s, _ := NewSecret()
	text := FormatSecret(s)
	if strings.ContainsAny(text, "=\n") {
		t.Errorf("the text form should be unpadded base32, got %q", text)
	}
	got, err := ParseSecret(text)
	if err != nil || string(got) != string(s) {
		t.Fatalf("round trip: %v", err)
	}
	// people paste secrets with spaces, lower case and padding; all must work
	spaced := strings.ToLower(strings.Join(chunks(text, 4), " ")) + "===="
	if got, err := ParseSecret(spaced); err != nil || string(got) != string(s) {
		t.Errorf("a spaced, lower-case, padded secret was refused: %v", err)
	}
	for _, bad := range []string{"", "!!!!", "ABC", strings.Repeat("A", 8)} {
		if _, err := ParseSecret(bad); err == nil {
			t.Errorf("%q was accepted as a secret", bad)
		}
	}
}

func chunks(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

// The otpauth URI is what an authenticator imports. The period must be in it, and the issuer/account are escaped.
func TestOTPAuthURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	u := URI(secret, "login gateway", "me@host", 8*time.Hour, 8)
	for _, want := range []string{
		"otpauth://totp/", "secret=" + strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "="),
		"period=28800", "digits=8", "algorithm=SHA1", "issuer=login%20gateway",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("URI lacks %q: %s", want, u)
		}
	}
}

func TestValidateInputs(t *testing.T) {
	if _, err := ParseSettings(8*time.Hour, 8); err != nil {
		t.Errorf("8 h / 8 digits refused: %v", err)
	}
	for name, c := range map[string]struct {
		p time.Duration
		d int
	}{"zero period": {0, 8}, "negative": {-time.Hour, 8}, "under 30s": {10 * time.Second, 8},
		"over a week": {8 * 24 * time.Hour, 8}, "5 digits": {time.Hour, 5}, "9 digits": {time.Hour, 9}} {
		if _, err := ParseSettings(c.p, c.d); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// ---- candidates for a span of time ----

// A code is read in one window and the submission arrives in a later one, so the server tries the codes of every window
// the span touches. With a 30 s period and a 90 s span that is up to four windows; with a long period it is one or two.
func TestCandidatesForASpan(t *testing.T) {
	p := 30 * time.Second
	at := time.Unix(1000*30+10, 0) // 10 s into window 1000
	// a span that stays inside one window: one candidate
	if got := CandidatesBetween(rfcSeed, at, at.Add(5*time.Second), p, 8); len(got) != 1 {
		t.Errorf("one window: %d candidates, want 1", len(got))
	}
	// a span covering windows 1000..1002: three candidates, in time order, no duplicates
	got := CandidatesBetween(rfcSeed, at, at.Add(50*time.Second), p, 8)
	want := []string{Code(rfcSeed, at, p, 8), Code(rfcSeed, at.Add(30*time.Second), p, 8), Code(rfcSeed, at.Add(50*time.Second), p, 8)}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("three windows: %v, want %v", got, want)
	}
	// the span is ordered either way round
	rev := CandidatesBetween(rfcSeed, at.Add(50*time.Second), at, p, 8)
	if len(rev) != 3 {
		t.Errorf("a reversed span gave %d candidates", len(rev))
	}
}

func TestCandidatesForASpanAreBounded(t *testing.T) {
	// a huge span must not become a huge guess space or an unbounded loop
	got := CandidatesBetween(rfcSeed, time.Unix(0, 0), time.Unix(0, 0).Add(1000*time.Hour), 30*time.Second, 8)
	if len(got) > MaxCandidates {
		t.Fatalf("%d candidates, the bound is %d", len(got), MaxCandidates)
	}
	if len(got) == 0 {
		t.Fatal("no candidates")
	}
}

// ---- secret storage ----

func TestSecretFileIsPrivateAndRoundTrips(t *testing.T) {
	path := t.TempDir() + "/sub/link.totp"
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSecret(path, s); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the secret file must be 0600, got %v (%v)", st.Mode(), err)
	}
	if dst, _ := os.Stat(filepath.Dir(path)); dst.Mode().Perm() != 0o700 {
		t.Errorf("the directory must be 0700, got %v", dst.Mode())
	}
	got, err := LoadSecret(path)
	if err != nil || string(got) != string(s) {
		t.Fatalf("round trip: %v", err)
	}
}

// Never overwrite a secret that people have already registered in their authenticator: that would lock them out.
func TestSaveSecretRefusesToOverwrite(t *testing.T) {
	path := t.TempDir() + "/a.totp"
	first, _ := NewSecret()
	if err := SaveSecret(path, first); err != nil {
		t.Fatal(err)
	}
	second, _ := NewSecret()
	if err := SaveSecret(path, second); err == nil {
		t.Fatal("an existing secret was overwritten")
	}
	got, _ := LoadSecret(path)
	if string(got) != string(first) {
		t.Fatal("the first secret was changed")
	}
}

func TestLoadSecretRefusesMissingBadAndExposedFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadSecret(dir + "/missing.totp"); err == nil {
		t.Error("a missing file was accepted")
	}
	bad := dir + "/bad.totp"
	os.WriteFile(bad, []byte("not base32 !!!\n"), 0o600)
	if _, err := LoadSecret(bad); err == nil {
		t.Error("a file that is not a secret was accepted")
	}
	open := dir + "/open.totp"
	s, _ := NewSecret()
	os.WriteFile(open, []byte(FormatSecret(s)+"\n"), 0o644)
	if _, err := LoadSecret(open); err == nil {
		t.Error("a secret readable by other users was accepted: refuse rather than use a secret that may be exposed")
	}
}

// ---- a Source is what the server and the CLI use ----

func TestSourceCandidatesAndCode(t *testing.T) {
	src := &Source{Secret: rfcSeed, Settings: Settings{Period: 30 * time.Second, Digits: 8}}
	at := time.Unix(59, 0)
	if got := src.Code(at); got != "94287082" {
		t.Errorf("Code = %s, want the RFC vector 94287082", got)
	}
	if src.Digits() != 8 {
		t.Errorf("Digits = %d", src.Digits())
	}
	if got := src.Window(at, at); len(got) != 1 || got[0] != "94287082" {
		t.Errorf("Window = %v", got)
	}
}

// Two windows can produce the same code (a 6-digit code repeats with probability 1e-6). The server must not try the same
// key twice. For the RFC test seed, windows 910737 and 910738 are a real example: both give 911617 (found by search).
func TestASpanNeverRepeatsACode(t *testing.T) {
	p := 30 * time.Second
	if hotp(rfcSeed, 910737, 6) != "911617" || hotp(rfcSeed, 910738, 6) != "911617" {
		t.Fatal("test setup: the known repeat is gone")
	}
	got := CandidatesBetween(rfcSeed, time.Unix(910737*30, 0), time.Unix(910738*30+5, 0), p, 6)
	if len(got) != 1 || got[0] != "911617" {
		t.Fatalf("two windows with the same code gave %v, want it once", got)
	}
}
