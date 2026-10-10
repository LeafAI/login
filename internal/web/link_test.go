package web

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/login/internal/seal"
)

func baseRound() Round {
	return Round{
		Site: "gitlab.corp.example", Mode: "login", N: 1,
		APIBase:     "https://abc.lhr.life/0123456789abcdef0123456789abcdef",
		PublicKey:   []byte("public-key-bytes"),
		Fingerprint: strings.Repeat("AB", 20),
		Password:    bytes.Repeat([]byte{0x44}, 32),
	}
}

func fragment(t *testing.T, link string) url.Values {
	t.Helper()
	i := strings.Index(link, "#")
	if i < 0 {
		t.Fatalf("no fragment in %q", link)
	}
	v, err := url.ParseQuery(link[i+1:])
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Without a link code the link is the plain v2 link: nothing changes for people who have not switched the feature on.
func TestPlainLinkHasItsParametersInTheClear(t *testing.T) {
	v := fragment(t, Link("https://page.example/", baseRound()))
	for _, k := range []string{"v", "site", "mode", "round", "u", "k", "f", "s"} {
		if v.Get(k) == "" {
			t.Errorf("the plain link lacks %q", k)
		}
	}
	if v.Get("e") != "" || v.Get("c") != "" {
		t.Errorf("a plain link carries encrypted-parameter fields: %v", v)
	}
	if v.Get("v") != LinkVersion {
		t.Errorf("version %q", v.Get("v"))
	}
}

// With a link code, the DingTalk message holds neither the site, nor the tunnel address, nor the one-shot password.
func TestEncryptedLinkRevealsNoneOfTheSecretParameters(t *testing.T) {
	r := baseRound()
	r.LinkCodes = []string{"11111111", "22222222"}
	r.LinkDigits = 8
	link := Link("https://page.example/", r)
	v := fragment(t, link)
	for _, k := range []string{"site", "u", "s"} {
		if v.Get(k) != "" {
			t.Errorf("the encrypted link still carries %q in the clear", k)
		}
	}
	for _, leak := range []string{"gitlab", "corp.example", "lhr.life", "abc.lhr", "0123456789abcdef", "https%3A%2F%2Fabc"} {
		if strings.Contains(link, leak) {
			t.Errorf("the link contains %q", leak)
		}
	}
	// what stays in the clear is exactly what the person must be able to check before typing the code
	for _, k := range []string{"v", "mode", "round", "k", "f", "e", "c"} {
		if v.Get(k) == "" {
			t.Errorf("the encrypted link lacks %q", k)
		}
	}
	if v.Get("c") != "8" {
		t.Errorf("the link must say how many digits the unlock code has, got %q", v.Get("c"))
	}
}

// And what is hidden can be recovered with the code, by the reference implementation the page mirrors.
func TestEncryptedLinkOpensWithTheCode(t *testing.T) {
	r := baseRound()
	r.LinkCodes = []string{"11111111", "22222222"}
	r.LinkDigits = 8
	v := fragment(t, Link("https://page.example/", r))
	c := seal.LinkContext{Fingerprint: v.Get("f"), Mode: v.Get("mode"), Round: 1}
	for _, code := range r.LinkCodes {
		p, err := seal.OpenLink(code, c, v.Get("e"))
		if err != nil || p.Site != BoundSite(r.Site) || p.API != r.APIBase || !bytes.Equal(p.Password, r.Password) {
			t.Fatalf("code %s: %+v %v", code, p, err)
		}
	}
	if _, err := seal.OpenLink("00000000", c, v.Get("e")); err == nil {
		t.Error("a wrong code opened the parameters")
	}
}

// The unlock code and the sealing code are different things and appear as different parameters.
func TestBothCodeLengthsCanBeAnnounced(t *testing.T) {
	r := baseRound()
	r.LinkCodes, r.LinkDigits, r.FactorDigits = []string{"11111111"}, 8, 6
	v := fragment(t, Link("https://page.example/", r))
	if v.Get("c") != "8" || v.Get("t") != "6" {
		t.Errorf("c=%q t=%q, want 8 and 6", v.Get("c"), v.Get("t"))
	}
}

// A link that was asked to be encrypted but cannot be (no candidate codes, a bad round) must not silently become a
// plain link: the person would believe the parameters are hidden.
func TestLinkRefusesToFallBackToPlainWhenEncryptionFails(t *testing.T) {
	r := baseRound()
	r.LinkDigits = 8 // asked for, but no codes to encrypt with
	if _, err := LinkChecked("https://page.example/", r); err == nil {
		t.Fatal("encryption was requested without codes and the link was built anyway")
	}
	r.LinkCodes = []string{"11111111"}
	r.Password = []byte("short")
	if _, err := LinkChecked("https://page.example/", r); err == nil {
		t.Fatal("a link with a bad one-shot password was built")
	}
}
