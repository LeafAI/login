package seal

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var lc = LinkContext{Fingerprint: strings.Repeat("AB", 20), Mode: "login", Round: 1}

var sample = LinkParams{Site: "gitlab.corp.example", API: "https://abc.lhr.life/0123456789abcdef0123456789abcdef", Password: bytes.Repeat([]byte{0x33}, 32)}

func TestLinkRoundTrip(t *testing.T) {
	enc, err := SealLink([]string{"11111111", "22222222"}, lc, sample)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenLink("11111111", lc, enc)
	if err != nil || got.Site != sample.Site || got.API != sample.API || !bytes.Equal(got.Password, sample.Password) {
		t.Fatalf("OpenLink = %+v, %v", got, err)
	}
	// the code of the other window opens it too
	if got, err := OpenLink("22222222", lc, enc); err != nil || got.Site != sample.Site {
		t.Fatalf("the second window's code: %+v %v", got, err)
	}
}

// The point of the layer: what is sent to DingTalk does not contain the site, the tunnel address or the one-shot
// password, in any recognisable form.
func TestTheEncryptedLinkHidesItsParameters(t *testing.T) {
	enc, _ := SealLink([]string{"11111111"}, lc, sample)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(enc, LinkPrefix))
	for _, needle := range []string{sample.Site, "lhr.life", "0123456789abcdef", string(sample.Password), "gitlab", "https://"} {
		if bytes.Contains(raw, []byte(needle)) || strings.Contains(enc, needle) {
			t.Errorf("the encrypted parameters contain %q", needle)
		}
	}
}

func TestAWrongLinkCodeDoesNotOpen(t *testing.T) {
	enc, _ := SealLink([]string{"11111111", "22222222"}, lc, sample)
	for _, c := range []string{"00000000", "11111112", "", "1111111", "111111111"} {
		if _, err := OpenLink(c, lc, enc); err == nil {
			t.Errorf("the code %q opened the link", c)
		}
	}
}

// Bound to the key and the step: a parameter blob cut out of one link and pasted into another does not open there.
func TestLinkParametersAreBoundToTheirKeyAndStep(t *testing.T) {
	enc, _ := SealLink([]string{"11111111"}, lc, sample)
	for name, c := range map[string]LinkContext{
		"fingerprint": {Fingerprint: strings.Repeat("CD", 20), Mode: lc.Mode, Round: lc.Round},
		"mode":        {Fingerprint: lc.Fingerprint, Mode: "totp", Round: lc.Round},
		"round":       {Fingerprint: lc.Fingerprint, Mode: lc.Mode, Round: 2},
	} {
		if _, err := OpenLink("11111111", c, enc); err == nil {
			t.Errorf("the parameters opened for another %s", name)
		}
	}
}

func TestLinkTamperingIsDetected(t *testing.T) {
	enc, _ := SealLink([]string{"11111111", "22222222"}, lc, sample)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(enc, LinkPrefix))
	// One run of the key stretch costs real time (that is its purpose), so flip one byte in each structural part rather
	// than every byte: the slot count, each slot's IV / ciphertext / tag, and the body's IV / ciphertext / tag.
	body := 1 + 2*slotSize
	// each position is opened with the code whose slot it belongs to (slots are independent: damage to another code's
	// slot does not matter to this one, which is the point of having one per code)
	type spot struct {
		at   int
		code string
	}
	positions := map[string]spot{
		"slot count":        {0, "22222222"},
		"slot 1 IV":         {1, "11111111"},
		"slot 1 ciphertext": {1 + ivSize, "11111111"},
		"slot 1 tag":        {1 + slotSize - 1, "11111111"},
		"slot 2 IV":         {1 + slotSize, "22222222"},
		"slot 2 ciphertext": {1 + slotSize + ivSize, "22222222"},
		"slot 2 tag":        {1 + 2*slotSize - 1, "22222222"},
		"body IV":           {body, "22222222"},
		"body ciphertext":   {body + ivSize, "22222222"},
		"body tag":          {len(raw) - 1, "22222222"},
	}
	for name, sp := range positions {
		bad := append([]byte{}, raw...)
		bad[sp.at] ^= 0x01
		if _, err := OpenLink(sp.code, lc, LinkPrefix+base64.RawURLEncoding.EncodeToString(bad)); err == nil {
			t.Errorf("a flipped bit in the %s (byte %d of %d) went unnoticed", name, sp.at, len(raw))
		}
	}
	// damage to one code's slot leaves the other code's slot working
	bad := append([]byte{}, raw...)
	bad[1] ^= 0x01
	if _, err := OpenLink("22222222", lc, LinkPrefix+base64.RawURLEncoding.EncodeToString(bad)); err != nil {
		t.Errorf("a damaged slot 1 must not stop slot 2 from opening: %v", err)
	}
	// and a truncated or extended body
	for _, n := range []int{len(raw) - 1, len(raw) - 16, body + ivSize} {
		if _, err := OpenLink("22222222", lc, LinkPrefix+base64.RawURLEncoding.EncodeToString(raw[:n])); err == nil {
			t.Errorf("a message cut to %d bytes was accepted", n)
		}
	}
	if _, err := OpenLink("22222222", lc, LinkPrefix+base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), 0))); err == nil {
		t.Error("a message with an extra byte was accepted")
	}
}

func TestMalformedLinkBlobsAreRefused(t *testing.T) {
	for name, in := range map[string]string{
		"empty": "", "no prefix": "AAAA", "prefix only": LinkPrefix, "bad base64": LinkPrefix + "***",
		"short": LinkPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 10)),
	} {
		if _, err := OpenLink("11111111", lc, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The link key is fresh for every link: two links with the same parameters share nothing recognisable.
func TestEveryLinkUsesAFreshKeyAndIV(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		enc, err := SealLink([]string{"11111111"}, lc, sample)
		if err != nil {
			t.Fatal(err)
		}
		if seen[enc] {
			t.Fatal("two links with the same parameters were identical")
		}
		seen[enc] = true
	}
}

// One wrapped key per candidate code: the link has as many "slots" as there are codes, and opening tries them.
func TestEveryCandidateCodeGetsItsOwnSlot(t *testing.T) {
	one, _ := SealLink([]string{"11111111"}, lc, sample)
	three, _ := SealLink([]string{"11111111", "22222222", "33333333"}, lc, sample)
	if len(three) <= len(one) {
		t.Errorf("three candidates (%d chars) must take more room than one (%d chars)", len(three), len(one))
	}
	for _, c := range []string{"11111111", "22222222", "33333333"} {
		if _, err := OpenLink(c, lc, three); err != nil {
			t.Errorf("the code %s did not open it: %v", c, err)
		}
	}
	if _, err := SealLink(nil, lc, sample); err == nil {
		t.Error("a link with no candidate codes was allowed: nobody could open it")
	}
	many := make([]string, MaxLinkSlots+1)
	for i := range many {
		many[i] = strings.Repeat(string(rune('1'+i%9)), 8)
	}
	if _, err := SealLink(many, lc, sample); err == nil {
		t.Errorf("more than %d slots was allowed: the link would grow without bound", MaxLinkSlots)
	}
}

func TestLinkParamsAreValidatedAtSealTime(t *testing.T) {
	for name, p := range map[string]LinkParams{
		"short password": {Site: "a", API: "https://x", Password: []byte("short")},
		"empty api":      {Site: "a", API: "", Password: bytes.Repeat([]byte{1}, 32)},
		"empty site":     {Site: "", API: "https://x", Password: bytes.Repeat([]byte{1}, 32)},
	} {
		if _, err := SealLink([]string{"11111111"}, lc, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Fixed vectors for the browser: the page must derive exactly these. Computed by an independent implementation
// (Python hashlib.pbkdf2_hmac + a hand-written HKDF), see internal/seal/vectors.go.
func TestFixedVectorsForTheLinkDerivation(t *testing.T) {
	if got := hexOf(stretchLink("12345678", lc)); got != VectorLinkStretched {
		t.Errorf("stretched = %s\nwant       %s", got, VectorLinkStretched)
	}
	if got := hexOf(linkSlotKey("12345678", lc)); got != VectorLinkSlotKey {
		t.Errorf("slot key = %s\nwant       %s", got, VectorLinkSlotKey)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// The link key must be random per link. The IVs differ every time anyway, so ciphertexts differing proves nothing about
// the key: the key itself is recovered here, by opening the first slot with the code, and two links must give different
// keys. A fixed key would let anyone who learns it once read every later link's parameters.
func TestTheLinkKeyIsDifferentForEveryLink(t *testing.T) {
	recover := func() []byte {
		enc, err := SealLink([]string{"11111111"}, lc, sample)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(enc, LinkPrefix))
		gcm, _ := gcmFor(linkSlotKey("11111111", lc))
		slot := raw[1 : 1+slotSize]
		key, err := gcm.Open(nil, slot[:ivSize], slot[ivSize:], slotAAD(lc))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	a, b := recover(), recover()
	if len(a) != 32 {
		t.Fatalf("the link key is %d bytes, want 32 (AES-256)", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two links used the same link key")
	}
	if bytes.Equal(a, make([]byte, 32)) {
		t.Fatal("the link key is all zeros")
	}
}
