package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

var ctx = Context{Site: "gitlab.corp.example", Mode: "login", Round: 1, Nonce: "n-1"}

func mustPassword(t *testing.T) []byte {
	t.Helper()
	p, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoundTrip(t *testing.T) {
	pw := mustPassword(t)
	plain := []byte(`{"username":"alice","password":"p@ss"}`)
	sealed, err := Seal(pw, ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(pw, ctx, sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestPasswordIsRandomAndFullStrength(t *testing.T) {
	a, b := mustPassword(t), mustPassword(t)
	if len(a) != 32 {
		t.Fatalf("password is %d bytes, want 32 (256 bits)", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two one-shot passwords were equal")
	}
}

// A fresh random IV per seal: the same plaintext under the same key must not produce the same ciphertext, or an
// observer learns when a value repeats, and GCM would break if an IV were ever reused.
func TestEverySealUsesAFreshIV(t *testing.T) {
	pw := mustPassword(t)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s, err := Seal(pw, ctx, []byte("same plaintext"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[s] {
			t.Fatal("two seals of the same plaintext were identical: the IV was reused")
		}
		seen[s] = true
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	sealed, _ := Seal(mustPassword(t), ctx, []byte("secret"))
	if _, err := Open(mustPassword(t), ctx, sealed); err == nil {
		t.Fatal("a different one-shot password opened the seal")
	}
}

// The context is bound in twice (key derivation and AAD): a seal made for one site, step or round cannot be replayed
// into another, even by someone holding the right password.
func TestSealIsBoundToItsContext(t *testing.T) {
	pw := mustPassword(t)
	sealed, _ := Seal(pw, ctx, []byte("secret"))
	for name, c := range map[string]Context{
		"site":  {Site: "other.example", Mode: ctx.Mode, Round: ctx.Round, Nonce: ctx.Nonce},
		"mode":  {Site: ctx.Site, Mode: "totp", Round: ctx.Round, Nonce: ctx.Nonce},
		"round": {Site: ctx.Site, Mode: ctx.Mode, Round: 2, Nonce: ctx.Nonce},
		"nonce": {Site: ctx.Site, Mode: ctx.Mode, Round: ctx.Round, Nonce: "n-2"},
	} {
		if _, err := Open(pw, c, sealed); err == nil {
			t.Errorf("a seal for another %s was accepted", name)
		}
	}
}

// GCM authenticates: flipping any bit anywhere, or cutting the message, must fail rather than yield garbage.
func TestTamperingIsDetected(t *testing.T) {
	pw := mustPassword(t)
	sealed, _ := Seal(pw, ctx, []byte("secret value"))
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, Prefix))
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		bad := append([]byte{}, raw...)
		bad[i] ^= 0x01
		if _, err := Open(pw, ctx, Prefix+base64.RawURLEncoding.EncodeToString(bad)); err == nil {
			t.Fatalf("a flipped bit at byte %d of %d went unnoticed", i, len(raw))
		}
	}
	for _, n := range []int{0, 5, ivSize, ivSize + 8, len(raw) - 1} {
		if _, err := Open(pw, ctx, Prefix+base64.RawURLEncoding.EncodeToString(raw[:n])); err == nil {
			t.Errorf("a message cut to %d bytes was accepted", n)
		}
	}
}

func TestMalformedInputIsRefusedNotPanicked(t *testing.T) {
	pw := mustPassword(t)
	for name, in := range map[string]string{
		"empty":        "",
		"no prefix":    "AAAA",
		"bad base64":   Prefix + "***",
		"only prefix":  Prefix,
		"wrong prefix": "v9." + base64.RawURLEncoding.EncodeToString(make([]byte, 40)),
	} {
		if _, err := Open(pw, ctx, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Open(nil, ctx, "v1.x"); err == nil {
		t.Error("an empty password was accepted")
	}
	if _, err := Open([]byte("short"), ctx, "v1.x"); err == nil {
		t.Error("a short password was accepted")
	}
	if _, err := Seal([]byte("short"), ctx, []byte("x")); err == nil {
		t.Error("sealing with a short password was allowed")
	}
	// Exactly 256 bits is required, not "at least something": a weak password must not be usable, and a password
	// of the wrong length is a sign that the two sides disagree about the protocol.
	for _, n := range []int{1, 15, 16, 24, 31, 33, 64} {
		if _, err := Seal(make([]byte, n), ctx, []byte("x")); err == nil {
			t.Errorf("sealing with a %d-byte password was allowed", n)
		}
		if _, err := Open(make([]byte, n), ctx, Prefix+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
			t.Errorf("opening with a %d-byte password was allowed", n)
		}
	}
}

// The wire format must be exactly what a browser's WebCrypto produces, so the page and the server agree: this test
// builds the seal by hand from the documented steps (HKDF-SHA256, AES-256-GCM, 12-byte IV, AAD) and the server must
// open it.
func TestOpensASealBuiltFromTheDocumentedSteps(t *testing.T) {
	pw := bytes.Repeat([]byte{7}, 32)
	key := deriveKey(pw, ctx)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	rand.Read(iv)
	ct := gcm.Seal(nil, iv, []byte("hand made"), aad(ctx))
	msg := Prefix + base64.RawURLEncoding.EncodeToString(append(iv, ct...))
	got, err := Open(pw, ctx, msg)
	if err != nil || string(got) != "hand made" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if len(key) != 32 {
		t.Errorf("derived key is %d bytes, want 32 (AES-256)", len(key))
	}
}

// Different contexts must give different keys, or the binding would rest on the AAD alone.
func TestDifferentContextsDeriveDifferentKeys(t *testing.T) {
	pw := bytes.Repeat([]byte{9}, 32)
	a := deriveKey(pw, ctx)
	b := deriveKey(pw, Context{Site: ctx.Site, Mode: ctx.Mode, Round: 2, Nonce: ctx.Nonce})
	if bytes.Equal(a, b) {
		t.Fatal("two rounds derived the same key")
	}
	// the derived key is not the password itself
	if bytes.Equal(a, pw) {
		t.Fatal("the key is the raw password")
	}
}

func TestWipeClearsThePassword(t *testing.T) {
	pw := mustPassword(t)
	Wipe(pw)
	for _, b := range pw {
		if b != 0 {
			t.Fatal("password not wiped")
		}
	}
}

// Each binding must work on its own, so that losing one (a refactor of the key derivation, or of the additional
// data) is caught and does not hide behind the other.
func TestContextIsBoundByTheAdditionalDataAloneAndByTheKeyAlone(t *testing.T) {
	pw := bytes.Repeat([]byte{5}, 32)
	other := Context{Site: ctx.Site, Mode: ctx.Mode, Round: ctx.Round, Nonce: "n-OTHER"}
	// Only the nonce is not part of the key derivation, so a different nonce is bound by the additional data alone.
	if !bytes.Equal(deriveKey(pw, ctx), deriveKey(pw, other)) {
		t.Fatal("test setup: the nonce is expected not to affect the derived key")
	}
	sealed, _ := Seal(pw, ctx, []byte("x"))
	if _, err := Open(pw, other, sealed); err == nil {
		t.Fatal("the additional data does not bind the nonce")
	}
	// Site, mode and round are bound by the key: with the additional data made equal they still fail.
	for name, c := range map[string]Context{
		"site":  {Site: "x.example", Mode: ctx.Mode, Round: ctx.Round, Nonce: ctx.Nonce},
		"mode":  {Site: ctx.Site, Mode: "totp", Round: ctx.Round, Nonce: ctx.Nonce},
		"round": {Site: ctx.Site, Mode: ctx.Mode, Round: 9, Nonce: ctx.Nonce},
	} {
		if bytes.Equal(deriveKey(pw, ctx), deriveKey(pw, c)) {
			t.Errorf("the derived key does not depend on the %s", name)
		}
	}
}

// A reused IV breaks GCM completely. Sealing must read it from a random source every time, which is checked here
// by counting: two seals under the same key never share an IV.
func TestIVsAreNeverRepeatedUnderOneKey(t *testing.T) {
	pw := bytes.Repeat([]byte{3}, 32)
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		s, _ := Seal(pw, ctx, []byte("x"))
		raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
		iv := string(raw[:ivSize])
		if seen[iv] {
			t.Fatalf("IV repeated after %d seals", i)
		}
		seen[iv] = true
	}
}

// ---- second factor: a code (for example a long-period TOTP) that is combined with the one-shot password ----

var factorCtx = Context{Site: "gitlab.corp.example", Mode: "login", Round: 1, Nonce: "n-1"}

func TestFactorRoundTrip(t *testing.T) {
	pw := mustPassword(t)
	sealed, err := SealWithFactor(pw, "12345678", factorCtx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, PrefixFactor) {
		t.Fatalf("a seal with a factor must say so in its prefix, got %.8q", sealed)
	}
	got, err := OpenWithFactor(pw, []string{"12345678"}, factorCtx, sealed)
	if err != nil || string(got) != "secret" {
		t.Fatalf("OpenWithFactor = %q, %v", got, err)
	}
}

// The factor is a real second secret: the right one-shot password alone, or the right code alone, does not open it.
func TestAFactorSealNeedsBothTheCodeAndThePassword(t *testing.T) {
	pw := mustPassword(t)
	sealed, _ := SealWithFactor(pw, "12345678", factorCtx, []byte("secret"))
	if _, err := OpenWithFactor(pw, []string{"87654321"}, factorCtx, sealed); err == nil {
		t.Error("a wrong code opened the seal")
	}
	if _, err := OpenWithFactor(mustPassword(t), []string{"12345678"}, factorCtx, sealed); err == nil {
		t.Error("a wrong one-shot password opened the seal")
	}
	if _, err := OpenWithFactor(pw, nil, factorCtx, sealed); err == nil {
		t.Error("no code opened the seal")
	}
	if _, err := Open(pw, factorCtx, sealed); err == nil {
		t.Error("a seal with a factor opened as a plain seal: the factor can be skipped")
	}
}

// Several candidate codes (the neighbouring window near a boundary) are tried, and the right one may be any of them.
func TestTheRightCandidateMayBeAnyOfSeveral(t *testing.T) {
	pw := mustPassword(t)
	sealed, _ := SealWithFactor(pw, "22222222", factorCtx, []byte("x"))
	for _, cands := range [][]string{{"22222222"}, {"11111111", "22222222"}, {"22222222", "33333333"}} {
		if _, err := OpenWithFactor(pw, cands, factorCtx, sealed); err != nil {
			t.Errorf("candidates %v: %v", cands, err)
		}
	}
	if _, err := OpenWithFactor(pw, []string{"11111111", "33333333"}, factorCtx, sealed); err == nil {
		t.Error("no candidate was right but it opened")
	}
}

// When a factor is required, a plain seal is refused: switching the factor on must not leave a way around it.
func TestAPlainSealIsRefusedWhenAFactorIsRequired(t *testing.T) {
	pw := mustPassword(t)
	plain, _ := Seal(pw, factorCtx, []byte("secret"))
	if _, err := OpenWithFactor(pw, []string{"12345678"}, factorCtx, plain); err == nil {
		t.Fatal("a seal without the factor was accepted while a factor is required")
	}
}

// The factor is stretched with PBKDF2 and salted with the one-shot password, so that a guess costs real work and the
// work cannot be shared between rounds. The cost is pinned: lowering it silently would cheapen every brute force.
func TestTheFactorIsStretched(t *testing.T) {
	if FactorIterations < 100000 {
		t.Fatalf("PBKDF2 iterations = %d, too few to slow a guess of a short code", FactorIterations)
	}
	pw := bytes.Repeat([]byte{1}, 32)
	other := bytes.Repeat([]byte{2}, 32)
	a := stretch("12345678", pw)
	if len(a) != 32 {
		t.Fatalf("stretched factor is %d bytes", len(a))
	}
	if bytes.Equal(a, stretch("12345678", other)) {
		t.Error("the salt (the one-shot password) does not affect the stretched factor: one table would serve every round")
	}
	if bytes.Equal(a, stretch("12345679", pw)) {
		t.Error("different codes gave the same stretched factor")
	}
}

// Byte-exact vectors. The browser derives the same bytes with WebCrypto (PBKDF2-SHA256 then HKDF-SHA256), and a Go
// seal and a browser seal must open each other, so these values are fixed here and the same values are asserted in the
// browser test. If either side changes the derivation, one of the two tests fails.
func TestFixedVectorsForTheDerivation(t *testing.T) {
	pw := bytes.Repeat([]byte{0x11}, 32)
	if got := hex.EncodeToString(stretch("12345678", pw)); got != VectorStretched {
		t.Errorf("stretched factor = %s\nwant              %s", got, VectorStretched)
	}
	if got := hex.EncodeToString(deriveKeyWithFactor(pw, "12345678", factorCtx)); got != VectorKey {
		t.Errorf("key with factor = %s\nwant            %s", got, VectorKey)
	}
	if got := hex.EncodeToString(deriveKey(pw, factorCtx)); got != VectorPlainKey {
		t.Errorf("plain key = %s\nwant       %s", got, VectorPlainKey)
	}
}

// A seal built by hand from the documented steps (the way a second implementation would) opens.
func TestOpensAFactorSealBuiltFromTheDocumentedSteps(t *testing.T) {
	pw := bytes.Repeat([]byte{0x22}, 32)
	key := deriveKeyWithFactor(pw, "00000042", factorCtx)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	iv := bytes.Repeat([]byte{9}, 12)
	ct := gcm.Seal(nil, iv, []byte("by hand"), aadFactor(factorCtx)) // the v2 label, not the v1 one
	msg := PrefixFactor + base64.RawURLEncoding.EncodeToString(append(iv, ct...))
	got, err := OpenWithFactor(pw, []string{"00000042"}, factorCtx, msg)
	if err != nil || string(got) != "by hand" {
		t.Fatalf("OpenWithFactor = %q, %v", got, err)
	}
}

func TestFactorIsRefusedWhenEmptyOrOversized(t *testing.T) {
	pw := mustPassword(t)
	for _, f := range []string{"", strings.Repeat("9", 65)} {
		if _, err := SealWithFactor(pw, f, factorCtx, []byte("x")); err == nil {
			t.Errorf("a factor of length %d was allowed", len(f))
		}
	}
}

// A sealed value of the plain format must not open under the factor path, even with a "right" code: the prefix decides
// which derivation is used, and the factor path must never accept a v1 value (that would be a way around the factor).
func TestTheFactorPathRefusesAPlainPrefix(t *testing.T) {
	pw := mustPassword(t)
	withFactor, _ := SealWithFactor(pw, "12345678", factorCtx, []byte("secret"))
	relabelled := Prefix + strings.TrimPrefix(withFactor, PrefixFactor) // same bytes, v1 prefix
	if _, err := OpenWithFactor(pw, []string{"12345678"}, factorCtx, relabelled); err == nil {
		t.Fatal("OpenWithFactor accepted a value with the plain prefix")
	}
	if _, err := Open(pw, factorCtx, relabelled); err == nil {
		t.Fatal("a factor seal relabelled as plain opened as plain")
	}
	if _, err := OpenWithFactor(pw, []string{"12345678"}, factorCtx, Prefix+"AAAA"); err == nil {
		t.Fatal("garbage with the plain prefix was accepted by the factor path")
	}
}

// The nonce is bound into the factor seal by the additional data alone (it is not part of key derivation), so a value
// must not open for another nonce.
func TestAFactorSealIsBoundToItsNonce(t *testing.T) {
	pw := mustPassword(t)
	sealed, _ := SealWithFactor(pw, "12345678", factorCtx, []byte("secret"))
	other := factorCtx
	other.Nonce = "n-OTHER"
	if _, err := OpenWithFactor(pw, []string{"12345678"}, other, sealed); err == nil {
		t.Fatal("a factor seal opened for another nonce")
	}
	for name, c := range map[string]Context{
		"site":  {Site: "x.example", Mode: factorCtx.Mode, Round: factorCtx.Round, Nonce: factorCtx.Nonce},
		"mode":  {Site: factorCtx.Site, Mode: "totp", Round: factorCtx.Round, Nonce: factorCtx.Nonce},
		"round": {Site: factorCtx.Site, Mode: factorCtx.Mode, Round: 9, Nonce: factorCtx.Nonce},
	} {
		if _, err := OpenWithFactor(pw, []string{"12345678"}, c, sealed); err == nil {
			t.Errorf("a factor seal opened for another %s", name)
		}
	}
}

// The key must depend on BOTH the one-shot password and the stretched factor: changing only the password, with the
// code fixed, must change the key (and the other way round), or one of the two factors is being ignored.
func TestTheKeyDependsOnBothSecrets(t *testing.T) {
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	base := deriveKeyWithFactor(a, "11111111", factorCtx)
	if bytes.Equal(base, deriveKeyWithFactor(b, "11111111", factorCtx)) {
		t.Error("the key ignores the one-shot password")
	}
	if bytes.Equal(base, deriveKeyWithFactor(a, "22222222", factorCtx)) {
		t.Error("the key ignores the code")
	}
	// with the salt held equal the stretched factor alone would still differ per password: check the combination is
	// not merely the stretched value (a key from the code alone would be the same under a different password)
	if bytes.Equal(deriveKeyWithFactor(a, "11111111", factorCtx), stretch("11111111", a)) {
		t.Error("the key is just the stretched code")
	}
}

// Defence in depth: even if the prefix check were bypassed, a plain (v1) seal forced under the v2 prefix cannot open on
// the factor path, because the two formats use different labels, so different keys and different additional data.
func TestAPlainSealForcedUnderTheFactorPrefixStillDoesNotOpen(t *testing.T) {
	pw := mustPassword(t)
	v1, _ := Seal(pw, factorCtx, []byte("secret"))
	forced := PrefixFactor + strings.TrimPrefix(v1, Prefix)
	for _, code := range []string{"12345678", "00000000"} {
		if _, err := OpenWithFactor(pw, []string{code}, factorCtx, forced); err == nil {
			t.Fatalf("a v1 seal forced under the v2 prefix opened with code %q", code)
		}
	}
}
