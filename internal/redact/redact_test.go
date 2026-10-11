package redact

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"
	"testing"
)

const placeholder = "[REDACTED]"

// variants lists the ways a server can hand a secret back to us. A scrubber that only knows the raw value is useless:
// echo endpoints, error pages and debug views all re-encode what they were sent.
func variants(secret string) map[string]string {
	b := []byte(secret)
	return map[string]string{
		"raw":             secret,
		"url-escaped":     url.QueryEscape(secret),
		"path-escaped":    url.PathEscape(secret),
		"double-escaped":  url.QueryEscape(url.QueryEscape(secret)),
		"html-escaped":    html.EscapeString(secret),
		"json-escaped":    strings.NewReplacer(`"`, `\"`, `\`, `\\`, "/", `\/`).Replace(secret),
		"json-unicode":    refJSONUnicode(secret),
		"base64-std":      base64.StdEncoding.EncodeToString(b),
		"base64-url":      base64.URLEncoding.EncodeToString(b),
		"base64-raw-std":  base64.RawStdEncoding.EncodeToString(b),
		"base64-raw-url":  base64.RawURLEncoding.EncodeToString(b),
		"hex":             hex.EncodeToString(b),
		"hex-upper":       strings.ToUpper(hex.EncodeToString(b)),
		"lower-case":      strings.ToLower(secret),
		"percent-all-hex": refPercentAll(secret),
	}
}

func refJSONUnicode(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(`\u00`)
		b.WriteString(hex.EncodeToString([]byte{byte(r)}))
	}
	return b.String()
}

func refPercentAll(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		b.WriteString("%")
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func TestEveryEncodingOfASecretIsRemoved(t *testing.T) {
	const secret = `sess=Ab/Cd+Ef"gh\ij&kl 9z`
	s := New([]string{secret})
	for name, v := range variants(secret) {
		for _, where := range []string{"body", "inside text", "json value"} {
			var in string
			switch where {
			case "body":
				in = v
			case "inside text":
				in = "before " + v + " after"
			case "json value":
				in = `{"echo":"` + v + `"}`
			}
			out, n := s.Text(in)
			if strings.Contains(out, v) {
				t.Errorf("%s (%s) survived: %q -> %q", name, where, in, out)
			}
			if n == 0 {
				t.Errorf("%s (%s): the replacement count must be reported", name, where)
			}
		}
	}
}

func TestLowerCaseVariantIsOnlyMatchedWhenItIsReallyDifferent(t *testing.T) {
	s := New([]string{"AbCdEfGhIjKl"})
	out, _ := s.Text("the value abcdefghijkl came back")
	if strings.Contains(out, "abcdefghijkl") {
		t.Errorf("a server that lower-cases the secret still leaks it: %q", out)
	}
}

func TestTextWithoutSecretsIsUntouchedAndCountsNothing(t *testing.T) {
	s := New([]string{"SECRET-VALUE-12345"})
	in := `{"ok":true,"items":[1,2,3],"name":"alice"}`
	out, n := s.Text(in)
	if out != in || n != 0 {
		t.Errorf("%q %d", out, n)
	}
}

func TestSeveralSecretsAndRepeatedOccurrences(t *testing.T) {
	s := New([]string{"first-secret-aaaa", "second-secret-bbbb"})
	out, n := s.Text("first-secret-aaaa, second-secret-bbbb, first-secret-aaaa")
	if strings.Contains(out, "secret-aaaa") || strings.Contains(out, "secret-bbbb") {
		t.Errorf("%q", out)
	}
	if n != 3 {
		t.Errorf("three occurrences: %d", n)
	}
	if strings.Count(out, placeholder) != 3 {
		t.Errorf("%q", out)
	}
}

// A longer secret that contains a shorter one must be replaced whole: replacing the short one first would leave the
// rest of the long secret behind.
func TestTheLongestSecretIsReplacedFirst(t *testing.T) {
	s := New([]string{"tokenvalue1234", "tokenvalue1234-and-more-secret-tail"})
	out, _ := s.Text("x tokenvalue1234-and-more-secret-tail y")
	if strings.Contains(out, "secret-tail") || strings.Contains(out, "and-more") {
		t.Errorf("the tail of a long secret leaked: %q", out)
	}
}

// Each secret is a substring of the placeholder's neighbours after replacement; a secret that happens to be part of the
// placeholder text must not loop or corrupt the output.
func TestASecretThatLooksLikeThePlaceholderDoesNotLoop(t *testing.T) {
	s := New([]string{"REDACTED-token-9999", "[REDACTED]"})
	out, _ := s.Text("a [REDACTED] b REDACTED-token-9999 c")
	if strings.Contains(out, "REDACTED-token-9999") {
		t.Errorf("%q", out)
	}
}

func TestShortSecretsAreHandledByWordBoundary(t *testing.T) {
	s := New([]string{"abcd"})
	for in, want := range map[string]string{
		"value is abcd here":      "value is " + placeholder + " here",
		"abcd":                    placeholder,
		"x=abcd&y=2":              "x=" + placeholder + "&y=2",
		"abcdef is a longer word": "abcdef is a longer word",
		"xabcd":                   "xabcd",
		"the word abcdabcd":       "the word abcdabcd",
	} {
		if out, _ := s.Text(in); out != want {
			t.Errorf("%q -> %q, want %q", in, out, want)
		}
	}
}

func TestSecretsShorterThanFourCharactersAreIgnored(t *testing.T) {
	s := New([]string{"ab", "xyz", ""})
	in := "ab xyz and an empty secret"
	if out, n := s.Text(in); out != in || n != 0 {
		t.Errorf("a three character value would destroy the response and tells nobody anything: %q %d", out, n)
	}
}

func TestLongSecretsAreReplacedInsideWords(t *testing.T) {
	s := New([]string{"0123456789abcdef"})
	out, _ := s.Text("prefix0123456789abcdefsuffix")
	if strings.Contains(out, "0123456789abcdef") {
		t.Errorf("a long random value has no business being inside a word, and must go: %q", out)
	}
}

func TestMultilineAndBinarySafeText(t *testing.T) {
	s := New([]string{"line-one-secret-1\nline-two-secret-2"})
	out, _ := s.Text("a\nline-one-secret-1\nline-two-secret-2\nb")
	if strings.Contains(out, "secret-1") || strings.Contains(out, "secret-2") {
		t.Errorf("%q", out)
	}
	if got, _ := s.Text("\x00\x01\xff\xfe"); got != "\x00\x01\xff\xfe" {
		t.Errorf("bytes that are not text pass through: %q", got)
	}
}

func TestPatternsCatchBearerTokensTheSessionNeverHeld(t *testing.T) {
	s := New(nil)
	for in, leak := range map[string]string{
		"Authorization: Bearer abc.def.ghi-123456":              "abc.def.ghi-123456",
		"authorization: bearer ZZZZZZZZZZZZZZZZ":                "ZZZZZZZZZZZZZZZZ",
		`{"access_token":"tok-abcdef123456","expires_in":3600}`: "tok-abcdef123456",
		`{"refresh_token": "r-9876543210zz"}`:                   "r-9876543210zz",
		`{"id_token":"eyJhbGciOiJIUzI1NiJ9.e30.sig12345"}`:      "eyJhbGciOiJIUzI1NiJ9.e30.sig12345",
		`{"api_key":"key-0000111122223333"}`:                    "key-0000111122223333",
		`{"password":"hunter2-hunter2"}`:                        "hunter2-hunter2",
		`{"client_secret":"cs-aaaabbbbcccc"}`:                   "cs-aaaabbbbcccc",
		"access_token=querystyle12345&x=1":                      "querystyle12345",
		"Set-Cookie: session=cookie-value-12345; Path=/":        "cookie-value-12345",
		"Cookie: a=cookie-aaaa-1111; b=cookie-bbbb-2222":        "cookie-aaaa-1111",
	} {
		out, n := s.Text(in)
		if strings.Contains(out, leak) {
			t.Errorf("a credential shaped value survived: %q -> %q", in, out)
		}
		if n == 0 {
			t.Errorf("%q: not counted", in)
		}
	}
}

func TestPatternsLeaveOrdinaryTextAlone(t *testing.T) {
	s := New(nil)
	for _, in := range []string{
		`{"name":"token bucket","count":3}`,
		"the password policy requires 12 characters",
		`{"has_token":true}`,
		"Bearer",
		"a cookie recipe",
		`{"tokens":[1,2,3]}`,
	} {
		if out, n := s.Text(in); out != in || n != 0 {
			t.Errorf("ordinary text was changed: %q -> %q (%d)", in, out, n)
		}
	}
}

func TestPatternsDoNotEatTheWholeDocument(t *testing.T) {
	s := New(nil)
	in := `{"access_token":"tok-abcdef123456","user":"alice","roles":["admin","dev"]}`
	out, _ := s.Text(in)
	if !strings.Contains(out, `"user":"alice"`) || !strings.Contains(out, `"roles":["admin","dev"]`) {
		t.Errorf("only the credential may go: %q", out)
	}
}

func TestHeadersAreScrubbedValueByValue(t *testing.T) {
	s := New([]string{"cookie-secret-value-1"})
	h := map[string][]string{
		"Location":     {"https://x.example/cb?sid=cookie-secret-value-1"},
		"X-Echo":       {"cookie-secret-value-1", "fine"},
		"Content-Type": {"text/plain"},
	}
	out, n := s.Header(h)
	if strings.Contains(out["Location"][0], "cookie-secret") || strings.Contains(out["X-Echo"][0], "cookie-secret") {
		t.Errorf("%v", out)
	}
	if out["X-Echo"][1] != "fine" || out["Content-Type"][0] != "text/plain" {
		t.Errorf("%v", out)
	}
	if n != 2 {
		t.Errorf("%d", n)
	}
	if h["Location"][0] != "https://x.example/cb?sid=cookie-secret-value-1" {
		t.Error("the input must not be modified")
	}
}

func TestSetCookieAndCredentialHeadersAreDroppedWhole(t *testing.T) {
	s := New(nil)
	h := map[string][]string{
		"Set-Cookie":          {"a=1"},
		"Set-Cookie2":         {"a=1"},
		"Authorization":       {"Bearer x"},
		"Proxy-Authorization": {"Basic eA=="},
		"Www-Authenticate":    {`Bearer realm="x"`},
		"Proxy-Authenticate":  {"Basic"},
		"Content-Type":        {"text/plain"},
	}
	out, _ := s.Header(h)
	for _, gone := range []string{"Set-Cookie", "Set-Cookie2", "Authorization", "Proxy-Authorization"} {
		if _, ok := out[gone]; ok {
			t.Errorf("%s must not reach the agent", gone)
		}
	}
	if out["Content-Type"][0] != "text/plain" {
		t.Errorf("%v", out)
	}
}

func TestHeaderNamesAreMatchedWhateverTheCase(t *testing.T) {
	s := New(nil)
	out, _ := s.Header(map[string][]string{"sEt-CoOkIe": {"a=1"}, "AUTHORIZATION": {"x"}})
	if len(out) != 0 {
		t.Errorf("%v", out)
	}
}

func TestBytesReportsWhetherTheyAreText(t *testing.T) {
	s := New([]string{"secret-value-abcdef"})
	out, n, text := s.Bytes([]byte("hello secret-value-abcdef"))
	if !text || n != 1 || strings.Contains(string(out), "abcdef") {
		t.Errorf("%q %d %v", out, n, text)
	}
	bin := []byte{0x89, 'P', 'N', 'G', 0, 1, 2, 3, 0xff, 0xfe}
	out, n, text = s.Bytes(bin)
	if text || n != 0 || string(out) != string(bin) {
		t.Errorf("binary must pass through and be reported as binary: %v %d %v", out, n, text)
	}
}

// A binary response that contains the secret cannot be scrubbed by text replacement; the caller is told so and must
// not hand the bytes to the agent.
func TestBinaryThatContainsASecretIsFlagged(t *testing.T) {
	s := New([]string{"secret-value-abcdef"})
	bin := append([]byte{0x00, 0x01, 0x02, 0xff}, []byte("secret-value-abcdef")...)
	bin = append(bin, 0xfe, 0x00)
	if !s.BinaryLeaks(bin) {
		t.Error("a secret inside binary data is a leak that cannot be fixed by replacement: it must be reported")
	}
	if s.BinaryLeaks([]byte{0x00, 0x01, 0x02, 0xff}) {
		t.Error("binary without a secret is fine")
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("secret-value-abcdef"))
	if !s.BinaryLeaks(append([]byte{0x00, 0xff}, []byte(b64)...)) {
		t.Error("an encoded secret inside binary data is reported too")
	}
}

func TestLongestAndEmptyAndNilScrubbers(t *testing.T) {
	if New(nil).Longest() != 0 {
		t.Error("no secrets, no length")
	}
	if got := New([]string{"abcd", "abcdefghij", "abc"}).Longest(); got < 10 {
		t.Errorf("the longest variant matters for reading enough of a response: %d", got)
	}
	var nilS *Scrubber
	if out, n := nilS.Text("abc"); out != "abc" || n != 0 {
		t.Errorf("a nil scrubber changes nothing: %q %d", out, n)
	}
}

func TestVariantExplosionIsBounded(t *testing.T) {
	long := strings.Repeat("A1b2C3d4", 4000) // a very long value
	s := New([]string{long})
	if s.Longest() > maxExpansion*len(long)+8 {
		t.Errorf("the variants of a huge secret must stay within a sensible multiple: %d", s.Longest())
	}
	secrets := make([]string, 500)
	for i := range secrets {
		secrets[i] = strings.Repeat("x", 20) + string(rune('a'+i%26)) + strings.Repeat("y", i%7+1)
	}
	if out, _ := New(secrets).Text("plain"); out != "plain" {
		t.Error(out)
	}
}

func TestNewDoesNotKeepOrChangeTheCallersSlice(t *testing.T) {
	in := []string{"keep-this-secret-1", "keep-this-secret-2"}
	cp := append([]string{}, in...)
	New(in)
	if in[0] != cp[0] || in[1] != cp[1] {
		t.Errorf("%v", in)
	}
}

func TestScrubbingIsDeterministicAndIdempotent(t *testing.T) {
	s := New([]string{"idempotent-secret-77"})
	in := "x idempotent-secret-77 y " + url.QueryEscape("idempotent-secret-77")
	once, _ := s.Text(in)
	twice, n := s.Text(once)
	if once != twice || n != 0 {
		t.Errorf("a scrubbed text has nothing left to scrub: %q / %q (%d)", once, twice, n)
	}
}

func TestConcurrentUse(t *testing.T) {
	s := New([]string{"concurrent-secret-xyz"})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 200; j++ {
				if out, _ := s.Text("a concurrent-secret-xyz b"); strings.Contains(out, "secret-xyz") {
					t.Error("leak")
				}
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// Each encoding has to be tested with a secret that makes it differ from its neighbours. With a secret whose base64
// forms coincide, deleting one encoding changes nothing and the test proves nothing about it.

// distinct returns secrets for which the named encodings produce different strings.
func TestEachBase64FlavourIsCoveredByASecretThatSeparatesIt(t *testing.T) {
	// 0xfb 0xff bytes encode with '+' and '/' in standard base64 and with '-' and '_' in URL base64; the length is not a
	// multiple of 3, so the padded and unpadded forms differ too.
	secret := string([]byte{'a', 'b', 'c', 0xfb, 0xff, 0xfe, 'x', 'y'})
	forms := map[string]string{
		"std":     base64.StdEncoding.EncodeToString([]byte(secret)),
		"url":     base64.URLEncoding.EncodeToString([]byte(secret)),
		"raw-std": base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"raw-url": base64.RawURLEncoding.EncodeToString([]byte(secret)),
	}
	seen := map[string]string{}
	for k, v := range forms {
		if other, dup := seen[v]; dup {
			t.Fatalf("test setup: %s and %s are the same string %q", k, other, v)
		}
		seen[v] = k
	}
	if forms["std"] == forms["raw-std"] || forms["url"] == forms["raw-url"] {
		t.Fatal("test setup: padding must show")
	}
	s := New([]string{secret})
	for name, v := range forms {
		// the form alone, with the characters around it that break a prefix match
		in := "x=" + v + "&y"
		out, _ := s.Text(in)
		if strings.Contains(out, v) || strings.Contains(out, strings.TrimRight(v, "=")) {
			t.Errorf("base64 %s survived: %q -> %q", name, in, out)
		}
	}
}

func TestUpperAndLowerCaseFormsAreCoveredByATokenWithBothCases(t *testing.T) {
	s := New([]string{"MiXeD-Case-Token-123"})
	for _, v := range []string{"MIXED-CASE-TOKEN-123", "mixed-case-token-123"} {
		if out, _ := s.Text("v=" + v); strings.Contains(strings.ToLower(out), "mixed-case") {
			t.Errorf("%q survived: %q", v, out)
		}
	}
}

func TestPercentEncodedHexIsCoveredInBothCases(t *testing.T) {
	secret := "ab/cd+ef=gh"
	s := New([]string{secret})
	upper, lower := refPercentAll(secret), strings.ToLower(refPercentAll(secret))
	if upper == lower {
		t.Fatal("test setup: the secret must contain letters so that the two cases differ")
	}
	for _, v := range []string{upper, lower} {
		if out, _ := s.Text("a=" + v + "&b"); strings.Contains(strings.ToLower(out), "%61%62") {
			t.Errorf("%q survived: %q", v, out)
		}
	}
}

func TestUnicodeEscapesAreCoveredInBothCases(t *testing.T) {
	secret := "ab/cd+ef"
	s := New([]string{secret})
	upper := ""
	lower := ""
	for _, r := range secret {
		upper += fmt.Sprintf(`\u%04X`, r)
		lower += fmt.Sprintf(`\u%04x`, r)
	}
	// "/" is 0x2F and letters are lower-case hex digits: the two spellings differ only if some digit is a letter a-f
	if upper == lower {
		t.Fatal("test setup: the escapes must contain a hex letter")
	}
	for _, v := range []string{upper, lower} {
		if out, _ := s.Text(`"` + v + `"`); strings.Contains(strings.ToLower(out), `\u0061`) {
			t.Errorf("%q survived: %q", v, out)
		}
	}
}

func TestHTMLEntityFormsAreBothCovered(t *testing.T) {
	// html.EscapeString writes &#39; for the apostrophe, the named form writes &apos;
	secret := `a'b"c<d>e&f-token-1`
	s := New([]string{secret})
	for name, v := range map[string]string{"numeric": html.EscapeString(secret), "named": htmlNamed(secret)} {
		if out, _ := s.Text("<p>" + v + "</p>"); strings.Contains(out, "token-1") {
			t.Errorf("%s survived: %q", name, out)
		}
	}
	if html.EscapeString(secret) == htmlNamed(secret) {
		t.Fatal("test setup: the apostrophe must make the two forms differ")
	}
}

func TestSecretsBelowTheMinimumAreDroppedNotReplaced(t *testing.T) {
	// "abc" would be replaced everywhere if it were not dropped
	if out, n := New([]string{"abc"}).Text("abc abc abc"); out != "abc abc abc" || n != 0 {
		t.Errorf("%q %d", out, n)
	}
	// exactly the minimum is kept
	if out, _ := New([]string{"abcd"}).Text("x abcd y"); strings.Contains(out, "abcd") {
		t.Errorf("a four character secret is scrubbed: %q", out)
	}
}

func TestAHugeSecretsVariantsStayBounded(t *testing.T) {
	huge := strings.Repeat("Aa1/+", 2000) // 10000 bytes
	s := New([]string{huge})
	limit := maxExpansion*len(huge) + 8
	for _, v := range s.vars {
		if len(v.s) > limit {
			t.Fatalf("a variant of %d bytes exceeds the bound %d", len(v.s), limit)
		}
	}
	// the percent-all form of a 10000 byte value is 30000 bytes, within the bound; a pathological one is not
	if len(s.vars) == 0 {
		t.Fatal("the secret itself is still scrubbed")
	}
}

func TestASecretThatIsPartOfThePlaceholderIsNeverUsedAsAVariant(t *testing.T) {
	s := New([]string{"REDACTED"})
	for _, v := range s.vars {
		if strings.Contains(Placeholder, v.s) {
			t.Errorf("%q is part of the placeholder: replacing it would rewrite every placeholder, and the output would keep changing", v.s)
		}
	}
	out, _ := s.Text("[REDACTED] stays")
	if !strings.Contains(out, "[REDACTED] stays") && out != "[REDACTED] stays" {
		t.Errorf("%q", out)
	}
}

func TestSetCookieAttributesStayReadable(t *testing.T) {
	out, _ := New(nil).Text("Set-Cookie: sid=value-aaaa-1111; Path=/app; Expires=Wed, 01 Jan 2031 00:00:00 GMT; HttpOnly")
	if strings.Contains(out, "value-aaaa") {
		t.Errorf("the value goes: %q", out)
	}
	for _, keep := range []string{"Path=/app", "Expires=Wed", "HttpOnly"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q is not secret and the agent may need it: %q", keep, out)
		}
	}
}

func TestNonUTF8BytesAreNotText(t *testing.T) {
	if IsText([]byte{0xff, 0xfe, 'a'}) {
		t.Error("invalid UTF-8 is not text")
	}
	if IsText([]byte("ok\x00no")) {
		t.Error("a NUL byte is not text")
	}
	if !IsText([]byte("héllo 你好\n")) {
		t.Error("valid text with non-ASCII characters is text")
	}
}

func TestShortSecretsAreNotSoughtInsideBinaryData(t *testing.T) {
	s := New([]string{"abcd"}) // a short secret: matched by words in text, never inside binary data
	if s.BinaryLeaks([]byte{0x00, 0xff, 'a', 'b', 'c', 'd', 0x00}) {
		t.Error("four bytes match by chance in any binary file; reporting them would reject harmless responses")
	}
}

// A padded base64 form must go whole: leaving the '=' behind would not leak the secret, but a scrubber that leaves
// pieces of an encoding is a scrubber that is one off-by-one from leaving more.
func TestPaddedBase64FormsLeaveNothingBehind(t *testing.T) {
	secret := string([]byte{'a', 'b', 'c', 0xfb, 0xff, 0xfe, 'x', 'y'})
	for name, enc := range map[string]*base64.Encoding{"std": base64.StdEncoding, "url": base64.URLEncoding} {
		v := enc.EncodeToString([]byte(secret))
		if !strings.HasSuffix(v, "=") {
			t.Fatal("test setup: the form must be padded")
		}
		out, _ := New([]string{secret}).Text("<" + v + ">")
		if out != "<"+Placeholder+">" {
			t.Errorf("%s: %q", name, out)
		}
	}
}

// The percent-encoding of a huge secret is three times its length, base64 four thirds, hex twice, JSON unicode six
// times: all inside the bound. What the bound exists for is a value for which some encoding explodes.
func TestNoVariantExceedsTheBound(t *testing.T) {
	for _, sec := range []string{strings.Repeat("\u4e2d", 200), strings.Repeat("\U0001F600", 100), strings.Repeat(`"\/<>&'`, 300)} {
		s := New([]string{sec})
		limit := maxExpansion*len(sec) + 8
		for _, v := range s.vars {
			if len(v.s) > limit {
				t.Errorf("a variant of %d bytes exceeds the bound %d (secret %d bytes)", len(v.s), limit, len(sec))
			}
		}
	}
}

func TestEveryNonBasicAuthorizationSchemeIsScrubbed(t *testing.T) {
	for _, in := range []string{
		"Authorization: Digest username=\"u\", response=\"abcdef1234567890\"",
		"Authorization: Negotiate YIIChQYGKwYBBQUCoIICeTCCAnWgDTALBgkqhkiG9xIBAgKhBAMCAQ",
		"Authorization: Token abcdef1234567890",
	} {
		out, n := New(nil).Text(in)
		if n == 0 || strings.Contains(out, "abcdef1234567890") || strings.Contains(out, "YIIChQYG") {
			t.Errorf("%q -> %q (%d)", in, out, n)
		}
	}
}

// The bound must be tight enough to bite and loose enough not to remove a real variant: every encoding the scrubber knows
// is kept for every kind of secret.
func TestTheBoundKeepsEveryRealEncodingOfEveryKindOfSecret(t *testing.T) {
	for name, sec := range map[string]string{
		"ascii": strings.Repeat("a", 40), "cjk": strings.Repeat("\u4e2d", 20), "emoji": strings.Repeat("\U0001F600", 20),
		"punct": strings.Repeat(`"\/<>&'`, 10), "short": "abcd",
	} {
		s := New([]string{sec})
		have := map[string]bool{}
		for _, v := range s.vars {
			have[v.s] = true
		}
		for _, v := range variantsOf(sec) {
			if len(v) >= MinSecretLen && !strings.Contains(Placeholder, v) && !have[v] {
				t.Errorf("%s: the real variant %.30q was dropped by the bound (%d bytes for a %d byte secret)", name, v, len(v), len(sec))
			}
		}
	}
}

func TestAVariantBeyondTheBoundIsDroppedAndOneWithinItIsKept(t *testing.T) {
	sec := "abcdefgh"
	limit := maxExpansion*len(sec) + 8
	exact := strings.Repeat("e", limit)
	over := strings.Repeat("o", limit+1)
	s := newWith([]string{sec}, func(string) []string { return []string{exact, over, "normal-variant"} })
	have := map[string]bool{}
	for _, v := range s.vars {
		have[v.s] = true
	}
	if !have[exact] {
		t.Errorf("a variant exactly at the bound (%d bytes) is kept", limit)
	}
	if have[over] {
		t.Errorf("a variant one byte over the bound (%d bytes) must be dropped: it is how a huge value would cost memory", limit+1)
	}
	if !have["normal-variant"] {
		t.Error("ordinary variants are kept")
	}
	if s.Longest() != limit {
		t.Errorf("the longest kept variant sets the read-ahead: %d, want %d", s.Longest(), limit)
	}
}

// The expansion bound is a number with a reason (the longest real encoding is six times the secret). Pin it here, so
// that loosening it to make a test pass is a visible change to this file and not a silent one to the constant.
func TestTheExpansionBoundIsSevenTimes(t *testing.T) {
	if maxExpansion != 7 {
		t.Errorf("maxExpansion is %d: the longest real encoding (\\uXXXX) is 6x, so 7 leaves one spare, and anything more only invites a value that costs memory", maxExpansion)
	}
	if MinSecretLen != 4 || wordOnlyBelow != 8 {
		t.Errorf("MinSecretLen=%d wordOnlyBelow=%d: the documented limits are 4 and 8", MinSecretLen, wordOnlyBelow)
	}
	// and 6x is really the largest: no encoding the scrubber knows exceeds it
	for _, sec := range []string{strings.Repeat("a", 40), strings.Repeat("\u4e2d", 20), strings.Repeat("\U0001F600", 20)} {
		for _, v := range variantsOf(sec) {
			if len(v) > 6*len(sec) {
				t.Errorf("an encoding of %d bytes exceeds 6x its %d byte secret: the documented bound is wrong", len(v), len(sec))
			}
		}
	}
}
