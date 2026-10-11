// Package redact removes credentials from what a site sends back before an AI agent sees it.
//
// The proxy puts a session's cookies and tokens into a request, so the response may repeat them: an echo endpoint, an
// error page, a debug view or a redirect target all do. A scrubber that only knows the raw value is not enough, because
// those places re-encode what they were sent. This one removes every value of the session in the encodings a server is
// likely to use, and, as a second net, anything shaped like a credential that the session never held.
//
// It is a safety net, not a proof: a server can transform a value in ways no list covers. The proxy therefore does not
// rely on it alone (it never lets the agent send credentials, never follows a redirect off the site, and drops every
// credential header), and the limits are written down in docs/OPERATING.md.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Placeholder replaces every credential that is removed.
const Placeholder = "[REDACTED]"

const (
	// MinSecretLen is the shortest value that is scrubbed. A shorter one appears in ordinary text by chance, and replacing
	// it would damage the response without protecting anything.
	MinSecretLen = 4
	// maxExpansion bounds how much longer than the secret any variant of it may be. The longest encoding in use is the
	// \uXXXX form, six times the secret; a variant beyond this bound would only be a way to make a huge value cost
	// memory, so it is dropped.
	maxExpansion = 7
	// wordOnlyBelow: values shorter than this are replaced only as whole words. A long random value has no business inside
	// another word; a short one (a numeric id, a short token) very well may.
	wordOnlyBelow = 8
)

type variant struct {
	s    string
	word bool // match only between non-word characters
}

// Scrubber removes a fixed set of secrets. It is safe for concurrent use and never changes after New.
type Scrubber struct {
	vars    []variant // longest first
	longest int
}

// New builds a scrubber for the given secret values. The slice is not kept or changed.
func New(secrets []string) *Scrubber { return newWith(secrets, variantsOf) }

// newWith is New with the encodings to use; tests pass one that misbehaves to show that the bound holds.
func newWith(secrets []string, forms func(string) []string) *Scrubber {
	seen := map[string]int{} // variant -> index in list
	var list []variant
	add := func(v string, word bool, limit int) {
		if len(v) < MinSecretLen || len(v) > limit || strings.Contains(Placeholder, v) {
			return
		}
		if i, ok := seen[v]; ok {
			if !word {
				list[i].word = false // a long secret's variant is matched as a substring, whoever else shares it
			}
			return
		}
		seen[v] = len(list)
		list = append(list, variant{v, word})
	}
	for _, sec := range secrets {
		word := len(sec) < wordOnlyBelow
		limit := maxExpansion*len(sec) + 8
		for _, v := range forms(sec) {
			add(v, word, limit)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return len(list[i].s) > len(list[j].s) })
	s := &Scrubber{vars: list}
	if len(list) > 0 {
		s.longest = len(list[0].s)
	}
	return s
}

// variantsOf returns the forms in which a server may repeat a secret.
func variantsOf(sec string) []string {
	b := []byte(sec)
	q := url.QueryEscape(sec)
	out := []string{
		sec, strings.ToLower(sec), strings.ToUpper(sec),
		q, strings.ToLower(q), url.PathEscape(sec), url.QueryEscape(q),
		percentAll(sec, true), percentAll(sec, false),
		html.EscapeString(sec), htmlNamed(sec),
		jsonSlash(sec), jsonStd(sec), jsonUnicode(sec, true), jsonUnicode(sec, false),
		base64.StdEncoding.EncodeToString(b), base64.URLEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
	}
	return out
}

func percentAll(s string, upper bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if upper {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	return b.String()
}

var htmlNamedReplacer = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func htmlNamed(s string) string { return htmlNamedReplacer.Replace(s) }

var jsonSlashReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "/", `\/`, "\n", `\n`, "\r", `\r`, "\t", `\t`)

// jsonSlash is JSON string escaping as PHP and several other encoders do it, which also escapes the slash.
func jsonSlash(s string) string { return jsonSlashReplacer.Replace(s) }

// jsonStd is what encoding/json writes (it escapes <, > and & as \u003c and friends).
func jsonStd(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1])
}

// jsonUnicode writes every character as a \uXXXX escape, which a few servers do to defeat exactly this kind of matching.
func jsonUnicode(s string, lower bool) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0xFFFF {
			r1, r2 := splitSurrogates(r)
			writeU(&b, r1, lower)
			writeU(&b, r2, lower)
			continue
		}
		writeU(&b, r, lower)
	}
	return b.String()
}

func splitSurrogates(r rune) (rune, rune) {
	r -= 0x10000
	return 0xD800 + (r>>10)&0x3FF, 0xDC00 + r&0x3FF
}

func writeU(b *strings.Builder, r rune, lower bool) {
	if lower {
		fmt.Fprintf(b, `\u%04x`, r)
	} else {
		fmt.Fprintf(b, `\u%04X`, r)
	}
}

// Longest is the length of the longest form of any secret: a response must be read at least that far past its limit so
// that a secret cut in half by the limit is still found whole.
func (s *Scrubber) Longest() int {
	if s == nil {
		return 0
	}
	return s.longest
}

// Text removes every secret and every credential-shaped value from in and reports how many it replaced.
func (s *Scrubber) Text(in string) (string, int) {
	if s == nil {
		return in, 0
	}
	out, n := in, 0
	for _, v := range s.vars {
		var k int
		out, k = replace(out, v)
		n += k
	}
	out, k := scrubPatterns(out)
	return out, n + k
}

func replace(in string, v variant) (string, int) {
	if !strings.Contains(in, v.s) {
		return in, 0
	}
	if !v.word {
		return strings.ReplaceAll(in, v.s, Placeholder), strings.Count(in, v.s)
	}
	var b strings.Builder
	n, from := 0, 0
	for {
		i := strings.Index(in[from:], v.s)
		if i < 0 {
			break
		}
		i += from
		end := i + len(v.s)
		if (i == 0 || !isWord(in[i-1])) && (end == len(in) || !isWord(in[end])) {
			b.WriteString(in[from:i])
			b.WriteString(Placeholder)
			n++
		} else {
			b.WriteString(in[from:end])
		}
		from = end
	}
	if n == 0 {
		return in, 0
	}
	b.WriteString(in[from:])
	return b.String(), n
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

var (
	// Authorization: Bearer <token>
	reBearer = regexp.MustCompile(`(?i)\b(bearer)(\s+)([A-Za-z0-9._~+/=-]{8,})`)
	// Authorization: Basic/Digest/Negotiate/Token <whatever>
	reAuthLine = regexp.MustCompile(`(?i)(\bauthorization\s*:\s*)(basic|digest|negotiate|token)(\s+)([^\r\n]+)`)
	// "access_token": "value" and its relatives in JSON
	reJSONKey = regexp.MustCompile(`(?i)("(?:access_token|refresh_token|id_token|token|api_key|apikey|client_secret|secret|password|passwd|authorization)"\s*:\s*")((?:[^"\\]|\\.){4,})(")`)
	// access_token=value in a query string or a form
	reQuery = regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|api_key|apikey|client_secret|token|password|passwd|secret)=([^&\s"'<>;]{4,})`)
	// Cookie: a=b; c=d and Set-Cookie: a=b; Path=/
	reCookieLine = regexp.MustCompile(`(?i)\b(set-cookie|cookie)(\s*:\s*)([^\r\n]+)`)
)

func scrubPatterns(in string) (string, int) {
	n := 0
	count := func(re *regexp.Regexp, s string, fn func(m []string) string) string {
		return re.ReplaceAllStringFunc(s, func(whole string) string {
			m := re.FindStringSubmatch(whole)
			r := fn(m)
			if r != whole {
				n++
			}
			return r
		})
	}
	out := in
	out = count(reBearer, out, func(m []string) string { return m[1] + m[2] + Placeholder })
	out = count(reAuthLine, out, func(m []string) string {
		if strings.HasPrefix(m[4], Placeholder) {
			return m[0]
		}
		return m[1] + m[2] + m[3] + Placeholder
	})
	out = count(reJSONKey, out, func(m []string) string { return m[1] + Placeholder + m[3] })
	out = count(reQuery, out, func(m []string) string { return m[1] + "=" + Placeholder })
	out = count(reCookieLine, out, func(m []string) string {
		return m[1] + m[2] + scrubCookiePairs(m[3], strings.EqualFold(m[1], "set-cookie"))
	})
	return out, n
}

// scrubCookiePairs blanks the value of every name=value pair of a Cookie line, or only the first pair of a Set-Cookie
// line (the rest are attributes such as Path and Expires, which are not secret and which an agent may need to read).
func scrubCookiePairs(line string, setCookie bool) string {
	parts := strings.Split(line, ";")
	for i, p := range parts {
		if setCookie && i > 0 {
			break
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 || len(strings.TrimSpace(p[eq+1:])) < MinSecretLen || strings.Contains(p[eq+1:], Placeholder) {
			continue
		}
		parts[i] = p[:eq+1] + Placeholder
	}
	return strings.Join(parts, ";")
}

// dropped are response headers that carry credentials and are never passed on.
var dropped = map[string]bool{"set-cookie": true, "set-cookie2": true, "authorization": true, "proxy-authorization": true}

// Header returns a scrubbed copy of h. Credential headers are removed whole; the others have their values scrubbed.
func (s *Scrubber) Header(h map[string][]string) (map[string][]string, int) {
	out := make(map[string][]string, len(h))
	n := 0
	for k, vals := range h {
		if dropped[strings.ToLower(k)] {
			continue
		}
		cp := make([]string, len(vals))
		for i, v := range vals {
			var m int
			cp[i], m = s.Text(v)
			n += m
		}
		out[k] = cp
	}
	return out, n
}

// IsText reports whether b is something a person or a model can read: valid UTF-8 without NUL bytes.
func IsText(b []byte) bool { return utf8.Valid(b) && bytes.IndexByte(b, 0) < 0 }

// Bytes scrubs b when it is text. For anything else it returns b untouched and false: replacing inside a binary format
// would corrupt it, so the caller decides what to do (see BinaryLeaks).
func (s *Scrubber) Bytes(b []byte) ([]byte, int, bool) {
	if !IsText(b) {
		return b, 0, false
	}
	out, n := s.Text(string(b))
	return []byte(out), n, true
}

// BinaryLeaks reports whether a secret appears inside binary data. Such a leak cannot be repaired by replacement, so a
// response in which it is found must not be handed to the agent. Short secrets are not looked for: four random bytes
// match a secret by chance far too often for the answer to mean anything.
func (s *Scrubber) BinaryLeaks(b []byte) bool {
	if s == nil {
		return false
	}
	for _, v := range s.vars {
		if !v.word && bytes.Contains(b, []byte(v.s)) {
			return true
		}
	}
	return false
}
