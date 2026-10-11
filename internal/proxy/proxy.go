// Package proxy sends an HTTP request to a site on behalf of an AI agent, with the session's credentials put in by this
// process and taken out of the answer before the agent sees it.
//
// The agent says what to ask for (method, path, query, body, ordinary headers). It never supplies, and never receives, a
// cookie, a token or an authorization header:
//
//   - it can only reach the site the session belongs to (an absolute path on that origin, nothing else);
//   - it cannot set a header that carries or steers credentials (Cookie, Authorization, the session's own headers, Host,
//     the framing headers);
//   - redirects are not followed unless asked, never across origins, and never down from https;
//   - Set-Cookie and every credential header are dropped from the answer, and every value of the session (and of any
//     cookie the site rotates) is removed from the headers and the body in the encodings a server is likely to use;
//   - a body that cannot be scrubbed because it is binary and holds a credential is withheld.
package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LeafAI/securl/internal/redact"
	"github.com/LeafAI/securl/internal/site"
)

var (
	// ErrInvalid marks a request that was refused before anything was sent.
	ErrInvalid = errors.New("invalid request")
	// ErrSessionExpired marks a session that has run out.
	ErrSessionExpired = errors.New("the session has expired")
	// ErrUnreachable marks a request that was sent (or could not be) and got no answer.
	ErrUnreachable = errors.New("the site could not be reached")
	// ErrTooManyRedirects marks a redirect chain that did not end.
	ErrTooManyRedirects = errors.New("too many redirects")
)

const (
	defaultTimeout     = 25 * time.Second // below the 30 s a tool call gets behind the contexts gateway
	defaultMaxTimeout  = 120 * time.Second
	defaultMaxRequest  = 1 << 20
	defaultMaxResponse = 256 << 10
	maxRedirects       = 10
	drainLimit         = 1 << 20 // how much of an over-long body is read only to count it
	maxHeaders         = 50
	maxHeaderBytes     = 8 << 10
)

// Proxy sends requests. The zero value of every field but HC takes a default.
type Proxy struct {
	HC               *http.Client
	MaxRequestBytes  int
	MaxResponseBytes int
	MaxTimeout       time.Duration
}

// Request is what an agent may ask for. Exactly one of JSON, Form, Text and Base64 may carry a body.
type Request struct {
	Base            *url.URL // the site (scheme, host, optional path prefix); the path below is added to it
	Method          string
	Path            string // absolute path on the site; no query, no fragment
	Query           map[string][]string
	Headers         map[string]string
	JSON            json.RawMessage
	Form            map[string][]string
	Text            string
	Base64          string
	FollowRedirects bool
	Timeout         time.Duration
}

// Result is what the agent gets. It holds nothing secret.
type Result struct {
	Status       int                 `json:"status"`
	Headers      map[string][]string `json:"headers,omitempty"`
	Body         string              `json:"body,omitempty"`
	BodyIsBase64 bool                `json:"body_is_base64,omitempty"`
	Truncated    bool                `json:"truncated,omitempty"`
	TotalBytes   int                 `json:"total_bytes,omitempty"`
	Redactions   int                 `json:"redactions"`
	Withheld     bool                `json:"withheld,omitempty"`
	FinalPath    string              `json:"final_path,omitempty"`

	// NewSession is the session with the cookies the site rotated. It is for the caller to store; it is never serialised.
	NewSession *site.Session `json:"-"`
}

// FinalPathOr is where the request ended up, or fallback when it did not move (a path, never a query string).
func (r *Result) FinalPathOr(fallback string) string {
	if r.FinalPath != "" {
		return r.FinalPath
	}
	return fallback
}

func (p *Proxy) maxTimeout() time.Duration {
	if p.MaxTimeout > 0 {
		return p.MaxTimeout
	}
	return defaultMaxTimeout
}

func (p *Proxy) timeout(r Request) time.Duration {
	d := r.Timeout
	if d <= 0 {
		d = defaultTimeout
	}
	if m := p.maxTimeout(); d > m {
		d = m
	}
	return d
}

func (p *Proxy) maxRequest() int {
	if p.MaxRequestBytes > 0 {
		return p.MaxRequestBytes
	}
	return defaultMaxRequest
}

func (p *Proxy) maxResponse() int {
	if p.MaxResponseBytes > 0 {
		return p.MaxResponseBytes
	}
	return defaultMaxResponse
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ---- validating what the agent asked for ----

var allowedMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}

// forbidden are the headers an agent may not set: those that carry or steer credentials, and those that frame the message.
var forbidden = map[string]bool{
	"cookie": true, "authorization": true, "proxy-authorization": true, "host": true, "content-length": true,
	"transfer-encoding": true, "connection": true, "proxy-connection": true, "upgrade": true, "te": true, "expect": true,
	"accept-encoding": true, "trailer": true, "keep-alive": true,
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func validHeaderValue(v string) bool {
	if len(v) > maxHeaderBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func agentHeaders(in map[string]string, sess *site.Session) (http.Header, error) {
	if len(in) > maxHeaders {
		return nil, invalid("too many headers (at most %d)", maxHeaders)
	}
	own := map[string]bool{}
	for k := range sess.Headers {
		own[strings.ToLower(k)] = true
	}
	out := http.Header{}
	for k, v := range in {
		if !isToken(k) {
			return nil, invalid("%q is not a valid header name", clipName(k))
		}
		lk := strings.ToLower(k)
		if forbidden[lk] || own[lk] {
			return nil, invalid("the %s header is set by the gateway and cannot be supplied", http.CanonicalHeaderKey(k))
		}
		if !validHeaderValue(v) {
			return nil, invalid("the value of header %s contains a control character or is too long", http.CanonicalHeaderKey(k))
		}
		out.Set(k, v)
	}
	return out, nil
}

func clipName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func hexVal(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// checkPath accepts an absolute path made of characters that may stand in a URL path, with no dot-dot segment.
func checkPath(p string) (decoded string, err error) {
	switch {
	case p == "":
		return "", invalid("path is required")
	case p[0] != '/':
		return "", invalid("path must be an absolute path starting with /, not a URL")
	case strings.HasPrefix(p, "//"):
		return "", invalid("path must not start with // (that names another host)")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '%':
			if i+2 >= len(p) || !hexVal(p[i+1]) || !hexVal(p[i+2]) {
				return "", invalid("path has a malformed percent escape")
			}
			i += 2
		case c == '?' || c == '#':
			return "", invalid("path must not carry a query or a fragment: use the query field")
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0:
		default:
			return "", invalid("path has a character that must be percent-encoded")
		}
	}
	d, err := url.PathUnescape(p)
	if err != nil {
		return "", invalid("path is not valid")
	}
	for i := 0; i < len(d); i++ {
		if d[i] < 0x20 || d[i] == 0x7f || d[i] == '\\' {
			return "", invalid("path contains a control character or a backslash")
		}
	}
	for _, seg := range strings.Split(d, "/") {
		if seg == ".." {
			return "", invalid("path must not contain a .. segment")
		}
	}
	return d, nil
}

type prepared struct {
	method string
	url    *url.URL
	header http.Header
	body   []byte
}

func (p *Proxy) prepare(sess *site.Session, r Request) (*prepared, error) {
	m := strings.ToUpper(r.Method)
	if !allowedMethods[m] {
		return nil, invalid("method is not allowed (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS)")
	}
	b := r.Base
	if b == nil || (b.Scheme != "http" && b.Scheme != "https") || b.Host == "" || b.User != nil {
		return nil, invalid("the site address is not usable")
	}
	decoded, err := checkPath(r.Path)
	if err != nil {
		return nil, err
	}
	prefix := strings.TrimRight(b.EscapedPath(), "/")
	u := &url.URL{Scheme: b.Scheme, Host: b.Host, RawPath: prefix + r.Path}
	if u.Path, err = url.PathUnescape(u.RawPath); err != nil {
		return nil, invalid("path is not valid")
	}
	_ = decoded
	if len(r.Query) > 0 {
		u.RawQuery = url.Values(r.Query).Encode()
	}
	hdr, err := agentHeaders(r.Headers, sess)
	if err != nil {
		return nil, err
	}
	body, ctype, err := p.body(m, r)
	if err != nil {
		return nil, err
	}
	if body != nil && hdr.Get("Content-Type") == "" {
		hdr.Set("Content-Type", ctype)
	}
	return &prepared{method: m, url: u, header: hdr, body: body}, nil
}

func (p *Proxy) body(method string, r Request) ([]byte, string, error) {
	forms := 0
	for _, has := range []bool{len(r.JSON) > 0, len(r.Form) > 0, r.Text != "", r.Base64 != ""} {
		if has {
			forms++
		}
	}
	if forms == 0 {
		return nil, "", nil
	}
	if forms > 1 {
		return nil, "", invalid("give one body: json, form, text or base64")
	}
	if method == "GET" || method == "HEAD" {
		return nil, "", invalid("a %s request has no body", method)
	}
	var b []byte
	var ctype string
	switch {
	case len(r.JSON) > 0:
		if !json.Valid(r.JSON) {
			return nil, "", invalid("json is not valid JSON")
		}
		b, ctype = []byte(r.JSON), "application/json"
	case len(r.Form) > 0:
		b, ctype = []byte(url.Values(r.Form).Encode()), "application/x-www-form-urlencoded"
	case r.Text != "":
		b, ctype = []byte(r.Text), "text/plain; charset=utf-8"
	default:
		d, err := base64.StdEncoding.DecodeString(r.Base64)
		if err != nil {
			return nil, "", invalid("base64 is not valid standard base64")
		}
		b, ctype = d, "application/octet-stream"
	}
	if len(b) > p.maxRequest() {
		return nil, "", invalid("the body is %d bytes; the limit is %d", len(b), p.maxRequest())
	}
	return b, ctype, nil
}

// ---- the session ----

// driverState are Tokens that name how a driver works, not credentials: replacing them in an answer would only damage it.
var driverState = map[string]bool{"api": true, "identity_provider": true, "auth": true, "user": true, "crumb_field": true, "login_method": true}

func secretsOf(s *site.Session) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if len(v) >= redact.MinSecretLen && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, c := range s.Cookies {
		add(c.Value)
		if u, err := url.QueryUnescape(c.Value); err == nil && u != c.Value {
			add(u)
		}
	}
	for _, v := range s.Headers {
		add(v)
		if rest := afterScheme(v); rest != "" {
			add(rest)
			if strings.HasPrefix(strings.ToLower(v), "basic ") {
				if d, err := base64.StdEncoding.DecodeString(rest); err == nil && utf8.Valid(d) {
					add(string(d))
					if i := strings.IndexByte(string(d), ':'); i >= 0 {
						add(string(d)[i+1:])
					}
				}
			}
		}
	}
	for k, v := range s.Tokens {
		if !driverState[strings.ToLower(k)] && len(v) >= 8 {
			add(v)
		}
	}
	return out
}

// afterScheme returns what follows an authorization scheme word ("Bearer abc" -> "abc"), or "" when there is no scheme.
func afterScheme(v string) string {
	i := strings.IndexAny(v, " \t")
	if i <= 0 {
		return ""
	}
	for _, c := range v[:i] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return ""
		}
	}
	return strings.TrimSpace(v[i:])
}

func domainMatch(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(strings.TrimPrefix(domain, "."))
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain) && !isIP(host)
}

func isIP(h string) bool {
	return strings.Trim(h, "0123456789.") == "" || strings.Contains(h, ":")
}

func pathMatch(reqPath, cookiePath string) bool {
	if cookiePath == "" || cookiePath == "/" || reqPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(reqPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || reqPath[len(cookiePath)] == '/'
}

func selectCookies(cookies []*http.Cookie, u *url.URL, now time.Time) string {
	var parts []string
	for _, c := range cookies {
		switch {
		case c.Name == "":
		case !c.Expires.IsZero() && !now.Before(c.Expires):
		case c.Secure && u.Scheme != "https":
		case c.Domain != "" && !domainMatch(u.Hostname(), c.Domain):
		case !pathMatch(u.Path, c.Path):
		default:
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func cloneCookies(in []*http.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, len(in))
	for i, c := range in {
		cp := *c
		out[i] = &cp
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// state follows the cookies through a chain of requests: a cookie set by one answer is sent with the next.
type state struct {
	sess    *site.Session
	cookies []*http.Cookie
	secrets []string
}

func (st *state) apply(set []*http.Cookie, host string, now time.Time) {
	for _, c := range set {
		if c.Name == "" || (c.Domain != "" && !domainMatch(host, c.Domain)) {
			continue
		}
		st.secrets = append(st.secrets, c.Value)
		if u, err := url.QueryUnescape(c.Value); err == nil && u != c.Value {
			st.secrets = append(st.secrets, u)
		}
		cp := *c
		if cp.MaxAge > 0 && cp.Expires.IsZero() {
			cp.Expires = now.Add(time.Duration(cp.MaxAge) * time.Second)
		}
		cp.MaxAge = 0
		gone := c.MaxAge < 0 || c.Value == "" || (!c.Expires.IsZero() && !now.Before(c.Expires))
		kept := st.cookies[:0:0]
		replaced := false
		for _, old := range st.cookies {
			if old.Name != c.Name {
				kept = append(kept, old)
				continue
			}
			if !gone && !replaced {
				kept = append(kept, &cp)
				replaced = true
			}
		}
		if !gone && !replaced {
			kept = append(kept, &cp)
		}
		st.cookies = kept
	}
}

func cookieSig(cs []*http.Cookie) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = c.Name + "\x00" + c.Value
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x01")
}

func (st *state) newSession() *site.Session {
	if cookieSig(st.cookies) == cookieSig(st.sess.Cookies) {
		return nil
	}
	cp := *st.sess
	cp.Cookies = cloneCookies(st.cookies)
	cp.Headers = cloneMap(st.sess.Headers)
	cp.Tokens = cloneMap(st.sess.Tokens)
	return &cp
}

// ---- sending ----

func sameOrigin(a, b *url.URL) bool {
	if b.User != nil || !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return portOf(a) == portOf(b)
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// Do sends the request with the session's credentials and returns the scrubbed answer.
func (p *Proxy) Do(ctx context.Context, sess *site.Session, r Request) (*Result, error) {
	if sess == nil {
		return nil, invalid("there is no session to use")
	}
	if !sess.ExpiresAt.IsZero() && !time.Now().Before(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	if p.HC == nil {
		return nil, errors.New("proxy: no HTTP client")
	}
	pr, err := p.prepare(sess, r)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout(r))
	defer cancel()
	client := *p.HC
	client.Timeout = 0 // the context carries the deadline: an agent may ask for longer than the client's default
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	st := &state{sess: sess, cookies: cloneCookies(sess.Cookies), secrets: secretsOf(sess)}
	origin, method, u, body, hdr := pr.url, pr.method, pr.url, pr.body, pr.header
	for hop := 0; ; hop++ {
		resp, err := p.send(ctx, &client, st, method, u, hdr, body)
		if err != nil {
			return nil, err
		}
		st.apply(resp.Cookies(), u.Hostname(), time.Now())
		next, nmethod, nbody := p.follow(r, resp, u, origin, method, body)
		if next == nil {
			return p.finish(resp, st, u)
		}
		if hop >= maxRedirects {
			resp.Body.Close()
			return nil, fmt.Errorf("%w: stopped after %d", ErrTooManyRedirects, maxRedirects)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if nmethod != method {
			hdr = hdr.Clone()
			hdr.Del("Content-Type")
		}
		method, u, body = nmethod, next, nbody
	}
}

// follow decides whether to follow a redirect. It returns the next URL (nil: do not follow), the method and the body.
func (p *Proxy) follow(r Request, resp *http.Response, cur, origin *url.URL, method string, body []byte) (*url.URL, string, []byte) {
	if !r.FollowRedirects {
		return nil, "", nil
	}
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
	default:
		return nil, "", nil
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, "", nil
	}
	next, err := cur.Parse(loc)
	if err != nil || !sameOrigin(origin, next) {
		return nil, "", nil
	}
	next.Fragment = ""
	if resp.StatusCode == 307 || resp.StatusCode == 308 {
		return next, method, body
	}
	if method != "HEAD" {
		method = "GET"
	}
	return next, method, nil
}

func (p *Proxy) send(ctx context.Context, client *http.Client, st *state, method string, u *url.URL, agent http.Header, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, invalid("the request could not be built")
	}
	for k, vs := range agent {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for k, v := range st.sess.Headers {
		req.Header.Set(k, v)
	}
	if c := selectCookies(st.cookies, u, time.Now()); c != "" {
		req.Header.Set("Cookie", c)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			err = ue.Err // net/http copies the whole URL into its error, query string included
		}
		msg, _ := redact.New(st.secrets).Text(err.Error())
		return nil, fmt.Errorf("%w: %s", ErrUnreachable, msg)
	}
	return resp, nil
}

// finish reads and scrubs the final response.
func (p *Proxy) finish(resp *http.Response, st *state, u *url.URL) (*Result, error) {
	defer resp.Body.Close()
	scrub := redact.New(st.secrets)
	max := p.maxResponse()
	limit := max + scrub.Longest() // read past the limit so that a secret the limit would cut in half is still found whole
	var buf []byte
	total, more := 0, false
	if resp.Request == nil || resp.Request.Method != "HEAD" {
		var err error
		buf, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
		if err != nil {
			msg, _ := scrub.Text(err.Error())
			return nil, fmt.Errorf("%w: reading the answer failed: %s", ErrUnreachable, msg)
		}
		total = len(buf) // everything read, including the one byte past the limit that showed there was more
		if more = len(buf) > limit; more {
			buf = buf[:limit]
			n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
			total += int(n)
		}
	}
	hdr, hn := scrub.Header(resp.Header)
	res := &Result{Status: resp.StatusCode, Headers: hdr, Redactions: hn, TotalBytes: total, NewSession: st.newSession()}
	if u != nil {
		res.FinalPath = u.Path
	}
	if more {
		buf = trimPartialRune(buf)
	}
	switch {
	case len(buf) == 0:
	case redact.IsText(buf):
		out, n := scrub.Text(string(buf))
		res.Redactions += n
		res.Body = cutUTF8(out, max)
		res.Truncated = more || len(out) > max
	case scrub.BinaryLeaks(buf):
		res.Withheld = true
	default:
		if len(buf) > max {
			buf = buf[:max]
			res.Truncated = true
		}
		res.Truncated = res.Truncated || more
		res.Body, res.BodyIsBase64 = base64.StdEncoding.EncodeToString(buf), true
	}
	return res, nil
}

// trimPartialRune removes a UTF-8 sequence that the read limit cut short, so that the text is not mistaken for binary.
func trimPartialRune(b []byte) []byte {
	for j := len(b) - 1; j >= 0 && j >= len(b)-4; j-- {
		if utf8.RuneStart(b[j]) {
			if !utf8.FullRune(b[j:]) {
				return b[:j]
			}
			return b
		}
	}
	return b
}

// cutUTF8 shortens s to at most max bytes without splitting a character.
func cutUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
