package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/netguard"
	"github.com/LeafAI/securl/internal/site"
)

const (
	cookieVal = "COOKIE-VALUE-0123456789abcdef"
	bearerVal = "BEARER-VALUE-fedcba9876543210"
	csrfVal   = "CSRF-VALUE-aaaabbbbccccdddd"
)

func session() *site.Session {
	return &site.Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: cookieVal, Path: "/"}},
		Headers: map[string]string{"Authorization": "Bearer " + bearerVal, "X-CSRFToken": csrfVal},
		Tokens:  map[string]string{"api": "rest"},
	}
}

// seen is what the server behind the proxy received.
type seen struct {
	mu   sync.Mutex
	reqs []*recorded
}

type recorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

func (s *seen) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.reqs = append(s.reqs, &recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
	s.mu.Unlock()
}

func (s *seen) last() *recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return nil
	}
	return s.reqs[len(s.reqs)-1]
}

func (s *seen) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.reqs) }

func newProxy(t *testing.T, h http.Handler) (*Proxy, *url.URL, *seen) {
	t.Helper()
	sn := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the recorder reads the body, so the handler gets a fresh copy of it
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		sn.add(r)
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	hc := netguard.New(netguard.Policy{AllowLocal: true, Timeout: 5 * time.Second})
	return &Proxy{HC: hc}, base, sn
}

func req(base *url.URL, method, path string) Request {
	return Request{Base: base, Method: method, Path: path}
}

func echo(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"cookie": r.Header.Get("Cookie"), "auth": r.Header.Get("Authorization"),
		"csrf": r.Header.Get("X-CSRFToken"), "body": string(b), "path": r.URL.Path, "query": r.URL.RawQuery})
}

func TestTheSessionsCredentialsAreInjectedAndNeverComeBack(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/api/me"))
	if err != nil {
		t.Fatal(err)
	}
	got := sn.last()
	if !strings.Contains(got.Header.Get("Cookie"), "sid="+cookieVal) {
		t.Errorf("the cookie must be sent: %q", got.Header.Get("Cookie"))
	}
	if got.Header.Get("Authorization") != "Bearer "+bearerVal {
		t.Errorf("the bearer token must be sent: %q", got.Header.Get("Authorization"))
	}
	if got.Header.Get("X-CSRFToken") != csrfVal {
		t.Errorf("the session's own headers must be sent: %q", got.Header.Get("X-CSRFToken"))
	}
	for _, secret := range []string{cookieVal, bearerVal} {
		if strings.Contains(res.Body, secret) {
			t.Errorf("the response echoed %q back to the agent: %s", secret, res.Body)
		}
	}
	if res.Status != 200 || res.Redactions == 0 {
		t.Errorf("status and the number of values removed must be reported: %+v", res)
	}
}

func TestTheAgentCannotSetCredentialHeaders(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	for _, h := range []string{"Cookie", "cookie", "Authorization", "AUTHORIZATION", "Proxy-Authorization", "X-CSRFToken", "x-csrftoken",
		"Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "TE", "Expect", "Accept-Encoding", "Trailer", "Keep-Alive"} {
		r := req(base, "GET", "/api/me")
		r.Headers = map[string]string{h: "agent-supplied-value"}
		before := sn.count()
		_, err := p.Do(context.Background(), session(), r)
		if err == nil {
			t.Errorf("header %q set by the agent must be refused", h)
		}
		if sn.count() != before {
			t.Errorf("header %q: nothing may be sent when the request is refused", h)
		}
	}
}

func TestAnAgentHeaderWithALineBreakIsRefused(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	for name, h := range map[string]map[string]string{
		"value":  {"X-Note": "a\r\nCookie: evil=1"},
		"value2": {"X-Note": "a\nb"},
		"name":   {"X-Note\r\nCookie": "evil=1"},
		"nul":    {"X-Note": "a\x00b"},
		"empty":  {"": "x"},
		"space":  {"X Note": "x"},
	} {
		r := req(base, "GET", "/x")
		r.Headers = h
		if _, err := p.Do(context.Background(), session(), r); err == nil {
			t.Errorf("%s: a header that could split the request must be refused", name)
		}
	}
	if sn.count() != 0 {
		t.Error("nothing is sent")
	}
}

func TestOrdinaryAgentHeadersPassThrough(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	r := req(base, "GET", "/x")
	r.Headers = map[string]string{"Accept": "application/json", "X-Request-Id": "abc-123", "If-None-Match": `"v1"`}
	if _, err := p.Do(context.Background(), session(), r); err != nil {
		t.Fatal(err)
	}
	g := sn.last().Header
	if g.Get("Accept") != "application/json" || g.Get("X-Request-Id") != "abc-123" || g.Get("If-None-Match") != `"v1"` {
		t.Errorf("%v", g)
	}
}

func TestSessionHeaderNamesAreProtectedWhateverTheyAre(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(echo))
	sess := &site.Session{Headers: map[string]string{"X-Custom-Auth-Token": "secret-header-value-1234"}}
	r := req(base, "GET", "/x")
	r.Headers = map[string]string{"x-custom-auth-token": "agent-value"}
	if _, err := p.Do(context.Background(), sess, r); err == nil {
		t.Error("a header the session sets is the session's, whatever it is called")
	}
}

func TestOnlyTheSessionsOwnSiteIsReachable(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	other := httptest.NewServer(http.HandlerFunc(echo))
	defer other.Close()
	for name, path := range map[string]string{
		"absolute other host": other.URL + "/x",
		"scheme relative":     "//" + strings.TrimPrefix(other.URL, "http://") + "/x",
		"userinfo trick":      "http://" + strings.TrimPrefix(base.String(), "http://") + "@" + strings.TrimPrefix(other.URL, "http://") + "/x",
		"backslash":           `\\` + strings.TrimPrefix(other.URL, "http://") + `/x`,
		"no leading slash":    "x/y",
		"empty":               "",
		"fragment":            "/x#frag",
		"control char":        "/x\ny",
		"space":               "/a b",
		"dot dot out of root": "/../../etc/passwd",
	} {
		before := sn.count()
		res, err := p.Do(context.Background(), session(), req(base, "GET", path))
		if err == nil && (strings.Contains(res.Body, "evil") || sn.count() != before+1) {
			t.Errorf("%s: %q reached something other than the site", name, path)
		}
		if err == nil && sn.count() == before {
			t.Errorf("%s: a request that went nowhere must be an error", name)
		}
	}
	if sn.count() > 0 {
		for _, r := range sn.reqs {
			if strings.Contains(r.Path, "//") && strings.Contains(r.Header.Get("Cookie"), cookieVal) && r.Path == "" {
				t.Errorf("%+v", r)
			}
		}
	}
}

func TestAnAbsolutePathIsTheOnlyAcceptedForm(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	for _, ok := range []string{"/", "/a", "/a/b.json", "/a%20b", "/a;b", "/a:b", "/~u/x", "/a,b"} {
		if _, err := p.Do(context.Background(), session(), req(base, "GET", ok)); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
	if sn.count() != 8 {
		t.Errorf("%d", sn.count())
	}
}

func TestTheQueryIsBuiltByTheProxyAndEncoded(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	r := req(base, "GET", "/search")
	r.Query = map[string][]string{"q": {"a b&c=d"}, "n": {"1", "2"}}
	if _, err := p.Do(context.Background(), session(), r); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(sn.last().Query)
	if q.Get("q") != "a b&c=d" || len(q["n"]) != 2 {
		t.Errorf("%q", sn.last().Query)
	}
	// a path that carries its own query is refused: two places for one thing is how a request gets smuggled
	r = req(base, "GET", "/search?x=1")
	if _, err := p.Do(context.Background(), session(), r); err == nil {
		t.Error("a query in the path must be refused: use the query field")
	}
}

func TestMethodsAreAllowListed(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "get", "Post"} {
		if _, err := p.Do(context.Background(), session(), req(base, m, "/x")); err != nil {
			t.Errorf("%s must be allowed: %v", m, err)
		}
	}
	before := sn.count()
	for _, m := range []string{"CONNECT", "TRACE", "PROPFIND", "", "GET /x HTTP/1.1\r\nHost: evil\r\n\r\nGET", "G ET", "BREW"} {
		if _, err := p.Do(context.Background(), session(), req(base, m, "/x")); err == nil {
			t.Errorf("method %q must be refused", m)
		}
	}
	if sn.count() != before {
		t.Error("nothing is sent for a refused method")
	}
}

func TestBodyFormsAndTheirContentTypes(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	cases := map[string]struct {
		r    Request
		body string
		ct   string
	}{
		"json":   {Request{Method: "POST", Path: "/j", JSON: json.RawMessage(`{"a":1}`)}, `{"a":1}`, "application/json"},
		"form":   {Request{Method: "POST", Path: "/f", Form: map[string][]string{"a": {"1 2"}, "b": {"x"}}}, "a=1+2&b=x", "application/x-www-form-urlencoded"},
		"text":   {Request{Method: "POST", Path: "/t", Text: "plain body"}, "plain body", "text/plain; charset=utf-8"},
		"base64": {Request{Method: "PUT", Path: "/b", Base64: base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 0xff})}, "\x00\x01\x02\xff", "application/octet-stream"},
	}
	for name, c := range cases {
		c.r.Base = base
		if _, err := p.Do(context.Background(), session(), c.r); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		g := sn.last()
		if g.Body != c.body {
			t.Errorf("%s: body %q, want %q", name, g.Body, c.body)
		}
		if g.Header.Get("Content-Type") != c.ct {
			t.Errorf("%s: content type %q, want %q", name, g.Header.Get("Content-Type"), c.ct)
		}
	}
}

func TestTheAgentsContentTypeWinsOverTheDefault(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	r := Request{Base: base, Method: "POST", Path: "/x", JSON: json.RawMessage(`{}`), Headers: map[string]string{"Content-Type": "application/vnd.api+json"}}
	if _, err := p.Do(context.Background(), session(), r); err != nil {
		t.Fatal(err)
	}
	if sn.last().Header.Get("Content-Type") != "application/vnd.api+json" {
		t.Errorf("%v", sn.last().Header)
	}
}

func TestOnlyOneBodyFormAtATime(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	r := Request{Base: base, Method: "POST", Path: "/x", JSON: json.RawMessage(`{}`), Text: "x"}
	if _, err := p.Do(context.Background(), session(), r); err == nil {
		t.Error("two bodies are ambiguous")
	}
	r = Request{Base: base, Method: "POST", Path: "/x", JSON: json.RawMessage(`{not json`)}
	if _, err := p.Do(context.Background(), session(), r); err == nil {
		t.Error("invalid JSON is refused before it is sent")
	}
	r = Request{Base: base, Method: "POST", Path: "/x", Base64: "!!!not base64"}
	if _, err := p.Do(context.Background(), session(), r); err == nil {
		t.Error("invalid base64 is refused")
	}
	r = Request{Base: base, Method: "GET", Path: "/x", Text: "a body on a GET"}
	if _, err := p.Do(context.Background(), session(), r); err == nil {
		t.Error("a GET with a body is refused: servers and caches disagree about what it means")
	}
	if sn.count() != 0 {
		t.Error("nothing is sent")
	}
}

func TestRequestBodySizeIsBounded(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	p.MaxRequestBytes = 1000
	r := Request{Base: base, Method: "POST", Path: "/x", Text: strings.Repeat("a", 1001)}
	if _, err := p.Do(context.Background(), session(), r); err == nil {
		t.Error("an oversized body is refused")
	}
	r.Text = strings.Repeat("a", 1000)
	if _, err := p.Do(context.Background(), session(), r); err != nil {
		t.Errorf("a body at the limit is fine: %v", err)
	}
	if sn.count() != 1 {
		t.Errorf("%d", sn.count())
	}
}

func TestSetCookieIsNeverShownAndRotatedValuesAreCollected(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ROTATED-sid-value-777777", Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "extra", Value: "EXTRA-cookie-value-9999", Path: "/"})
		w.Write([]byte("ok"))
	}))
	sess := session()
	res, err := p.Do(context.Background(), sess, req(base, "GET", "/x"))
	if err != nil {
		t.Fatal(err)
	}
	for k := range res.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			t.Error("Set-Cookie must never reach the agent")
		}
	}
	if res.NewSession == nil {
		t.Fatal("the server rotated the cookie: the caller must get the updated session to keep")
	}
	vals := map[string]string{}
	for _, c := range res.NewSession.Cookies {
		vals[c.Name] = c.Value
	}
	if vals["sid"] != "ROTATED-sid-value-777777" || vals["extra"] != "EXTRA-cookie-value-9999" {
		t.Errorf("%v", vals)
	}
	if sess.Cookies[0].Value != cookieVal {
		t.Error("the session that was passed in must not be modified: the caller decides whether to keep the new one")
	}
	if res.NewSession.Headers["X-CSRFToken"] != csrfVal || res.NewSession.Tokens["api"] != "rest" {
		t.Errorf("the rest of the session carries over: %+v", res.NewSession)
	}
}

func TestADeletedCookieIsRemovedFromTheNewSession(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/logout"))
	if err != nil {
		t.Fatal(err)
	}
	if res.NewSession == nil {
		t.Fatal("a change must be reported")
	}
	for _, c := range res.NewSession.Cookies {
		if c.Name == "sid" {
			t.Errorf("the server expired the cookie: %+v", c)
		}
	}
}

func TestNoNewSessionWhenNothingChanged(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(echo))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/x"))
	if err != nil {
		t.Fatal(err)
	}
	if res.NewSession != nil {
		t.Error("an unchanged session is not re-stored")
	}
}

func TestEveryEncodingOfACredentialIsRemovedFromTheBody(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := r.Header.Get("Cookie")
		v := strings.TrimPrefix(c, "sid=")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>" + v + "</p><a href='?sid=" + url.QueryEscape(v) + "'>x</a><code>" +
			base64.StdEncoding.EncodeToString([]byte(v)) + "</code><i>" + strings.ToLower(v) + "</i>"))
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/debug"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{cookieVal, url.QueryEscape(cookieVal), base64.StdEncoding.EncodeToString([]byte(cookieVal)), strings.ToLower(cookieVal)} {
		if strings.Contains(res.Body, leak) {
			t.Errorf("%q leaked: %s", leak, res.Body)
		}
	}
	if res.Redactions < 4 {
		t.Errorf("four values were removed, the count says %d", res.Redactions)
	}
}

func TestCredentialsInResponseHeadersAreRemoved(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location-Debug", "go to /x?t="+bearerVal)
		w.Header().Set("X-Echo-Cookie", r.Header.Get("Cookie"))
		w.Header().Set("Www-Authenticate", `Bearer realm="x"`)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/x"))
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range res.Headers {
		for _, v := range vs {
			if strings.Contains(v, bearerVal) || strings.Contains(v, cookieVal) {
				t.Errorf("header %s leaks: %q", k, v)
			}
		}
	}
	if res.Headers["Content-Type"] == nil {
		t.Errorf("ordinary headers are kept: %v", res.Headers)
	}
}

func TestResponseSizeIsBoundedAndTheCutIsReported(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	p.MaxResponseBytes = 1000
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/big"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Body) > 1000 || !res.Truncated {
		t.Errorf("body %d bytes, truncated=%v", len(res.Body), res.Truncated)
	}
	if res.TotalBytes != 5000 {
		t.Errorf("the size reported to the agent must be the real one: %d, want 5000", res.TotalBytes)
	}
}

// A secret that straddles the limit would be cut in half, and neither half matches the scrubber. The proxy reads past
// the limit by the length of the longest secret, scrubs, and only then cuts.
func TestASecretCutInHalfByTheLimitIsStillRemoved(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Repeat("x", 990) + r.Header.Get("Cookie") + strings.Repeat("y", 500)))
	}))
	p.MaxResponseBytes = 1000 // the cookie value starts at byte 994 and runs past the limit
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/straddle"))
	if err != nil {
		t.Fatal(err)
	}
	// the value starts at byte 994, so without the read-ahead only its first six characters fit under the limit
	if strings.Contains(res.Body, "COOKIE") {
		t.Errorf("part of the secret leaked at the cut: %q", res.Body[900:])
	}
	if !res.Truncated || len(res.Body) > 1000 {
		t.Errorf("truncated=%v, %d bytes", res.Truncated, len(res.Body))
	}
}

func TestBinaryResponsesAreReturnedAsBase64WhenTheyAreClean(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d}
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/logo.png"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.BodyIsBase64 || res.Body != base64.StdEncoding.EncodeToString(png) {
		t.Errorf("%+v", res)
	}
}

// Replacement inside a binary format corrupts it, so a binary body that holds a credential is not returned at all.
func TestABinaryResponseThatHoldsACredentialIsWithheld(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(append([]byte{0, 1, 2, 0xff}, []byte(r.Header.Get("Cookie"))...))
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/dump"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Body != "" || !res.Withheld {
		t.Errorf("a binary body with a credential in it must be withheld, not returned: %+v", res)
	}
	if res.Status != 200 {
		t.Errorf("the status is still told: %d", res.Status)
	}
}

func TestRedirectsAreNotFollowedByDefaultAndTheLocationIsShown(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", 302)
			return
		}
		w.Write([]byte("new"))
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/old"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 302 || res.Headers["Location"] == nil || res.Headers["Location"][0] != "/new" {
		t.Errorf("%+v", res)
	}
	if sn.count() != 1 {
		t.Errorf("the redirect must not be followed unless asked: %d requests", sn.count())
	}
}

func TestSameSiteRedirectsAreFollowedWhenAskedAndKeepTheCredentials(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", 302)
			return
		}
		echo(w, r)
	}))
	r := req(base, "GET", "/old")
	r.FollowRedirects = true
	res, err := p.Do(context.Background(), session(), r)
	if err != nil {
		t.Fatal(err)
	}
	if sn.count() != 2 || sn.last().Path != "/new" {
		t.Fatalf("%d requests, last %+v", sn.count(), sn.last())
	}
	if !strings.Contains(sn.last().Header.Get("Cookie"), cookieVal) {
		t.Error("the follow-up on the same site carries the session")
	}
	if strings.Contains(res.Body, cookieVal) {
		t.Errorf("%s", res.Body)
	}
}

func TestRedirectsToAnotherSiteAreNeverFollowedAndNeverCarryCredentials(t *testing.T) {
	other := &seen{}
	otherSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.add(r) }))
	defer otherSrv.Close()
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherSrv.URL+"/collect", 307)
	}))
	r := Request{Base: base, Method: "POST", Path: "/login", Text: "x=1", FollowRedirects: true}
	res, err := p.Do(context.Background(), session(), r)
	if err != nil {
		t.Fatal(err)
	}
	if other.count() != 0 {
		t.Fatalf("a redirect to another origin was followed: %+v", other.last())
	}
	if res.Status != 307 {
		t.Errorf("the redirect is returned to the agent instead: %d", res.Status)
	}
}

func TestSameSiteRedirectKeepsTheMethodAndBodyFor307And308Only(t *testing.T) {
	for code, wantMethod := range map[int]string{301: "GET", 302: "GET", 303: "GET", 307: "POST", 308: "POST"} {
		p, base, sn := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/a" {
				http.Redirect(w, r, "/b", code)
				return
			}
			w.Write([]byte("done"))
		}))
		r := Request{Base: base, Method: "POST", Path: "/a", Text: "payload", FollowRedirects: true}
		if _, err := p.Do(context.Background(), session(), r); err != nil {
			t.Fatal(err)
		}
		last := sn.last()
		if last.Method != wantMethod {
			t.Errorf("%d: the follow-up is a %s, want %s", code, last.Method, wantMethod)
		}
		if (wantMethod == "POST") != (last.Body == "payload") {
			t.Errorf("%d: body %q", code, last.Body)
		}
	}
}

func TestRedirectLoopsAreStopped(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", 302) }))
	r := req(base, "GET", "/loop")
	r.FollowRedirects = true
	res, err := p.Do(context.Background(), session(), r)
	if err != nil && !strings.Contains(err.Error(), "redirect") {
		t.Fatal(err)
	}
	if sn.count() > 12 {
		t.Errorf("the redirect chain must be bounded: %d requests", sn.count())
	}
	_ = res
}

func TestADowngradeToHTTPIsNotFollowed(t *testing.T) {
	// the only way to test this without TLS is the rule itself
	from, _ := url.Parse("https://site.example/a")
	for to, want := range map[string]bool{
		"https://site.example/b": true, "https://site.example:443/b": true, "/b": true,
		"http://site.example/b": false, "https://other.example/b": false, "https://site.example:8443/b": false,
		"https://SITE.example/b": true, "//site.example/b": true, "//evil.example/b": false,
		"https://site.example.evil.com/b": false, "https://site.example@evil.com/b": false,
	} {
		toURL, _ := from.Parse(to)
		if got := sameOrigin(from, toURL); got != want {
			t.Errorf("%s -> %s: same origin = %v, want %v", from, to, got, want)
		}
	}
}

func TestATransportErrorNeverShowsTheURLOrAnyCredential(t *testing.T) {
	p := &Proxy{HC: netguard.New(netguard.Policy{AllowLocal: true, Timeout: time.Second})}
	base, _ := url.Parse("http://127.0.0.1:1")
	r := req(base, "GET", "/secret/path")
	r.Query = map[string][]string{"token": {"QUERYSECRET-abcdef"}}
	_, err := p.Do(context.Background(), session(), r)
	if err == nil {
		t.Fatal("nothing listens there")
	}
	for _, bad := range []string{"QUERYSECRET", cookieVal, bearerVal, "/secret/path"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the error leaks %q: %v", bad, err)
		}
	}
}

func TestTimeoutIsReportedAndBounded(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	r := req(base, "GET", "/slow")
	r.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := p.Do(context.Background(), session(), r)
	if err == nil {
		t.Fatal("must time out")
	}
	if time.Since(start) > time.Second {
		t.Errorf("the timeout was not honoured: %v", time.Since(start))
	}
	r.Timeout = time.Hour
	if got := p.timeout(r); got > p.maxTimeout() {
		t.Errorf("an agent cannot ask for more than the cap: %v", got)
	}
}

func TestContextCancellationStopsTheRequest(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := p.Do(ctx, session(), req(base, "GET", "/slow")); err == nil {
		t.Fatal("cancelled")
	}
	if time.Since(start) > time.Second {
		t.Error("slow")
	}
}

func TestCookieAttributesDecideWhichCookiesAreSent(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	sess := &site.Session{Cookies: []*http.Cookie{
		{Name: "all", Value: "ALL-cookie-value-1111", Path: "/"},
		{Name: "app", Value: "APP-cookie-value-2222", Path: "/app"},
		{Name: "gone", Value: "GONE-cookie-value-3333", Path: "/", Expires: time.Now().Add(-time.Hour)},
		{Name: "elsewhere", Value: "ELSE-cookie-value-4444", Path: "/", Domain: "other.example"},
	}}
	if _, err := p.Do(context.Background(), sess, req(base, "GET", "/")); err != nil {
		t.Fatal(err)
	}
	c := sn.last().Header.Get("Cookie")
	if !strings.Contains(c, "all=") || strings.Contains(c, "app=") || strings.Contains(c, "gone=") {
		t.Errorf("path and expiry apply: %q", c)
	}
	if strings.Contains(c, "elsewhere=") {
		t.Errorf("a cookie for another domain is not ours to send: %q", c)
	}
	if _, err := p.Do(context.Background(), sess, req(base, "GET", "/app/x")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sn.last().Header.Get("Cookie"), "app=") {
		t.Errorf("%q", sn.last().Header.Get("Cookie"))
	}
}

func TestSecureCookiesAreNotSentOverPlainHTTP(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo)) // the test server is plain http
	sess := &site.Session{Cookies: []*http.Cookie{{Name: "sec", Value: "SECURE-cookie-value-5555", Path: "/", Secure: true}, {Name: "plain", Value: "PLAIN-cookie-value-6666", Path: "/"}}}
	if _, err := p.Do(context.Background(), sess, req(base, "GET", "/")); err != nil {
		t.Fatal(err)
	}
	c := sn.last().Header.Get("Cookie")
	if strings.Contains(c, "sec=") || !strings.Contains(c, "plain=") {
		t.Errorf("a Secure cookie must not travel over http: %q", c)
	}
}

func TestAnExpiredSessionIsRefusedBeforeAnythingIsSent(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	sess := session()
	sess.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := p.Do(context.Background(), sess, req(base, "GET", "/x")); err == nil {
		t.Error("an expired session must not be used")
	}
	if sn.count() != 0 {
		t.Error("nothing sent")
	}
}

func TestAnEmptySessionIsRefused(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(echo))
	if _, err := p.Do(context.Background(), nil, req(base, "GET", "/x")); err == nil {
		t.Error("no session")
	}
}

func TestASessionWithNoCredentialsStillWorksForASiteWithoutLogin(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	sess := &site.Session{Tokens: map[string]string{"auth": "none"}}
	if _, err := p.Do(context.Background(), sess, req(base, "GET", "/x")); err != nil {
		t.Fatalf("a site that needs no login has nothing to inject, and must still be reachable: %v", err)
	}
	if sn.last().Header.Get("Cookie") != "" || sn.last().Header.Get("Authorization") != "" {
		t.Errorf("%v", sn.last().Header)
	}
}

func TestTheSessionsTokensAreNotSentAsHeaders(t *testing.T) {
	p, base, sn := newProxy(t, http.HandlerFunc(echo))
	sess := &site.Session{Tokens: map[string]string{"api": "rest", "identity_provider": "ldap", "crumb": "CRUMB-VALUE-abcdef12"}, Cookies: session().Cookies}
	if _, err := p.Do(context.Background(), sess, req(base, "GET", "/x")); err != nil {
		t.Fatal(err)
	}
	for k, v := range sn.last().Header {
		for _, x := range v {
			if strings.Contains(x, "CRUMB-VALUE") {
				t.Errorf("Tokens are driver state, not headers: %s: %s", k, x)
			}
		}
	}
}

func TestTheTokenValuesAreScrubbedTooBecauseTheyAreSecrets(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"crumb":"CRUMB-VALUE-abcdef12","also":"` + r.Header.Get("Cookie") + `"}`))
	}))
	sess := &site.Session{Tokens: map[string]string{"crumb": "CRUMB-VALUE-abcdef12"}, Cookies: session().Cookies}
	res, err := p.Do(context.Background(), sess, req(base, "GET", "/x"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Body, "CRUMB-VALUE") || strings.Contains(res.Body, cookieVal) {
		t.Errorf("%s", res.Body)
	}
}

func TestSecretsComeFromEveryPlaceTheSessionKeepsThem(t *testing.T) {
	got := secretsOf(session())
	want := []string{cookieVal, "Bearer " + bearerVal, bearerVal, csrfVal}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not among the secrets: %q", w, got)
		}
	}
}

func TestTheAuthorizationSchemeWordAloneIsNotASecret(t *testing.T) {
	for _, g := range secretsOf(session()) {
		if g == "Bearer" || g == "Basic" {
			t.Errorf("%q would be replaced in every ordinary sentence", g)
		}
	}
}

func TestResultIsPlainDataWithNoSecretFields(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(echo))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	for _, secret := range []string{cookieVal, bearerVal, csrfVal} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the serialised result carries %q: %s", secret, b)
		}
	}
	if strings.Contains(string(b), "NewSession") || strings.Contains(string(b), "new_session") {
		t.Errorf("the updated session is for the caller, never for the agent: %s", b)
	}
}

func TestTotalBytesIsExactAtAndAroundTheLimit(t *testing.T) {
	for _, size := range []int{0, 1, 999, 1000, 1001, 1002, 3000} {
		body := strings.Repeat("a", size)
		p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(body))
		}))
		p.MaxResponseBytes = 1000
		res, err := p.Do(context.Background(), session(), req(base, "GET", "/n"))
		if err != nil {
			t.Fatal(err)
		}
		if res.TotalBytes != size {
			t.Errorf("size %d: total reported %d", size, res.TotalBytes)
		}
		if want := size > 1000; res.Truncated != want {
			t.Errorf("size %d: truncated=%v, want %v", size, res.Truncated, want)
		}
		if len(res.Body) > 1000 {
			t.Errorf("size %d: body of %d bytes exceeds the limit", size, len(res.Body))
		}
	}
}

// ---- the validators, tested directly: Go's own transport also refuses malformed paths and headers, so a test that only
// sees "the request failed" cannot tell whether OUR check did it. These assert that the refusal is ErrInvalid, i.e. that
// it happened before anything was built or sent.

func TestCheckPathRefusesBeforeAnythingIsSent(t *testing.T) {
	for name, p := range map[string]string{
		"empty": "", "relative": "x/y", "other host": "//evil.example/x", "query": "/a?b=1", "fragment": "/a#b",
		"bad escape": "/a%zz", "short escape": "/a%2", "trailing percent": "/a%", "space": "/a b", "quote": `/a"b`, "angle": "/a<b",
		"backslash": `/a\b`, "encoded NUL": "/a%00", "encoded newline": "/a%0a", "encoded CRLF": "/%0d%0a",
		"encoded backslash": "/a%5cb", "dot dot": "/../x", "inner dot dot": "/a/../b", "encoded dot dot": "/a/%2e%2e/b",
		"trailing dot dot": "/a/..", "unicode": "/caf\u00e9", "tab": "/a\tb", "DEL": "/a\x7fb",
	} {
		if _, err := checkPath(p); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %q must be refused as invalid, got %v", name, p, err)
		}
	}
	for _, ok := range []string{"/", "/a", "/a/b.json", "/a%20b", "/a;b", "/a:b", "/~u/x", "/a,b", "/..hidden", "/a..b", "/.well-known/x", "/a/./b", "/a%2fb", "/@user", "/a=b&c"} {
		if _, err := checkPath(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
}

func TestAgentHeadersRefuseWithAnInvalidRequestError(t *testing.T) {
	sess := &site.Session{} // no headers of its own: only the fixed list can be what refuses these
	for _, h := range []string{"Cookie", "Authorization", "Proxy-Authorization", "Host", "Content-Length", "Transfer-Encoding",
		"Connection", "Proxy-Connection", "Upgrade", "TE", "Expect", "Accept-Encoding", "Trailer", "Keep-Alive", "cOoKiE", "authorization"} {
		if _, err := agentHeaders(map[string]string{h: "v"}, sess); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s must be refused as invalid: %v", h, err)
		}
	}
	for name, in := range map[string]map[string]string{
		"CRLF in value": {"X-A": "a\r\nCookie: x"}, "LF in value": {"X-A": "a\nb"}, "NUL in value": {"X-A": "a\x00b"},
		"DEL in value": {"X-A": "a\x7fb"}, "CRLF in name": {"X-A\r\nB": "v"}, "space in name": {"X A": "v"}, "empty name": {"": "v"},
		"colon in name": {"X:A": "v"}, "non-ascii name": {"X-\u00e9": "v"}, "huge value": {"X-A": strings.Repeat("a", maxHeaderBytes+1)},
	} {
		if _, err := agentHeaders(in, sess); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s must be refused as invalid: %v", name, err)
		}
	}
	if _, err := agentHeaders(map[string]string{"X-Tab": "a\tb", "X-A": strings.Repeat("a", maxHeaderBytes)}, sess); err != nil {
		t.Errorf("a tab inside a value and a value at the limit are fine: %v", err)
	}
}

func TestTooManyHeadersAreRefused(t *testing.T) {
	in := map[string]string{}
	for i := 0; i < maxHeaders; i++ {
		in["X-H"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('A'+i/26))] = "v"
	}
	if len(in) != maxHeaders {
		t.Fatalf("test setup: %d headers", len(in))
	}
	if _, err := agentHeaders(in, &site.Session{}); err != nil {
		t.Errorf("exactly the limit is fine: %v", err)
	}
	in["X-One-More"] = "v"
	if _, err := agentHeaders(in, &site.Session{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("one more is refused: %v", err)
	}
}

func TestAHeaderTheSessionSetsIsRefusedInAnyCase(t *testing.T) {
	sess := &site.Session{Headers: map[string]string{"X-Custom-Auth": "v"}}
	for _, name := range []string{"X-Custom-Auth", "x-custom-auth", "X-CUSTOM-AUTH"} {
		if _, err := agentHeaders(map[string]string{name: "agent"}, sess); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDomainMatchingFollowsTheCookieRules(t *testing.T) {
	for _, c := range []struct {
		host, domain string
		want         bool
	}{
		{"site.example", "site.example", true}, {"a.site.example", "site.example", true}, {"a.site.example", ".site.example", true},
		{"SITE.example", "site.EXAMPLE", true}, {"site.example", "a.site.example", false}, {"evilsite.example", "site.example", false},
		{"site.example.evil.com", "site.example", false}, {"x.y.site.example", "site.example", true},
		// an address is matched whole, never by a suffix: 10.0.0.1 is not a subdomain of 0.0.1
		{"10.0.0.1", "0.0.1", false}, {"10.0.0.1", "10.0.0.1", true}, {"192.168.1.5", "1.5", false},
		{"[::1]", "::1", false}, {"::1", "::1", true},
	} {
		if got := domainMatch(c.host, c.domain); got != c.want {
			t.Errorf("domainMatch(%q, %q) = %v, want %v", c.host, c.domain, got, c.want)
		}
	}
}

func TestSameOriginIsStrict(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://s.example:8443/a", "https://s.example:8443/b", true},
		{"https://s.example:8443/a", "http://s.example:8443/b", false}, // the scheme differs while host and port are identical
		{"http://s.example:8080/a", "https://s.example:8080/b", false},
		{"https://s.example/a", "https://user@s.example/b", false}, // userinfo on the same host
		{"https://s.example/a", "https://user:pw@s.example/b", false},
		{"https://s.example/a", "https://s.example:444/b", false},
		{"https://s.example/a", "https://S.EXAMPLE/b", true}, {"https://s.example/a", "HTTPS://s.example/b", true},
		{"https://s.example/a", "https://s.example:443/b", true}, {"http://s.example/a", "http://s.example:80/b", true},
		{"https://s.example/a", "https://t.example/b", false}, {"https://s.example/a", "https://s.example.evil/b", false},
	} {
		a, _ := url.Parse(c.a)
		b, _ := url.Parse(c.b)
		if got := sameOrigin(a, b); got != c.want {
			t.Errorf("sameOrigin(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// failingTransport fails with an error that repeats what it was given, the way a misbehaving proxy or middleware does.
type failingTransport struct{}

func (failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("upstream rejected the request carrying " + r.Header.Get("Cookie") + " and " + r.Header.Get("Authorization"))
}

func TestATransportErrorIsScrubbedOfTheCredentialsItQuotes(t *testing.T) {
	p := &Proxy{HC: &http.Client{Transport: failingTransport{}}}
	base, _ := url.Parse("http://site.example")
	_, err := p.Do(context.Background(), session(), req(base, "GET", "/x"))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{cookieVal, bearerVal} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the error repeats a credential: %v", err)
		}
	}
	if !strings.Contains(err.Error(), "upstream rejected") {
		t.Errorf("the rest of the message is still useful: %v", err)
	}
}

// The two checks for "?", "#" and a bad escape are belt and braces: the allowed-character table would refuse them too.
// What the dedicated checks add is the reason, and the reason is what tells an agent how to fix the call.
func TestEachRefusalSaysWhyInTermsTheAgentCanActOn(t *testing.T) {
	for p, want := range map[string]string{
		"/a?b=1": "query", "/a#frag": "query", "/a%zz": "malformed", "/a%2": "malformed", "x": "absolute", "//evil/x": "//",
		"": "required", "/a b": "percent-encoded", "/a/../b": "..", "/a%00": "control",
	} {
		_, err := checkPath(p)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: the reason should mention %q: %v", p, want, err)
		}
	}
}

// A cookie the site sets during the request is a credential from that moment on: when the same response, or the next
// hop's response, repeats it, it must be removed like the session's own.
func TestACookieTheSiteJustRotatedIsScrubbedFromTheVeryResponseThatSetItIfItEchoesIt(t *testing.T) {
	const rotated = "ROTATED-sid-value-ZZZZ-9999"
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: rotated, Path: "/"})
		w.Write([]byte(`{"new_session_id":"` + rotated + `"}`))
	}))
	res, err := p.Do(context.Background(), session(), req(base, "GET", "/refresh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Body, rotated) {
		t.Errorf("a credential the site has just issued was shown to the agent: %s", res.Body)
	}
}

func TestACookieRotatedByAnEarlierHopIsScrubbedFromTheLaterOne(t *testing.T) {
	const rotated = "HOP-ROTATED-cookie-AAAA-1234"
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "hop", Value: rotated, Path: "/"})
			http.Redirect(w, r, "/end", 302)
			return
		}
		w.Write([]byte("you sent: " + r.Header.Get("Cookie")))
	}))
	r := req(base, "GET", "/start")
	r.FollowRedirects = true
	res, err := p.Do(context.Background(), session(), r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Body, rotated) || strings.Contains(res.Body, cookieVal) {
		t.Errorf("%s", res.Body)
	}
	if !strings.Contains(res.Body, "[REDACTED]") {
		t.Errorf("the server did echo the cookies, so something was removed: %s", res.Body)
	}
}

// Driver state in Tokens ("api": "rest", "identity_provider": "ldap") is not a credential: removing it would damage an
// answer that only says which API generation the site runs, and the agent needs that.
func TestDriverStateIsNotScrubbedButRealTokensAre(t *testing.T) {
	p, base, _ := newProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"api":"restful-generation","idp":"ldap-provider-name","crumb":"CRUMB-VALUE-abcdef12","user":"alice-the-user"}`))
	}))
	sess := &site.Session{Tokens: map[string]string{"api": "restful-generation", "identity_provider": "ldap-provider-name",
		"crumb": "CRUMB-VALUE-abcdef12", "user": "alice-the-user"}, Cookies: session().Cookies}
	res, err := p.Do(context.Background(), sess, req(base, "GET", "/x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, keep := range []string{"restful-generation", "ldap-provider-name", "alice-the-user"} {
		if !strings.Contains(res.Body, keep) {
			t.Errorf("%q is driver state, not a secret, and must stay readable: %s", keep, res.Body)
		}
	}
	if strings.Contains(res.Body, "CRUMB-VALUE") {
		t.Errorf("a crumb is a credential: %s", res.Body)
	}
}
