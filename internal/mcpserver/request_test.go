package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/proxy"
	"github.com/LeafAI/securl/internal/site"
)

const (
	rqCookie = "SESSION-COOKIE-VALUE-0123456789"
	rqBearer = "BEARER-TOKEN-VALUE-9876543210"
)

// rqSite is a site that checks the credentials it is sent and echoes what it saw, the way an echo or debug page would.
type rqSite struct {
	*httptest.Server
	mu   sync.Mutex
	seen []rqSeen
}

type rqSeen struct{ Method, Path, Query, Cookie, Auth, Body, ContentType string }

func newRqSite(t *testing.T) *rqSite {
	t.Helper()
	rs := &rqSite{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rs.mu.Lock()
		rs.seen = append(rs.seen, rqSeen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Cookie"), r.Header.Get("Authorization"), string(b), r.Header.Get("Content-Type")})
		rs.mu.Unlock()
		if c, err := r.Cookie("sid"); err != nil || c.Value != rqCookie {
			http.Error(w, "no session", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "you_sent_cookie": r.Header.Get("Cookie"), "path": r.URL.Path, "body": string(b)})
	})
	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ROTATED-SESSION-VALUE-77777777", Path: "/"})
		w.Write([]byte("rotated"))
	})
	rs.Server = httptest.NewServer(mux)
	t.Cleanup(rs.Close)
	return rs
}

func (rs *rqSite) last() rqSeen {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.seen[len(rs.seen)-1]
}

func (rs *rqSite) count() int { rs.mu.Lock(); defer rs.mu.Unlock(); return len(rs.seen) }

// withSession starts an open server that already holds a session for the site, as if a person had logged in.
func withSession(t *testing.T, rs *rqSite, tweak func(*config.Config)) *gateEnv {
	t.Helper()
	g := gateServer(t, "open", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(rs.URL, "http://"): "skywalking"}
		if tweak != nil {
			tweak(c)
		}
	})
	d, _ := site.Resolve("skywalking", nil)
	base := mustURL(t, rs.URL)
	g.s.core.cache.Put(base, d, &site.Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: rqCookie, Path: "/"}},
		Headers: map[string]string{"Authorization": "Bearer " + rqBearer},
	})
	return g
}

func TestRequestSendsTheCredentialsAndTheAgentNeverSeesThem(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/api/me"})
	if isErr {
		t.Fatalf("%v", out)
	}
	seen := rs.last()
	if !strings.Contains(seen.Cookie, "sid="+rqCookie) || seen.Auth != "Bearer "+rqBearer {
		t.Errorf("the credentials must be sent: %+v", seen)
	}
	if out["status"] != float64(200) {
		t.Errorf("%v", out)
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{rqCookie, rqBearer} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the result carries %q: %s", secret, raw)
		}
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Errorf("the echo page repeated the cookie, so something must have been removed: %s", raw)
	}
	if n, _ := out["redactions"].(float64); n < 1 {
		t.Errorf("%v", out["redactions"])
	}
}

func TestRequestBodyFormsReachTheSite(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	for name, args := range map[string]map[string]any{
		"json": {"method": "POST", "path": "/j", "json": map[string]any{"id": 12345678901234567890.0, "a": []any{1, 2}}},
		"form": {"method": "POST", "path": "/f", "form": map[string]any{"a": "1", "b": []any{"x", "y"}}},
		"text": {"method": "PUT", "path": "/t", "text": "plain"},
		"b64":  {"method": "POST", "path": "/b", "base64": base64.StdEncoding.EncodeToString([]byte{0, 1, 2})},
	} {
		args["url"] = rs.URL
		if out, isErr := g.call(t, toolRequest, args); isErr {
			t.Errorf("%s: %v", name, out)
		}
	}
	if rs.count() != 4 {
		t.Errorf("%d requests", rs.count())
	}
}

func TestRequestQueryAndHeadersAreBuiltByTheServer(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/s",
		"query": map[string]any{"q": "a b&c", "n": []any{"1", "2"}}, "headers": map[string]any{"Accept": "application/json"}})
	if isErr {
		t.Fatalf("%v", out)
	}
	if got := rs.last().Query; !strings.Contains(got, "q=a+b%26c") || !strings.Contains(got, "n=1&n=2") {
		t.Errorf("%q", got)
	}
}

func TestRequestRefusesWhatTheProxyRefuses(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	before := rs.count()
	for name, args := range map[string]map[string]any{
		"agent cookie":  {"method": "GET", "path": "/x", "headers": map[string]any{"Cookie": "evil=1"}},
		"agent auth":    {"method": "GET", "path": "/x", "headers": map[string]any{"Authorization": "Bearer evil"}},
		"other host":    {"method": "GET", "path": "http://evil.example/x"},
		"scheme rel":    {"method": "GET", "path": "//evil.example/x"},
		"dot dot":       {"method": "GET", "path": "/a/../../x"},
		"query in path": {"method": "GET", "path": "/x?y=1"},
		"bad method":    {"method": "TRACE", "path": "/x"},
		"get with body": {"method": "GET", "path": "/x", "text": "body"},
		"two bodies":    {"method": "POST", "path": "/x", "text": "a", "base64": "YQ=="},
	} {
		args["url"] = rs.URL
		out, isErr := g.call(t, toolRequest, args)
		if !isErr || out["code"] != "invalid_argument" {
			t.Errorf("%s: want invalid_argument, got %v", name, out)
		}
	}
	if rs.count() != before {
		t.Errorf("a refused request must send nothing: %d requests went out", rs.count()-before)
	}
}

func TestRequestNeedsTheVaultOpen(t *testing.T) {
	rs := newRqSite(t)
	g := gateServer(t, "locked", nil)
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x"})
	if !isErr || out["code"] != "vault_locked" {
		t.Errorf("%v", out)
	}
	g2 := gateServer(t, "none", nil)
	if out, isErr := g2.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x"}); !isErr || out["code"] != "vault_not_initialized" {
		t.Errorf("%v", out)
	}
	if rs.count() != 0 {
		t.Error("nothing is sent while the vault is shut")
	}
}

func TestRequestHonoursAllowedHostsAndLocalAddresses(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, func(c *config.Config) { c.Security.AllowedHosts = []string{"*.corp.example"} })
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x"})
	if !isErr || out["code"] != "host_not_allowed" {
		t.Errorf("%v", out)
	}
	if rs.count() != 0 {
		t.Error("nothing is sent to a host the policy does not allow")
	}
	g2 := withSession(t, rs, func(c *config.Config) { c.Security.AllowLocalAddresses = false })
	if out, isErr := g2.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x"}); !isErr || out["code"] != "host_not_allowed" {
		t.Errorf("a loopback site without allow_local_addresses: %v", out)
	}
}

// The request tool never opens a login by itself: asking a person to type a password is session_open's job, and an
// agent that can be steered into one request after another must not be able to flood people with login links.
func TestRequestWithoutASessionSaysSoAndAsksNobody(t *testing.T) {
	rs := newRqSite(t)
	g := gateServer(t, "open", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(rs.URL, "http://"): "skywalking"}
	})
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x"})
	if !isErr || out["code"] != "no_session" {
		t.Fatalf("%v", out)
	}
	if h, _ := out["hint"].(string); !strings.Contains(h, toolSessionOpen) {
		t.Errorf("the hint names the tool that opens a session: %q", h)
	}
	if rs.count() != 0 {
		t.Error("nothing is sent without a session")
	}
}

func TestRequestAnswers401WithSessionExpiredHintAndDropsTheDeadSession(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	// the site stops accepting the cookie
	d, _ := site.Resolve("skywalking", nil)
	g.s.core.cache.Put(mustURL(t, rs.URL), d, &site.Session{Cookies: []*http.Cookie{{Name: "sid", Value: "STALE-COOKIE-VALUE-123456", Path: "/"}}})
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x"})
	if isErr {
		t.Fatalf("a 401 is the site's answer, not a tool error: %v", out)
	}
	if out["status"] != float64(401) {
		t.Fatalf("%v", out)
	}
	if h, _ := out["hint"].(string); !strings.Contains(h, toolSessionOpen) || !strings.Contains(h, "force_refresh") {
		t.Errorf("a 401 must tell the agent how to get a new session: %v", out["hint"])
	}
}

func TestRequestKeepsARotatedCookieForTheNextCall(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	if out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/rotate"}); isErr {
		t.Fatalf("%v", out)
	}
	g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/after"})
	if got := rs.last().Cookie; !strings.Contains(got, "ROTATED-SESSION-VALUE-77777777") || strings.Contains(got, rqCookie) {
		t.Errorf("the cookie the site rotated must replace the old one: %q", got)
	}
}

func TestRequestRotatedCookieIsStoredInTheVault(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/rotate"})
	raw, err := g.v.Get("session/" + rs.URL)
	if err != nil || !strings.Contains(string(raw), "ROTATED-SESSION-VALUE-77777777") {
		t.Errorf("another process must see the rotated cookie: %v", err)
	}
}

func TestRequestResultNeverContainsASetCookieOrTheRotatedValue(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	out, _ := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/rotate"})
	raw, _ := json.Marshal(out)
	if strings.Contains(strings.ToLower(string(raw)), "set-cookie") || strings.Contains(string(raw), "ROTATED-SESSION") {
		t.Errorf("%s", raw)
	}
}

func TestRequestIsAudited(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "POST", "path": "/api/secret-looking/path",
		"query": map[string]any{"token": "QUERY-SECRET-abcdef"}, "text": "BODY-SECRET-ghijkl", "headers": map[string]any{"X-Note": "HEADER-SECRET-mnopqr"}})
	raw := readFile(t, g.cfg.Audit.File)
	for _, want := range []string{`"tool":"request"`, `"method":"POST"`, `"status":200`, "/api/secret-looking/path"} {
		if !strings.Contains(raw, want) {
			t.Errorf("the audit log lacks %s:\n%s", want, raw)
		}
	}
	for _, leak := range []string{"QUERY-SECRET", "BODY-SECRET", "HEADER-SECRET", rqCookie, rqBearer} {
		if strings.Contains(raw, leak) {
			t.Errorf("the audit log leaks %q:\n%s", leak, raw)
		}
	}
	if strings.Contains(raw, "?") && strings.Contains(raw, "token=") {
		t.Errorf("the query string is not logged:\n%s", raw)
	}
}

func TestRequestResponseSizeIsBoundedAndReported(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Repeat("x", 400000)))
	}))
	defer big.Close()
	g := gateServer(t, "open", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(big.URL, "http://"): "skywalking"}
	})
	d, _ := site.Resolve("skywalking", nil)
	g.s.core.cache.Put(mustURL(t, big.URL), d, &site.Session{Tokens: map[string]string{"auth": "none"}})
	out, isErr := g.call(t, toolRequest, map[string]any{"url": big.URL, "method": "GET", "path": "/big", "max_response_bytes": 1000})
	if isErr {
		t.Fatalf("%v", out)
	}
	body, _ := out["body"].(string)
	if len(body) > 1000 || out["truncated"] != true || out["total_bytes"] != float64(400000) {
		t.Errorf("%d bytes, truncated=%v total=%v", len(body), out["truncated"], out["total_bytes"])
	}
}

func TestRequestMaxResponseBytesCannotExceedTheServersCap(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	out, isErr := g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/x", "max_response_bytes": 1 << 40})
	if !isErr || out["code"] != "invalid_argument" {
		t.Errorf("an agent cannot ask for more than the cap: %v", out)
	}
}

func TestRequestTimeoutIsBoundedByTheGateway(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-make(chan struct{}):
		}
	}))
	defer slow.Close()
	g := gateServer(t, "open", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(slow.URL, "http://"): "skywalking"}
	})
	d, _ := site.Resolve("skywalking", nil)
	g.s.core.cache.Put(mustURL(t, slow.URL), d, &site.Session{Tokens: map[string]string{"auth": "none"}})
	out, isErr := g.call(t, toolRequest, map[string]any{"url": slow.URL, "method": "GET", "path": "/slow", "timeout_seconds": 1})
	if !isErr || out["code"] != "site_unreachable" {
		t.Errorf("%v", out)
	}
	if out2, isErr := g.call(t, toolRequest, map[string]any{"url": slow.URL, "method": "GET", "path": "/x", "timeout_seconds": 100000}); !isErr || out2["code"] != "invalid_argument" {
		t.Errorf("an agent cannot ask for a timeout beyond the cap: %v", out2)
	}
}

func TestRequestTransportErrorsNeverShowTheURLOrACredential(t *testing.T) {
	g := gateServer(t, "open", func(c *config.Config) { c.Aliases = map[string]string{"127.0.0.1:1": "skywalking"} })
	d, _ := site.Resolve("skywalking", nil)
	g.s.core.cache.Put(mustURL(t, "http://127.0.0.1:1"), d, &site.Session{Cookies: []*http.Cookie{{Name: "sid", Value: rqCookie, Path: "/"}}})
	out, isErr := g.call(t, toolRequest, map[string]any{"url": "http://127.0.0.1:1", "method": "GET", "path": "/p", "query": map[string]any{"t": "QS-SECRET-abcdef"}})
	if !isErr || out["code"] != "site_unreachable" {
		t.Fatalf("%v", out)
	}
	raw, _ := json.Marshal(out)
	for _, bad := range []string{"QS-SECRET", rqCookie, "/p"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the error leaks %q: %s", bad, raw)
		}
	}
}

func TestRequestSchemaDescribesJSONAsAnyValueNotAByteArray(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		if tl.Name != toolRequest {
			continue
		}
		raw, _ := json.Marshal(tl.InputSchema)
		if strings.Contains(string(raw), `"maximum":255`) {
			t.Errorf("the json field must accept any JSON value, not an array of bytes: %s", raw)
		}
		for _, field := range []string{`"url"`, `"method"`, `"path"`, `"query"`, `"headers"`, `"json"`, `"form"`, `"text"`, `"base64"`, `"follow_redirects"`} {
			if !strings.Contains(string(raw), field) {
				t.Errorf("schema lacks %s", field)
			}
		}
		return
	}
	t.Error("the request tool is not registered")
}

func TestRequestInputHasNoFieldForACredential(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		if tl.Name != toolRequest {
			continue
		}
		raw, _ := json.Marshal(tl.InputSchema)
		for _, bad := range []string{`"cookie"`, `"token"`, `"authorization"`, `"password"`, `"credential"`, `"session_id"`} {
			if strings.Contains(strings.ToLower(string(raw)), bad) {
				t.Errorf("an input named like %s would invite the agent to pass a credential: %s", bad, raw)
			}
		}
	}
}

func TestRequestDoesNotFollowRedirectsUnlessAsked(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) { hits++; http.Redirect(w, r, "/new", 302) })
	mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte("new")) })
	ts := httptest.NewServer(mux)
	defer ts.Close()
	g := gateServer(t, "open", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(ts.URL, "http://"): "skywalking"}
	})
	d, _ := site.Resolve("skywalking", nil)
	g.s.core.cache.Put(mustURL(t, ts.URL), d, &site.Session{Tokens: map[string]string{"auth": "none"}})
	out, _ := g.call(t, toolRequest, map[string]any{"url": ts.URL, "method": "GET", "path": "/old"})
	if out["status"] != float64(302) || hits != 1 {
		t.Errorf("%v hits=%d", out, hits)
	}
	hits = 0
	out, _ = g.call(t, toolRequest, map[string]any{"url": ts.URL, "method": "GET", "path": "/old", "follow_redirects": true})
	if out["status"] != float64(200) || hits != 2 {
		t.Errorf("%v hits=%d", out, hits)
	}
	if fmt.Sprint(out["final_path"]) != "/new" {
		t.Errorf("the agent learns where it ended up: %v", out["final_path"])
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMultiValueAcceptsAStringOrAListAndNothingElse(t *testing.T) {
	for in, want := range map[string][]string{
		`"abc"`: {"abc"}, `["a","b"]`: {"a", "b"}, `[]`: {}, `""`: {""}, `["a"]`: {"a"},
		`12`: {"12"}, `-3.5`: {"-3.5"}, `true`: {"true"}, `false`: {"false"}, `[1,"x",true]`: {"1", "x", "true"},
	} {
		var m multiValue
		if err := json.Unmarshal([]byte(in), &m); err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if fmt.Sprint([]string(m)) != fmt.Sprint(want) {
			t.Errorf("%s -> %v, want %v", in, []string(m), want)
		}
	}
	for _, bad := range []string{`null`, `{"a":1}`, `[[1]]`, `[{"a":1}]`, `[null]`} {
		var m multiValue
		if err := json.Unmarshal([]byte(bad), &m); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestMultiValueNumbersKeepTheirExactText(t *testing.T) {
	var m multiValue
	if err := json.Unmarshal([]byte(`12345678901234567890`), &m); err != nil || m[0] != "12345678901234567890" {
		t.Errorf("a large id must not be turned into 1.2345678901234567e+19: %v %v", m, err)
	}
	if err := json.Unmarshal([]byte(`1.50`), &m); err != nil || m[0] != "1.50" {
		t.Errorf("%v %v", m, err)
	}
}

func TestRequestSchemaOfQueryAndFormAcceptsAStringToo(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		if tl.Name != toolRequest {
			continue
		}
		props := tl.InputSchema.(map[string]any)["properties"].(map[string]any)
		for _, f := range []string{"query", "form"} {
			raw, _ := json.Marshal(props[f])
			if !strings.Contains(string(raw), "string") || !strings.Contains(string(raw), "array") {
				t.Errorf("%s must be described as a string or an array of strings: %s", f, raw)
			}
		}
	}
}

// What the agent sends must arrive as sent: each body form separately, byte for byte, with the content type that goes
// with it. The earlier table only counted requests, which a tool that dropped the body would also satisfy.
func TestEachBodyFormArrivesExactlyAsSent(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	cases := []struct {
		name string
		args map[string]any
		body string
		ct   string
	}{
		{"json keeps a large integer", map[string]any{"method": "POST", "path": "/j", "json": json.RawMessage(`{"id":12345678901234567890,"a":[1,2]}`)}, `{"id":12345678901234567890,"a":[1,2]}`, "application/json"},
		{"json scalar", map[string]any{"method": "POST", "path": "/j", "json": 42}, `42`, "application/json"},
		{"form", map[string]any{"method": "POST", "path": "/f", "form": map[string]any{"a": "1 2", "b": []any{"x", "y"}}}, "a=1+2&b=x&b=y", "application/x-www-form-urlencoded"},
		{"text", map[string]any{"method": "PUT", "path": "/t", "text": "plain body"}, "plain body", "text/plain; charset=utf-8"},
		{"base64", map[string]any{"method": "POST", "path": "/b", "base64": base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 0xff})}, "\x00\x01\x02\xff", "application/octet-stream"},
	}
	for _, c := range cases {
		c.args["url"] = rs.URL
		if out, isErr := g.call(t, toolRequest, c.args); isErr {
			t.Errorf("%s: %v", c.name, out)
			continue
		}
		got := rs.last()
		if got.Body != c.body || got.ContentType != c.ct {
			t.Errorf("%s: the site received %q (%s), want %q (%s)", c.name, got.Body, got.ContentType, c.body, c.ct)
		}
	}
}

func TestATimeoutOfOneSecondReallyStopsTheRequestAfterAboutOneSecond(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	g := gateServer(t, "open", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(slow.URL, "http://"): "skywalking"}
	})
	d, _ := site.Resolve("skywalking", nil)
	g.s.core.cache.Put(mustURL(t, slow.URL), d, &site.Session{Tokens: map[string]string{"auth": "none"}})
	start := time.Now()
	out, isErr := g.call(t, toolRequest, map[string]any{"url": slow.URL, "method": "GET", "path": "/slow", "timeout_seconds": 1})
	took := time.Since(start)
	if !isErr || out["code"] != "site_unreachable" {
		t.Fatalf("%v", out)
	}
	if took < 800*time.Millisecond || took > 3*time.Second {
		t.Errorf("the timeout the agent asked for (1 s) is what applies, not the default (25 s) and not none: %v", took)
	}
}

// A failure the tool has no name for must not repeat what the failure said: it may be an error from a library that has the
// request in it, headers and all.
func TestAnUnclassifiedFailureSaysNothingAboutItsCause(t *testing.T) {
	err := requestErr(errors.New("something with " + rqCookie + " in it"))
	if err.Code != "internal" || strings.Contains(err.Message, rqCookie) || strings.Contains(err.Message, "something") {
		t.Errorf("%+v", err)
	}
}

func TestEveryClassifiedFailureKeepsItsMeaning(t *testing.T) {
	for _, c := range []struct {
		err       error
		code      string
		retryable bool
	}{
		{fmt.Errorf("%w: x", proxy.ErrInvalid), "invalid_argument", false},
		{proxy.ErrSessionExpired, "session_expired", true},
		{fmt.Errorf("%w: x", proxy.ErrUnreachable), "site_unreachable", true},
		{fmt.Errorf("%w: stopped after 10", proxy.ErrTooManyRedirects), "site_unreachable", false},
		{fmt.Errorf("%w", site.ErrUnreachable), "site_unreachable", true},
	} {
		got := requestErr(c.err)
		if got.Code != c.code || got.Retryable != c.retryable {
			t.Errorf("%v -> %s retryable=%v, want %s retryable=%v", c.err, got.Code, got.Retryable, c.code, c.retryable)
		}
	}
	if h := requestErr(proxy.ErrSessionExpired).Hint; !strings.Contains(h, toolSessionOpen) {
		t.Errorf("an expired session says how to get a new one: %q", h)
	}
}

func TestRequestAuditEventCarriesTheSiteAndSizeToo(t *testing.T) {
	rs := newRqSite(t)
	g := withSession(t, rs, nil)
	g.call(t, toolRequest, map[string]any{"url": rs.URL, "method": "GET", "path": "/api/me"})
	raw := readFile(t, g.cfg.Audit.File)
	var ev audit.Event
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var e audit.Event
		if json.Unmarshal([]byte(line), &e) == nil && e.Event == "request" {
			ev = e
		}
	}
	if ev.Event != "request" || ev.Host != strings.TrimPrefix(rs.URL, "http://") || ev.Site != "skywalking" || ev.Bytes == 0 || ev.Method != "GET" || ev.Status != 200 || ev.Path != "/api/me" {
		t.Errorf("%+v", ev)
	}
}

// A client that validates arguments against the schema it was given must accept exactly what the tool accepts. The
// earlier check only looked for the words "string" and "array" somewhere in the field's schema, which the generated one
// satisfied while still forbidding a plain string value.
func TestTheQueryAndFormSchemasAcceptAPlainStringAndAListAndRefuseAnObject(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		if tl.Name != toolRequest {
			continue
		}
		raw, _ := json.Marshal(tl.InputSchema)
		var sc jsonschema.Schema
		if err := json.Unmarshal(raw, &sc); err != nil {
			t.Fatal(err)
		}
		resolved, err := sc.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		validate := func(doc string) error {
			var v any
			json.Unmarshal([]byte(doc), &v)
			return resolved.Validate(v)
		}
		for _, ok := range []string{
			`{"url":"u","method":"GET","path":"/","query":{"q":"a"}}`,
			`{"url":"u","method":"GET","path":"/","query":{"q":["a","b"]}}`,
			`{"url":"u","method":"POST","path":"/","form":{"a":"1","b":["x","y"]}}`,
			`{"url":"u","method":"GET","path":"/","query":{"n":12}}`,
			`{"url":"u","method":"GET","path":"/","query":{"f":true}}`,
			`{"url":"u","method":"POST","path":"/","json":{"id":12345678901234567890,"a":[1,2]}}`,
			`{"url":"u","method":"POST","path":"/","json":[1,2]}`,
			`{"url":"u","method":"POST","path":"/","json":"text"}`,
			`{"url":"u","method":"POST","path":"/","json":42}`,
		} {
			if err := validate(ok); err != nil {
				t.Errorf("the tool accepts %s but its schema refuses it: %v", ok, err)
			}
		}
		for _, bad := range []string{
			`{"url":"u","method":"GET","path":"/","query":{"q":{"a":1}}}`,
			`{"url":"u","method":"GET","path":"/","query":"q=a"}`,
			`{"url":"u","method":"GET","path":"/","headers":{"X":1}}`,
			`{"url":"u","method":"GET","path":"/","cookie":"a=b"}`,
			`{"method":"GET","path":"/"}`,
		} {
			if err := validate(bad); err == nil {
				t.Errorf("the schema accepts %s, which the tool refuses", bad)
			}
		}
	}
}
