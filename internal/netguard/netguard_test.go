package netguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlockedAddressClasses(t *testing.T) {
	for _, ip := range []string{
		"127.0.0.1", "127.255.255.254", "::1", "0.0.0.0", "::",
		"169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254", "100.100.100.200",
		"224.0.0.1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
	} {
		if !Blocked(net.ParseIP(ip)) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	for _, ip := range []string{
		"10.1.2.3", "172.16.0.9", "192.168.1.1", "197.19.1.27", "8.8.8.8", "100.64.0.1",
		"2001:4860:4860::8888", "fd12:3456::1", "::ffff:10.0.0.1",
	} {
		if Blocked(net.ParseIP(ip)) {
			t.Errorf("%s is an ordinary site address and must stay reachable", ip)
		}
	}
	if Blocked(nil) != true {
		t.Error("an unparseable address must be refused")
	}
}

func TestLocalHostNames(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "api.localhost", "127.0.0.1", "[::1]", "::1", "169.254.169.254", "0.0.0.0"} {
		if !LocalHost(h) {
			t.Errorf("%q must be recognised as local", h)
		}
	}
	for _, h := range []string{"arch.91aql.com", "10.0.0.5", "localhost.example.com", "notlocalhost", ""} {
		if LocalHost(h) {
			t.Errorf("%q is not a local host", h)
		}
	}
}

func get(c *http.Client, u string) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	return c.Do(req)
}

func TestClientRefusesLoopbackByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	if _, err := get(New(Policy{}), srv.URL); err == nil {
		t.Fatal("a loopback address must be refused")
	}
	if hits.Load() != 0 {
		t.Error("the connection must not even be made")
	}
	resp, err := get(New(Policy{AllowLocal: true}), srv.URL)
	if err != nil {
		t.Fatalf("allow_local_addresses must permit it: %v", err)
	}
	resp.Body.Close()
}

func TestClientChecksTheAddressItActuallyConnectsTo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	// "localhost" is a name, not a literal: only the dial-time check can catch where it points.
	if _, err := get(New(Policy{}), "http://localhost:"+port+"/"); err == nil {
		t.Fatal("a name that resolves to loopback must be refused at connect time")
	}
}

func TestDialerChecksTheResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, target := range []string{"127.0.0.1:" + port, "localhost:" + port} {
		c, err := newDialer(false).DialContext(context.Background(), "tcp", target)
		if err == nil {
			c.Close()
			t.Errorf("dialing %s must be refused", target)
		} else if !errors.Is(err, ErrBlocked) && !strings.Contains(err.Error(), "not permitted") {
			t.Errorf("dialing %s failed for another reason: %v", target, err)
		}
	}
	c, err := newDialer(true).DialContext(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("with local addresses allowed the dial must work: %v", err)
	}
	c.Close()
}

func TestClientSaysWhyItRefused(t *testing.T) {
	_, err := get(New(Policy{}), "http://127.0.0.1:1/x?token=SECRET")
	if err == nil {
		t.Fatal("must be refused")
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("the refusal should say why: %v", err)
	}
}

func TestCrossHostRedirectIsNotFollowedAndNoBodyIsForwarded(t *testing.T) {
	var secondHits atomic.Int32
	var secondBody atomic.Value
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		secondBody.Store(string(b))
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	c := New(Policy{AllowLocal: true})
	req, _ := http.NewRequest(http.MethodPost, first.URL+"/login", strings.NewReader("username=a&password=SECRET"))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("the redirect itself must be returned, got %d", resp.StatusCode)
	}
	if secondHits.Load() != 0 {
		t.Errorf("the second host received a request (%v)", secondBody.Load())
	}
}

func TestSameHostRedirectIsFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusFound)
			return
		}
		w.Write([]byte("arrived"))
	}))
	defer srv.Close()
	resp, err := get(New(Policy{AllowLocal: true}), srv.URL+"/old")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "arrived" {
		t.Errorf("a redirect inside one site must be followed, got %q", b)
	}
}

func hop(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func TestRedirectRules(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		from    string
		to      string
		follow  bool
	}{
		{"same origin", nil, "https://a.corp/x", "https://a.corp/y", true},
		{"host case differs", nil, "https://A.corp/x", "https://a.CORP/y", true},
		{"http to https upgrade", nil, "http://a.corp/x", "https://a.corp/y", true},
		{"upgrade with explicit 443", nil, "http://a.corp:80/x", "https://a.corp:443/y", true},
		{"https to http downgrade", nil, "https://a.corp/x", "http://a.corp/y", false},
		{"other host", nil, "https://a.corp/x", "https://b.corp/y", false},
		{"other port same host", nil, "https://a.corp:8443/x", "https://a.corp:9443/y", false},
		{"suffix lookalike", nil, "https://a.corp/x", "https://a.corp.evil.com/y", false},
		{"other host but allowed", []string{"*.corp"}, "https://a.corp/x", "https://sso.corp/y", true},
		{"other host not in allowed list", []string{"*.corp"}, "https://a.corp/x", "https://evil.com/y", false},
		{"allowed host but downgrade", []string{"*.corp"}, "https://a.corp/x", "http://sso.corp/y", false},
		{"allowed with port pattern", []string{"sso.corp:8443"}, "https://a.corp/x", "https://sso.corp:8443/y", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := redirectPolicy(tc.allowed)(hop(t, tc.to), []*http.Request{hop(t, tc.from)})
			if followed := err == nil; followed != tc.follow {
				t.Errorf("%s -> %s: followed=%v, want %v (%v)", tc.from, tc.to, followed, tc.follow, err)
			}
			if err != nil && err != http.ErrUseLastResponse {
				t.Errorf("a refused redirect must return the response, not an error: %v", err)
			}
		})
	}
}

func TestRedirectChainIsBoundedByTheFirstRequestNotTheLast(t *testing.T) {
	via := []*http.Request{hop(t, "https://a.corp/1"), hop(t, "https://b.corp/2")}
	if err := redirectPolicy(nil)(hop(t, "https://a.corp/3"), via); err == nil {
		t.Error("a chain that wandered to another host must be refused even when it comes back")
	}
}

func TestRedirectLimit(t *testing.T) {
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = hop(t, "https://a.corp/loop")
	}
	if err := redirectPolicy(nil)(hop(t, "https://a.corp/loop"), via); err == nil || err == http.ErrUseLastResponse {
		t.Errorf("more than 10 redirects must be an error, got %v", err)
	}
}

func TestProxyIsReachableButItsTargetIsStillChecked(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.Write([]byte("via proxy"))
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	c := New(Policy{Proxy: http.ProxyURL(pu)})
	resp, err := get(c, "http://intranet.example/")
	if err != nil {
		t.Fatalf("a proxy on a local address must stay usable: %v", err)
	}
	resp.Body.Close()
	if proxied.Load() != 1 {
		t.Fatal("the request did not go through the proxy")
	}
	if _, err := get(c, "http://127.0.0.1:9/"); err == nil {
		t.Error("a local target must be refused even through a proxy")
	}
	if _, err := get(c, "http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("the metadata address must be refused even through a proxy")
	}
	if proxied.Load() != 1 {
		t.Errorf("refused targets must never reach the proxy (%d requests)", proxied.Load())
	}
}

func TestClientKeepsItsTimeout(t *testing.T) {
	if c := New(Policy{Timeout: 3 * time.Second}); c.Timeout != 3*time.Second {
		t.Errorf("timeout lost: %v", c.Timeout)
	}
	if c := New(Policy{}); c.Timeout != 30*time.Second {
		t.Errorf("default timeout should be 30s: %v", c.Timeout)
	}
}
