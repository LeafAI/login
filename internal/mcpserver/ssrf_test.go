package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LeafAI/securl/internal/config"
)

func newGuardedServer(t *testing.T, tweak func(*config.Config)) *Server {
	t.Helper()
	cfg, _ := config.Load(t.TempDir() + "/none.yaml")
	cfg.Keys.Dir = t.TempDir()
	if tweak != nil {
		tweak(cfg)
	}
	_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}, Vault: testVault(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLocalAddressesAreRefusedByDefault(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("ok")) }))
	defer ts.Close()
	s := newGuardedServer(t, func(c *config.Config) { c.Aliases = map[string]string{ts.Listener.Addr().String(): "skywalking"} })
	for _, target := range []string{ts.URL, "http://localhost:" + strings.Split(ts.URL, ":")[2], "http://169.254.169.254/latest/meta-data/", "http://[::1]:1/"} {
		_, terr := s.ensureLogin(context.Background(), nil, target, "skywalking", "", false, true, 0)
		if terr == nil {
			t.Errorf("%s: a local address must be refused by default", target)
			continue
		}
		if terr.Code != "host_not_allowed" || !strings.Contains(terr.Message, "allow_local_addresses") {
			t.Errorf("%s: want host_not_allowed pointing at security.allow_local_addresses, got %s: %s", target, terr.Code, terr.Message)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("the local server received %d requests", hits.Load())
	}
}

func TestLocalAddressesCanBeAllowedExplicitly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer ts.Close()
	s := newGuardedServer(t, func(c *config.Config) {
		c.Security.AllowLocalAddresses = true
		c.Aliases = map[string]string{ts.Listener.Addr().String(): "skywalking"}
	})
	if out, terr := s.ensureLogin(context.Background(), nil, ts.URL, "", "", false, true, 0); terr != nil || out.Site != "skywalking" {
		t.Fatalf("with security.allow_local_addresses the site must be reachable: %+v %v", out, terr)
	}
}

func TestADNSNameThatPointsAtLoopbackIsRefusedAtConnectTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer ts.Close()
	port := strings.Split(ts.URL, ":")[2]
	// "localtest.me"-style names cannot be used offline, but "localhost" with an explicit alias reaches the same dial path
	// without being caught by the literal-address check when that check is bypassed by a root/alias on another name.
	s := newGuardedServer(t, nil)
	s.cfg.Aliases = map[string]string{"localhost:" + port: "skywalking"}
	if _, terr := s.hc.Get("http://localhost:" + port + "/"); terr == nil {
		t.Error("the client itself must refuse a name that resolves to loopback")
	}
}

func TestSiteCannotBounceALoginToAnotherHost(t *testing.T) {
	var secondHits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { secondHits.Add(1) }))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	s := newGuardedServer(t, func(c *config.Config) { c.Security.AllowLocalAddresses = true })
	req, _ := http.NewRequest(http.MethodPost, first.URL, strings.NewReader("password=SECRET"))
	resp, err := s.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if secondHits.Load() != 0 {
		t.Error("the shared client followed a redirect to another host and sent the request body there")
	}
}

func TestResolveRefusesLocalAddressesLikeTheTools(t *testing.T) {
	cfg, _ := config.Load(t.TempDir() + "/none.yaml")
	if _, _, err := Resolve(cfg, "http://127.0.0.1:8080", "skywalking"); err == nil || !strings.Contains(err.Error(), "allow_local_addresses") {
		t.Errorf("doctor -site goes through Resolve and must apply the same rule: %v", err)
	}
	cfg.Security.AllowLocalAddresses = true
	if _, _, err := Resolve(cfg, "http://127.0.0.1:8080", "skywalking"); err != nil {
		t.Errorf("allowed explicitly: %v", err)
	}
}

func TestRedirectToAnAllowedHostIsFollowed(t *testing.T) {
	var arrived atomic.Int32
	sso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrived.Add(1) }))
	defer sso.Close()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sso.URL, http.StatusFound)
	}))
	defer site.Close()
	allowed := strings.TrimPrefix(sso.URL, "http://")
	s := newGuardedServer(t, func(c *config.Config) {
		c.Security.AllowLocalAddresses = true
		c.Security.AllowedHosts = []string{allowed, strings.TrimPrefix(site.URL, "http://")}
	})
	resp, err := s.hc.Get(site.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if arrived.Load() != 1 {
		t.Error("a redirect to a host the operator listed in security.allowed_hosts (an SSO server, say) must work")
	}
}

func TestDefaultClientIsTheGuardedOne(t *testing.T) {
	s := newGuardedServer(t, nil)
	if _, err := s.hc.Get("http://127.0.0.1:1/"); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("the client used for sites must refuse local addresses itself, not only through the tool-level check: %v", err)
	}
}
