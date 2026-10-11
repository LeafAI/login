package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	_ "github.com/LeafAI/securl/internal/site/gitlab"
	_ "github.com/LeafAI/securl/internal/site/kubesphere"
	"github.com/LeafAI/securl/internal/vault"

	_ "github.com/LeafAI/securl/internal/site/noauth"
)

func TestAliasSelectsDriver(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer ts.Close()
	cfg, _ := config.Load(t.TempDir() + "/none.yaml")
	cfg.Keys.Dir = t.TempDir()
	cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
	cfg.Aliases = map[string]string{ts.Listener.Addr().String(): "skywalking"}
	_, s, err := New(cfg, Options{Vault: testVault(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	// Host is 127.0.0.1:port: nothing in the name hints at SkyWalking, only the alias does.
	out, terr := s.ensureLogin(context.Background(), nil, ts.URL, "", "", false, true, 0)
	if terr != nil || out.Site != "skywalking" || out.Auth != "none" {
		t.Fatalf("alias: %+v %v", out, terr)
	}
	cfg.Aliases = nil
	if _, terr := s.ensureLogin(context.Background(), nil, ts.URL, "", "", false, true, 0); terr == nil || terr.Code != "unsupported_site" {
		t.Errorf("without alias want unsupported_site, got %v", terr)
	}
}

func TestAllowedHosts(t *testing.T) {
	cfg, _ := config.Load(t.TempDir() + "/none.yaml")
	cfg.Keys.Dir = t.TempDir()
	cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
	cfg.Security.AllowedHosts = []string{"*.corp.example", "skywalking.other:8080"}
	_, s, err := New(cfg, Options{Vault: testVault(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	for url, want := range map[string]bool{
		"https://gitlab.corp.example/x":     true,
		"https://GitLab.Corp.Example":       true,
		"https://corp.example":              false,
		"https://evil.example":              false,
		"https://gitlab.corp.example.evil/": false,
		"http://skywalking.other:8080":      true,
		"http://skywalking.other:9090":      false,
	} {
		_, terr := s.ensureLogin(context.Background(), nil, url, "skywalking", "", false, true, 0)
		denied := terr != nil && terr.Code == "host_not_allowed"
		if denied == want {
			t.Errorf("%s: allowed=%v but denied=%v", url, want, denied)
		}
	}
}

func TestPersistentSessionsSurviveRestart(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != "persisted" {
			http.Error(w, "no", 401)
		}
	}))
	defer ts.Close()
	dir := t.TempDir()
	const pass = "correct horse battery staple"
	newServer := func(firstRun bool) *Server {
		cfg, _ := config.Load(dir + "/none.yaml")
		cfg.Keys.Dir = dir + "/keys"
		cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
		v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
		_, s, err := New(cfg, Options{Vault: v})
		if err != nil {
			t.Fatal(err)
		}
		if firstRun {
			if err := v.Init(pass); err != nil {
				t.Fatal(err)
			}
		}
		// "Restart": a brand-new process starts locked and is opened with the passphrase.
		if err := s.UnlockWith(pass); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := newServer(true)
	d, _ := site.Resolve("gitlab", nil)
	base, _ := url.Parse(ts.URL)
	first.core.cache.Put(base, d, &site.Session{Cookies: []*http.Cookie{{Name: "_gitlab_session", Value: "persisted"}}})
	first.Lock()

	// A brand-new server process reads the same vault; no human is involved.
	out, terr := newServer(false).ensureLogin(context.Background(), nil, ts.URL, "gitlab", "", false, true, 0)
	if terr != nil || !out.Cached {
		t.Fatalf("restart: %+v %v", out, terr)
	}
}

// A site served under a path prefix only works when `roots:` supplies the prefix, because the URL given by
// the agent is reduced to scheme://host.
func TestRootsSupplyPathPrefix(t *testing.T) {
	ts := httptest.NewServer(http.StripPrefix("/sky", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })))
	defer ts.Close()
	cfg, _ := config.Load(t.TempDir() + "/none.yaml")
	cfg.Keys.Dir = t.TempDir()
	cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
	host := ts.Listener.Addr().String()
	cfg.Aliases = map[string]string{host: "skywalking"}
	_, s, err := New(cfg, Options{Vault: testVault(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	if _, terr := s.ensureLogin(context.Background(), nil, ts.URL+"/sky/general-service", "", "", false, true, 0); terr == nil {
		t.Fatal("expected failure: without roots the request goes to / which the server does not serve")
	}
	cfg.Roots = map[string]string{host: ts.URL + "/sky/"}
	out, terr := s.ensureLogin(context.Background(), nil, ts.URL+"/sky/general-service", "", "", false, true, 0)
	if terr != nil || out.BaseURL != ts.URL+"/sky" {
		t.Fatalf("with roots: %+v %v", out, terr)
	}
}

func TestSiteOptionsValidation(t *testing.T) {
	// Driver options live on the process-wide driver instances: undo them so other tests are unaffected.
	t.Cleanup(func() {
		for _, name := range []string{"gitlab", "kubesphere"} {
			if d, err := site.Resolve(name, nil); err == nil {
				d.(site.Configurable).Configure(nil)
			}
		}
	})
	mk := func(opts map[string]map[string]string) error {
		cfg, _ := config.Load(t.TempDir() + "/none.yaml")
		cfg.Keys.Dir = t.TempDir()
		cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
		cfg.SiteOptions = opts
		_, _, err := New(cfg, Options{Vault: testVault(t, cfg)})
		return err
	}
	if err := mk(map[string]map[string]string{"gitlab": {"login_method": "ldap"}, "kubesphere": {"identity_provider": "ldap"}}); err != nil {
		t.Errorf("valid options rejected: %v", err)
	}
	if err := mk(map[string]map[string]string{"nope": {"a": "b"}}); err == nil {
		t.Error("unknown driver accepted")
	}
	if err := mk(map[string]map[string]string{"skywalking": {"a": "b"}}); err == nil {
		t.Error("driver without options accepted")
	}
}
