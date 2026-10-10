package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/site"
	_ "github.com/LeafAI/login/internal/site/gitlab"

	_ "github.com/LeafAI/login/internal/site/noauth"
)

func TestAliasSelectsDriver(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer ts.Close()
	cfg, _ := config.Load(t.TempDir() + "/none.yaml")
	cfg.Keys.Dir = t.TempDir()
	cfg.Aliases = map[string]string{ts.Listener.Addr().String(): "skywalking"}
	_, s, err := New(cfg, Options{})
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
	cfg.Security.AllowedHosts = []string{"*.corp.example", "skywalking.other:8080"}
	_, s, err := New(cfg, Options{})
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
	newServer := func() *Server {
		cfg, _ := config.Load(dir + "/none.yaml")
		cfg.Keys.Dir = dir + "/keys"
		cfg.Sessions.Persist = true
		_, s, err := New(cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := newServer()
	d, _ := site.Resolve("gitlab", nil)
	base, _ := url.Parse(ts.URL)
	first.cache.Put(base, d, &site.Session{Cookies: []*http.Cookie{{Name: "_gitlab_session", Value: "persisted"}}})

	// "Restart": a brand-new server process reads the same store; no human is involved.
	out, terr := newServer().ensureLogin(context.Background(), nil, ts.URL, "gitlab", "", false, true, 0)
	if terr != nil || !out.Cached || out.CookieHeader != "_gitlab_session=persisted" {
		t.Fatalf("restart: %+v %v", out, terr)
	}
}
