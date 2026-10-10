package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LeafAI/login/internal/config"

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
