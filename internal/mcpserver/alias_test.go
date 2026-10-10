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
