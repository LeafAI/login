package site_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/login/internal/site"
	_ "github.com/LeafAI/login/internal/site/kibana"
	_ "github.com/LeafAI/login/internal/site/kubesphere"
	"github.com/LeafAI/login/internal/site/sitetest"
)

func run(t *testing.T, name string, srv *httptest.Server, a *sitetest.Asker) (*site.Session, error) {
	t.Helper()
	d, err := site.Resolve(name, mustURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return d.Login(context.Background(), mustURL(srv.URL), a, srv.Client())
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

func answers(code string) *sitetest.Asker {
	return &sitetest.Asker{Answers: map[string]site.Credentials{
		"login": {"username": "alice", "password": "pw"}, "totp": {"code": code}}}
}

func kibanaFake(provider string, needOTP bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/security/login_state":
			json.NewEncoder(w).Encode(map[string]any{"selector": map[string]any{"enabled": false, "providers": []map[string]any{
				{"type": "saml", "name": "saml1", "usesLoginForm": false},
				{"type": "basic", "name": provider, "usesLoginForm": true}}}})
		case "/internal/security/login":
			if r.Header.Get("kbn-xsrf") == "" {
				http.Error(w, "xsrf", 400)
				return
			}
			var b struct {
				ProviderType string            `json:"providerType"`
				ProviderName string            `json:"providerName"`
				Params       map[string]string `json:"params"`
			}
			json.NewDecoder(r.Body).Decode(&b)
			if b.ProviderType != "basic" || b.ProviderName != provider {
				w.WriteHeader(401)
				w.Write([]byte(`{"message":"unknown provider"}`))
				return
			}
			if b.Params["username"] != "alice" || b.Params["password"] != "pw" {
				w.WriteHeader(401)
				w.Write([]byte(`{"message":"Unauthorized"}`))
				return
			}
			if needOTP && b.Params["otp"] != "123456" {
				w.WriteHeader(401)
				w.Write([]byte(`{"message":"otp required"}`))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "S", Path: "/"})
			w.Write([]byte(`{"location":"/"}`))
		case "/internal/security/me":
			if c, err := r.Cookie("sid"); err != nil || c.Value != "S" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func TestKibana(t *testing.T) {
	srv := httptest.NewServer(kibanaFake("basic1", true)) // a custom provider name, as many clusters use
	defer srv.Close()
	a := answers("123456")
	s, err := run(t, "kibana", srv, a)
	if err != nil || strings.Join(a.Asked, ",") != "login,totp" {
		t.Fatalf("2fa: %v asked=%v", err, a.Asked)
	}
	d, _ := site.Resolve("kibana", mustURL(srv.URL))
	if err := d.Probe(context.Background(), mustURL(srv.URL), s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
	plain := httptest.NewServer(kibanaFake("basic", false))
	defer plain.Close()
	a = answers("")
	if _, err := run(t, "kibana", plain, a); err != nil || len(a.Asked) != 1 {
		t.Errorf("no-2fa: %v %v", err, a.Asked)
	}
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := run(t, "kibana", plain, bad); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad creds: %v", err)
	}
}

// Kibana served under a path prefix (server.basePath) must work when the base URL carries the prefix.
func TestKibanaUnderPathPrefix(t *testing.T) {
	srv := httptest.NewServer(http.StripPrefix("/kibana", kibanaFake("basic", false)))
	defer srv.Close()
	base := mustURL(srv.URL + "/kibana")
	d, _ := site.Resolve("kibana", base)
	s, err := d.Login(context.Background(), base, answers(""), srv.Client())
	if err != nil {
		t.Fatalf("login under /kibana: %v", err)
	}
	if err := d.Probe(context.Background(), base, s, srv.Client()); err != nil {
		t.Errorf("probe under /kibana: %v", err)
	}
}

func TestKubeSphere(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			r.ParseForm()
			if r.PostForm.Get("grant_type") != "password" || r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"incorrect password"}`))
				return
			}
			w.Write([]byte(`{"access_token":"AT","refresh_token":"RT","token_type":"bearer","expires_in":7200}`))
		default:
			if r.Header.Get("Authorization") != "Bearer AT" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	s, err := run(t, "kubesphere", srv, answers(""))
	if err != nil || s.Headers["Authorization"] != "Bearer AT" || s.ExpiresAt.IsZero() {
		t.Fatalf("%+v %v", s, err)
	}
	d, _ := site.Resolve("kubesphere", mustURL(srv.URL))
	if err := d.Probe(context.Background(), mustURL(srv.URL), s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := run(t, "kubesphere", srv, bad); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad creds: %v", err)
	}
}
