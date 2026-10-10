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
	_ "github.com/LeafAI/login/internal/site/nightingale"
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

func TestKibana(t *testing.T) {
	needOTP := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/security/login":
			if r.Header.Get("kbn-xsrf") == "" {
				http.Error(w, "xsrf", 400)
				return
			}
			var b struct {
				Params map[string]string `json:"params"`
			}
			json.NewDecoder(r.Body).Decode(&b)
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
		}
	}))
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
	needOTP = false
	a = answers("")
	if _, err := run(t, "kibana", srv, a); err != nil || len(a.Asked) != 1 {
		t.Errorf("no-2fa: %v %v", err, a.Asked)
	}
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := run(t, "kibana", srv, bad); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad creds: %v", err)
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

func TestNightingale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/n9e/auth/login":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			switch {
			case b["username"] != "alice" || b["password"] != "pw":
				w.Write([]byte(`{"dat":null,"err":"invalid username or password"}`))
			case b["code"] != "123456":
				w.Write([]byte(`{"dat":null,"err":"mfa code required"}`))
			default:
				w.Write([]byte(`{"dat":{"access_token":"AT","refresh_token":"RT"},"err":""}`))
			}
		case "/api/n9e/self/profile":
			if r.Header.Get("Authorization") != "Bearer AT" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	a := answers("123456")
	s, err := run(t, "nightingale", srv, a)
	if err != nil || strings.Join(a.Asked, ",") != "login,totp" || s.Tokens["access_token"] != "AT" {
		t.Fatalf("%+v %v %v", s, err, a.Asked)
	}
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := run(t, "nightingale", srv, bad); !errors.Is(err, site.ErrBadCredentials) || len(bad.Asked) != 1 {
		t.Errorf("bad creds: %v asked=%v", err, bad.Asked)
	}
}
