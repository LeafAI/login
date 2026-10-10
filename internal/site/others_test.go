package site_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/LeafAI/login/internal/site"
	_ "github.com/LeafAI/login/internal/site/kibana"
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

func TestKibanaInspect(t *testing.T) {
	srv := httptest.NewServer(kibanaFake("basic1", false))
	defer srv.Close()
	d, _ := site.Resolve("kibana", mustURL(srv.URL))
	in, ok := d.(site.Inspector)
	if !ok {
		t.Fatal("kibana driver is not an Inspector")
	}
	out, err := in.Inspect(context.Background(), mustURL(srv.URL), srv.Client())
	if err != nil || !strings.Contains(strings.Join(out, " "), `name "basic1"`) {
		t.Errorf("%v %v", out, err)
	}
}

// kibana7Fake is Kibana 7.9.3 as seen on a live site (browser capture and probes): POST /internal/security/login
// takes a flat {"username","password"} and rejects providerType/providerName/currentURL/params as unknown keys
// (400), a wrong password is 401, and the login page carries the version in its injected metadata.
func kibana7Fake(posts *[]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Write([]byte(`<html><kbn-injected-metadata data="{&quot;version&quot;:&quot;7.9.3&quot;,&quot;buildNumber&quot;:34038}"></kbn-injected-metadata></html>`))
		case "/internal/security/login_state":
			w.Write([]byte(`{"allowLogin":true,"layout":"form","selector":{"enabled":false,"providers":[{"type":"basic","name":"basic","usesLoginForm":true}]}}`))
		case "/internal/security/login":
			raw, _ := io.ReadAll(r.Body)
			var all map[string]any
			json.Unmarshal(raw, &all)
			keys := make([]string, 0, len(all))
			for k := range all {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			*posts = append(*posts, strings.Join(keys, ","))
			for _, k := range []string{"providerType", "providerName", "currentURL", "params"} {
				if _, bad := all[k]; bad {
					w.WriteHeader(400)
					fmt.Fprintf(w, `{"statusCode":400,"error":"Bad Request","message":"[request body.%s]: definition for this key is missing"}`, k)
					return
				}
			}
			if _, ok := all["username"].(string); !ok {
				w.WriteHeader(400)
				w.Write([]byte(`{"statusCode":400,"error":"Bad Request","message":"[request body.username]: expected value of type [string] but got [undefined]"}`))
				return
			}
			if all["username"] != "alice" || all["password"] != "pw" {
				w.WriteHeader(401)
				w.Write([]byte(`{"statusCode":401,"error":"Unauthorized","message":"[security_exception] unable to authenticate user"}`))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "S", Path: "/"})
			w.WriteHeader(204)
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

func TestKibana7LoginUsesTheFlatBody(t *testing.T) {
	var posts []string
	srv := httptest.NewServer(kibana7Fake(&posts))
	defer srv.Close()
	a := answers("")
	s, err := run(t, "kibana", srv, a)
	if err != nil {
		t.Fatalf("a Kibana 7.9.3 login the browser accepts was refused: %v", err)
	}
	if len(s.Cookies) != 1 || s.Cookies[0].Name != "sid" {
		t.Errorf("session cookie: %+v", s.Cookies)
	}
	if len(posts) != 1 || posts[0] != "password,username" {
		t.Errorf("login POSTs = %v; Kibana 7.9.3 takes exactly one flat {username,password}", posts)
	}
	d, _ := site.Resolve("kibana", mustURL(srv.URL))
	if err := d.Probe(context.Background(), mustURL(srv.URL), s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
}

// When the version cannot be read (a fronting proxy rewrote the page), the 400 that names the unaccepted key is
// enough to switch format. A 400 is a validation failure before any authentication, so it never counts as a failed
// login and cannot lock the account.
func TestKibanaFormatIsLearnedFromTheRejection(t *testing.T) {
	var posts []string
	inner := kibana7Fake(&posts)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Write([]byte("<html>no version here</html>"))
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	if _, err := run(t, "kibana", srv, answers("")); err != nil {
		t.Fatalf("login with an unreadable version: %v", err)
	}
	if len(posts) != 2 || posts[1] != "password,username" {
		t.Errorf("POSTs = %v, want a rejected nested body then the flat one", posts)
	}
}

func TestKibana7WrongPasswordIsBadCredentialsAndDoesNotRetry(t *testing.T) {
	var posts []string
	srv := httptest.NewServer(kibana7Fake(&posts))
	defer srv.Close()
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "WRONG"}}}
	if _, err := run(t, "kibana", srv, bad); !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if len(posts) != 1 {
		t.Errorf("%d login POSTs; a rejected password must not be sent again (accounts lock)", len(posts))
	}
}

func TestKibanaInspectReportsTheVersionAndFormat(t *testing.T) {
	var posts []string
	srv := httptest.NewServer(kibana7Fake(&posts))
	defer srv.Close()
	d, _ := site.Resolve("kibana", mustURL(srv.URL))
	out, err := d.(site.Inspector).Inspect(context.Background(), mustURL(srv.URL), srv.Client())
	joined := strings.Join(out, " ")
	if err != nil || !strings.Contains(joined, "7.9.3") || !strings.Contains(joined, "flat") {
		t.Errorf("inspect should say the version and that the flat body is used: %v %v", out, err)
	}
	if len(posts) != 0 {
		t.Errorf("inspecting must not attempt a login: %v", posts)
	}
}
