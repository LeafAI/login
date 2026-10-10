package kubesphere

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/sitetest"
)

// fakeKS imitates the KubeSphere 3.4.1 behaviour found in its source: /oauth/token authenticates local
// users only, /oauth/login/{idp} authenticates LDAP users, the providers are published anonymously.
type fakeKS struct {
	providers []map[string]string // identityProviders in the published config
	cfgStatus int
	attempts  atomic.Int32 // POSTs to a login endpoint
}

func (f *fakeKS) handler() http.Handler {
	oauthErr := func(w http.ResponseWriter, code int, kind, desc string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": kind, "error_description": desc})
	}
	token := func(w http.ResponseWriter) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "AT", "refresh_token": "RT", "token_type": "jwt", "expires_in": 7200})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/kapis/config.kubesphere.io/v1alpha2/configs/oauth", func(w http.ResponseWriter, r *http.Request) {
		if f.cfgStatus != 0 {
			w.WriteHeader(f.cfgStatus)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"issuer": "kubesphere", "identityProviders": f.providers})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		f.attempts.Add(1)
		r.ParseForm()
		if r.PostForm.Get("client_id") != "kubesphere" || r.PostForm.Get("client_secret") != "kubesphere" || r.PostForm.Get("grant_type") != "password" {
			oauthErr(w, 401, "invalid_client", "bad client")
			return
		}
		// local users only (the handler passes an empty identity provider)
		if r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "adminpw" {
			token(w)
			return
		}
		oauthErr(w, 400, "invalid_grant", "incorrect password")
	})
	mux.HandleFunc("/oauth/login/", func(w http.ResponseWriter, r *http.Request) {
		f.attempts.Add(1)
		idp := strings.TrimPrefix(r.URL.Path, "/oauth/login/")
		r.ParseForm()
		u, p := r.PostForm.Get("username"), r.PostForm.Get("password")
		switch {
		case idp != "ldap":
			oauthErr(w, 500, "server_error", "the identity provider was not found")
		case u == "locked":
			oauthErr(w, 429, "invalid_grant", "auth rate limit exceeded")
		case u == "inactive":
			oauthErr(w, 400, "invalid_grant", "account is not active")
		case u == "down":
			oauthErr(w, 500, "server_error", "LDAP Result Code 200 \"Network Error\"")
		case u == "alice" && p == "pw":
			token(w)
		default:
			oauthErr(w, 400, "invalid_grant", "incorrect password")
		}
	})
	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer AT" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"sub":"alice"}`))
	})
	return mux
}

func ldapProviders() []map[string]string {
	return []map[string]string{{"name": "github", "type": "GitHubIdentityProvider"}, {"name": "ldap", "type": "LDAPIdentityProvider", "mappingMethod": "auto"}}
}

func run(t *testing.T, f *fakeKS, opts map[string]string, user, pass string) (*site.Session, error) {
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := &driver{}
	d.Configure(opts)
	u, _ := url.Parse(srv.URL)
	a := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": user, "password": pass}}}
	return d.Login(context.Background(), u, a, srv.Client())
}

func TestAutoDiscoversLDAPAndLogsInThroughIt(t *testing.T) {
	f := &fakeKS{providers: ldapProviders()}
	s, err := run(t, f, nil, "alice", "pw")
	if err != nil || s.Headers["Authorization"] != "Bearer AT" || s.Tokens["identity_provider"] != "ldap" || s.ExpiresAt.IsZero() {
		t.Fatalf("%+v %v", s, err)
	}
	if f.attempts.Load() != 1 {
		t.Errorf("%d login attempts; failed attempts lock KubeSphere accounts, so exactly one is allowed", f.attempts.Load())
	}
}

func TestLocalPasswordGrantCannotLogInLDAPUsers(t *testing.T) {
	// The 3.4.1 /oauth/token path would reject an LDAP user: this is why the driver must not use it for them.
	f := &fakeKS{providers: ldapProviders()}
	if _, err := run(t, f, map[string]string{"identity_provider": "local"}, "alice", "pw"); !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("local grant for an LDAP user: %v", err)
	}
	// ...but local accounts (e.g. admin) still work when asked for explicitly.
	s, err := run(t, &fakeKS{providers: ldapProviders()}, map[string]string{"identity_provider": "local"}, "admin", "adminpw")
	if err != nil || s.Tokens["identity_provider"] != "" {
		t.Fatalf("local admin: %+v %v", s, err)
	}
}

func TestNoProvidersOrNoConfigEndpointFallsBackToLocal(t *testing.T) {
	for name, f := range map[string]*fakeKS{
		"no providers":        {},
		"config unavailable":  {cfgStatus: 403},
		"only non-ldap types": {providers: []map[string]string{{"name": "github", "type": "GitHubIdentityProvider"}}},
	} {
		if s, err := run(t, f, nil, "admin", "adminpw"); err != nil || s.Headers["Authorization"] == "" {
			t.Errorf("%s: %+v %v", name, s, err)
		}
	}
}

func TestExplicitProviderName(t *testing.T) {
	f := &fakeKS{} // discovery would find nothing; the option wins
	if _, err := run(t, f, map[string]string{"identity_provider": "ldap"}, "alice", "pw"); err != nil {
		t.Fatal(err)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		user, pass string
		want       error
		contains   string
	}{
		{"alice", "WRONG", site.ErrBadCredentials, "incorrect password"},
		{"locked", "x", site.ErrLoginRejected, "locked"},
		{"inactive", "x", site.ErrLoginRejected, "not active"},
		{"down", "x", site.ErrLoginRejected, "LDAP reachable"},
	}
	for _, c := range cases {
		_, err := run(t, &fakeKS{providers: ldapProviders()}, nil, c.user, c.pass)
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.contains) {
			t.Errorf("%s: %v", c.user, err)
		}
	}
}

func TestProbe(t *testing.T) {
	srv := httptest.NewServer((&fakeKS{}).handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	d := &driver{}
	s := &site.Session{Headers: map[string]string{"Authorization": "Bearer AT"}}
	if err := d.Probe(context.Background(), u, s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
	s.Headers["Authorization"] = "Bearer revoked"
	if err := d.Probe(context.Background(), u, s, srv.Client()); err == nil {
		t.Error("revoked token accepted")
	}
}
