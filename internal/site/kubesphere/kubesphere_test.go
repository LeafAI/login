package kubesphere

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
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
	// webLogin makes /oauth/login/{idp} behave like the real KubeSphere web console seen in a browser capture:
	// the body is JSON, success is 302 + Set-Cookie (token, refreshToken, expire) and failure is
	// 200 {"status":500,"reason":"Internal Server Error"} whatever the reason.
	webLogin bool
	gotJSON  atomic.Bool  // the last login POST carried a JSON body
	bodyKeys atomic.Value // []string: sorted JSON keys of the last login POST body
	title    atomic.Value // string: the "title" field of the last login POST body
	probes   atomic.Int32 // requests that checked a token
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
		if f.webLogin {
			f.webLoginHandler(w, r)
			return
		}
		idp := strings.TrimPrefix(r.URL.Path, "/oauth/login/")
		var u, p string
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var in struct{ Username, Password string }
			json.NewDecoder(r.Body).Decode(&in)
			u, p = in.Username, in.Password
		} else {
			r.ParseForm()
			u, p = r.PostForm.Get("username"), r.PostForm.Get("password")
		}
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>console</html>")) })
	// The login page answers 200 to everybody: following a redirect to it must never look like success.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>sign in</html>")) })
	// Real v3.4.1 behaviour (checked against a live site): /oauth/userinfo is the OIDC endpoint for OAuth clients,
	// so a console token does not satisfy it. It redirects to the login page, valid token or not.
	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?referer=/oauth/userinfo", http.StatusFound)
	})
	// What does tell a good token from a bad one: an authenticated API call. 200 with a valid token, 401 with a
	// forged or revoked one, 403 with none.
	mux.HandleFunc("/kapis/resources.kubesphere.io/v1alpha2/namespaces", func(w http.ResponseWriter, r *http.Request) {
		f.probes.Add(1)
		auth := r.Header.Get("Authorization")
		switch {
		case auth == "":
			w.WriteHeader(403)
		case auth != "Bearer AT":
			w.WriteHeader(401)
		default:
			w.Write([]byte(`{"items":[{"metadata":{"name":"default"}}],"totalItems":1}`))
		}
	})
	return mux
}

func (f *fakeKS) webLoginHandler(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		f.gotJSON.Store(true)
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &in)
		var all map[string]any
		json.Unmarshal(raw, &all)
		keys := make([]string, 0, len(all))
		for k := range all {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		f.bodyKeys.Store(keys)
		t, _ := all["title"].(string)
		f.title.Store(t)
	}
	if strings.TrimPrefix(r.URL.Path, "/oauth/login/") == "ldap" && in.Username == "alice" && in.Password == "pw" {
		http.SetCookie(w, &http.Cookie{Name: "token", Value: "AT", Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "expire", Value: "1791622193618", Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "refreshToken", Value: "RT", Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"status": 500, "reason": "Internal Server Error"})
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
	f := &fakeKS{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	d := &driver{}
	probe := func(auth string) error {
		s := &site.Session{Headers: map[string]string{"Authorization": auth}}
		return d.Probe(context.Background(), u, s, srv.Client())
	}
	if err := probe("Bearer AT"); err != nil {
		t.Errorf("a valid token must pass: %v", err)
	}
	for name, auth := range map[string]string{"revoked": "Bearer revoked", "forged": "Bearer x.y.z", "none": ""} {
		if err := probe(auth); err == nil {
			t.Errorf("a %s token was accepted", name)
		}
	}
	if f.probes.Load() != 4 {
		t.Errorf("%d token checks for 4 probes: every probe must reach an API that authenticates", f.probes.Load())
	}
}

// Regression: on KubeSphere v3.4.1 /oauth/userinfo redirects every console token to the login page, which answers
// 200. A probe that follows the redirect therefore accepted ANY token, and expired or revoked sessions were
// handed to the agent as valid until their recorded expiry.
func TestProbeDoesNotMistakeTheLoginPageForAValidSession(t *testing.T) {
	srv := httptest.NewServer((&fakeKS{}).handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	s := &site.Session{Headers: map[string]string{"Authorization": "Bearer totally-made-up"}}
	if err := (&driver{}).Probe(context.Background(), u, s, srv.Client()); err == nil {
		t.Fatal("a made-up token passed the probe: the login page's 200 was taken for a valid session")
	}
}

func TestInspect(t *testing.T) {
	for name, tc := range map[string]struct {
		f    *fakeKS
		opts map[string]string
		want string
	}{
		"ldap discovered": {&fakeKS{providers: ldapProviders()}, nil, "/oauth/login/ldap"},
		"local only":      {&fakeKS{}, nil, "/oauth/token"},
		"forced local":    {&fakeKS{providers: ldapProviders()}, map[string]string{"identity_provider": "local"}, "/oauth/token"},
	} {
		srv := httptest.NewServer(tc.f.handler())
		d := &driver{}
		d.Configure(tc.opts)
		u, _ := url.Parse(srv.URL)
		out, err := d.Inspect(context.Background(), u, srv.Client())
		srv.Close()
		if err != nil || !strings.Contains(strings.Join(out, " "), tc.want) {
			t.Errorf("%s: %v %v", name, out, err)
		}
	}
}

// The real console (browser capture of POST /oauth/login/ldap): JSON body in, 302 + cookies out.
func TestLDAPLoginAsTheWebConsoleDoesIt(t *testing.T) {
	f := &fakeKS{providers: ldapProviders(), webLogin: true}
	s, err := run(t, f, nil, "alice", "pw")
	if err != nil {
		t.Fatalf("a login the real console would accept was refused: %v", err)
	}
	if !f.gotJSON.Load() {
		t.Error("the console posts JSON; a form-encoded body is not what KubeSphere's web login endpoint receives")
	}
	if s.Headers["Authorization"] != "Bearer AT" || s.Tokens["access_token"] != "AT" || s.Tokens["refresh_token"] != "RT" || s.Tokens["identity_provider"] != "ldap" {
		t.Errorf("token must come from the Set-Cookie of the 302: %+v", s)
	}
	if s.ExpiresAt.IsZero() {
		t.Error("the expire cookie (milliseconds since the epoch) gives the expiry")
	}
	if f.attempts.Load() != 1 {
		t.Errorf("%d login attempts; failed attempts lock accounts, so exactly one is allowed", f.attempts.Load())
	}
	// the cached session must still be accepted by the probe when the cookie variant is used
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if err := (&driver{}).Probe(context.Background(), u, s, srv.Client()); err != nil {
		t.Errorf("probe of the new session: %v", err)
	}
}

func TestWebConsoleFailureIsNotMistakenForSuccessOrSiteError(t *testing.T) {
	f := &fakeKS{providers: ldapProviders(), webLogin: true}
	_, err := run(t, f, nil, "alice", "WRONG")
	if err == nil {
		t.Fatal("a refused login was accepted")
	}
	if !errors.Is(err, site.ErrBadCredentials) && !errors.Is(err, site.ErrLoginRejected) {
		t.Fatalf("must be a classified failure, got %v", err)
	}
	// KubeSphere answers 200 {"status":500} for a wrong password and for an unreachable LDAP alike, so the
	// message must say both, not claim one of them.
	for _, want := range []string{"password", "LDAP"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message should mention %q: %v", want, err)
		}
	}
}

// The console submits exactly {username, password, title} to /oauth/login/<title> (read from its login bundle):
// the identity provider's name goes into the body as "title", and nothing else is sent.
func TestLDAPBodyIsExactlyWhatTheConsoleSends(t *testing.T) {
	f := &fakeKS{providers: ldapProviders(), webLogin: true}
	if _, err := run(t, f, nil, "alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.bodyKeys.Load().([]string); strings.Join(got, ",") != "password,title,username" {
		t.Errorf("body fields = %v, want exactly password, title, username (no empty otp)", got)
	}
	if got, _ := f.title.Load().(string); got != "ldap" {
		t.Errorf("title = %q, want the identity provider name %q", got, "ldap")
	}
	// an explicitly configured provider name is what goes into title, and into the path
	f2 := &fakeKS{webLogin: true}
	run(t, f2, map[string]string{"identity_provider": "corp-ldap"}, "alice", "pw")
	if got, _ := f2.title.Load().(string); got != "corp-ldap" {
		t.Errorf("title for identity_provider corp-ldap = %q", got)
	}
}

// A second factor is the one case where the body gains a field.
func TestOTPFieldOnlyAppearsWhenAsked(t *testing.T) {
	b := jsonLoginBody(url.Values{"username": {"a"}, "password": {"p"}}, "ldap")
	if strings.Contains(b, "otp") {
		t.Errorf("no code was asked for, so no otp field: %s", b)
	}
	b = jsonLoginBody(url.Values{"username": {"a"}, "password": {"p"}, "otp": {"123456"}}, "ldap")
	if !strings.Contains(b, `"otp":"123456"`) || !strings.Contains(b, `"title":"ldap"`) {
		t.Errorf("a given code must be sent along with title: %s", b)
	}
}

// Even on the right endpoint a redirect must not be followed: a gateway or session timeout that bounces the API
// call to the login page (which answers 200) must read as "not logged in".
func TestProbeRefusesARedirectToTheLoginPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>sign in</html>")) })
	mux.HandleFunc("/kapis/resources.kubesphere.io/v1alpha2/namespaces", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	s := &site.Session{Headers: map[string]string{"Authorization": "Bearer AT"}}
	if err := (&driver{}).Probe(context.Background(), u, s, srv.Client()); err == nil {
		t.Fatal("a redirect to the login page was accepted as a valid session")
	}
}
