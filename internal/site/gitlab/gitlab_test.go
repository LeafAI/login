package gitlab

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/sitetest"
)

type flavor int

const (
	classic flavor = iota // server-rendered forms with user[login]/user[password]/user[otp_attempt] inputs
	modern                // Vue sign-in and 2FA steps: token only in <meta name="csrf-token">, <div id="js-2fa">
)

type opts struct {
	flavor flavor
	twoFA  bool
	totp   bool // modern pages: data-totp-enabled
	ldap   bool // classic pages with an LDAP tab (account "alice" lives in LDAP and has no local password)
}

// fakeGitLab imitates GitLab's /users/sign_in in both page generations, optionally with TOTP 2FA.
func fakeGitLab(o opts) *httptest.Server {
	meta := func(tok string) string {
		return `<meta name="csrf-param" content="authenticity_token" /><meta name="csrf-token" content="` + tok + `" />`
	}
	signIn := func() string {
		if o.ldap {
			return `<ul class="nav-tabs"><li>main</li><li>Standard</li></ul>
<div id="ldapmain"><form action="/users/auth/ldapmain/callback" method="post"><input type="hidden" name="authenticity_token" value="LTOK"/><input name="username"/><input class="js-password" data-name="password"/></form></div>
<div id="login-pane"><form action="/users/sign_in" method="post"><input type="hidden" name="authenticity_token" value="TOK&#43;1"/><input name="user[login]"/><input name="user[password]"/></form></div>`
		}
		if o.flavor == modern {
			return `<html><head>` + meta("TOK+1") + `</head><body><div class="js-non-oauth-login"></div></body></html>`
		}
		return `<form><input type="hidden" name="authenticity_token" value="TOK&#43;1"/><input name="user[login]"/><input name="user[password]"/></form>`
	}
	otpPage := func() string {
		if o.flavor == modern {
			return `<html><head>` + meta("TOK2") + `</head><body><div id="js-2fa" data-path="/users/sign_in" data-totp-enabled="` +
				map[bool]string{true: "true", false: "false"}[o.totp] + `" data-webauthn-enabled="true"></div></body></html>`
		}
		return `<form action="/users/sign_in" method="post"><input type="hidden" name="authenticity_token" value="TOK2"/><input name="user[otp_attempt]"/></form>`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(signIn()))
			return
		}
		r.ParseForm()
		ok := func() {
			http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "sess", Path: "/"})
			http.Redirect(w, r, "/", 302)
		}
		if code := r.PostForm.Get("user[otp_attempt]"); code != "" {
			good := r.PostForm.Get("authenticity_token") == "TOK2" && code == "123456"
			if o.flavor == modern {
				good = good && r.PostForm.Get("two_factor_method") == "totp"
			}
			if good {
				ok()
			} else {
				w.Write([]byte(otpPage()))
			}
			return
		}
		login, pass := "alice", "pw"
		if o.ldap { // LDAP users have no local password; only local accounts use the standard form
			login, pass = "admin", "adminpw"
		}
		if r.PostForm.Get("authenticity_token") != "TOK+1" || r.PostForm.Get("user[login]") != login || r.PostForm.Get("user[password]") != pass {
			if o.flavor == modern { // current GitLab redirects back to the sign-in page with a flash message
				http.Redirect(w, r, "/users/sign_in", 302)
				return
			}
			w.Write([]byte(signIn()))
			return
		}
		if o.twoFA {
			w.Write([]byte(otpPage()))
			return
		}
		ok()
	})
	mux.HandleFunc("/users/auth/ldapmain/callback", func(w http.ResponseWriter, r *http.Request) {
		if !o.ldap || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		r.ParseForm()
		if r.PostForm.Get("authenticity_token") != "LTOK" || r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
			http.Redirect(w, r, "/users/sign_in", 302) // GitLab: flash "Invalid Login or password"
			return
		}
		if o.twoFA {
			w.Write([]byte(otpPage())) // prompt_for_two_factor renders the OTP form (posting to /users/sign_in)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "sess", Path: "/"})
		http.Redirect(w, r, "/", 302)
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != "sess" {
			http.Error(w, "401", 401)
			return
		}
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("dashboard")) })
	return httptest.NewServer(mux)
}

func login(t *testing.T, srv *httptest.Server, a *sitetest.Asker) (*site.Session, error) {
	return loginWith(t, srv, a, nil)
}

func loginWith(t *testing.T, srv *httptest.Server, a *sitetest.Asker, options map[string]string) (*site.Session, error) {
	u, _ := url.Parse(srv.URL)
	d := &driver{}
	d.Configure(options)
	return d.Login(context.Background(), u, a, srv.Client())
}

func each(t *testing.T, fn func(t *testing.T, f flavor)) {
	t.Run("classic", func(t *testing.T) { fn(t, classic) })
	t.Run("modern", func(t *testing.T) { fn(t, modern) })
}

func good() *sitetest.Asker {
	return &sitetest.Asker{Answers: map[string]site.Credentials{
		"login": {"username": "alice", "password": "pw"}, "totp": {"code": " 123456 "}}}
}

func TestLoginNo2FA(t *testing.T) {
	each(t, func(t *testing.T, f flavor) {
		srv := fakeGitLab(opts{flavor: f})
		defer srv.Close()
		a := good()
		s, err := login(t, srv, a)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(a.Asked, ",") != "login" {
			t.Errorf("rounds asked: %v", a.Asked)
		}
		u, _ := url.Parse(srv.URL)
		if err := (&driver{}).Probe(context.Background(), u, s, srv.Client()); err != nil {
			t.Errorf("probe: %v", err)
		}
	})
}

func TestLoginDetects2FAAndLaunchesSecondRound(t *testing.T) {
	each(t, func(t *testing.T, f flavor) {
		srv := fakeGitLab(opts{flavor: f, twoFA: true, totp: true})
		defer srv.Close()
		a := good()
		s, err := login(t, srv, a)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(a.Asked, ",") != "login,totp" {
			t.Errorf("rounds asked: %v", a.Asked)
		}
		if len(s.Cookies) == 0 {
			t.Error("no cookies")
		}
	})
}

func TestBadPasswordAndBadCode(t *testing.T) {
	each(t, func(t *testing.T, f flavor) {
		srv := fakeGitLab(opts{flavor: f, twoFA: true, totp: true})
		defer srv.Close()
		a := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "WRONG"}}}
		if _, err := login(t, srv, a); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("bad password: %v", err)
		}
		a = &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}, "totp": {"code": "000000"}}}
		if _, err := login(t, srv, a); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("bad code: %v", err)
		}
	})
}

// A modern account whose only second factor is WebAuthn/email must not be asked for a TOTP code.
func TestTOTPNotEnabledIsExplained(t *testing.T) {
	srv := fakeGitLab(opts{flavor: modern, twoFA: true, totp: false})
	defer srv.Close()
	a := good()
	_, err := login(t, srv, a)
	if !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "WebAuthn") {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(a.Asked, ",") != "login" {
		t.Errorf("a TOTP round was started: %v", a.Asked)
	}
}

func TestRejectPropagates(t *testing.T) {
	srv := fakeGitLab(opts{})
	defer srv.Close()
	_, err := login(t, srv, &sitetest.Asker{Reject: "not now"})
	var rj *sitetest.Rejected
	if !errors.As(err, &rj) || rj.Reason != "not now" {
		t.Errorf("err = %v", err)
	}
}

// LDAP-enabled GitLab (16.8 style): the LDAP tab form posts to /users/auth/ldapmain/callback.
func TestLDAPLoginIsChosenAutomatically(t *testing.T) {
	srv := fakeGitLab(opts{ldap: true})
	defer srv.Close()
	a := good()
	s, err := login(t, srv, a)
	if err != nil || len(s.Cookies) == 0 || strings.Join(a.Asked, ",") != "login" {
		t.Fatalf("%+v %v %v", s, err, a.Asked)
	}
}

func TestLDAPWithTOTP(t *testing.T) {
	srv := fakeGitLab(opts{ldap: true, twoFA: true, totp: true})
	defer srv.Close()
	a := good()
	s, err := login(t, srv, a)
	if err != nil || len(s.Cookies) == 0 {
		t.Fatalf("%+v %v", s, err)
	}
	if strings.Join(a.Asked, ",") != "login,totp" {
		t.Errorf("rounds asked: %v", a.Asked)
	}
	// wrong password never reaches the second round
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "WRONG"}}}
	if _, err := login(t, srv, bad); !errors.Is(err, site.ErrBadCredentials) || len(bad.Asked) != 1 {
		t.Errorf("bad ldap password: %v asked=%v", err, bad.Asked)
	}
	wrongCode := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}, "totp": {"code": "000000"}}}
	if _, err := login(t, srv, wrongCode); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad code: %v", err)
	}
}

func TestLoginMethodOptions(t *testing.T) {
	srv := fakeGitLab(opts{ldap: true})
	defer srv.Close()
	local := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "admin", "password": "adminpw"}}}
	// auto picks LDAP, so a local-only account fails there...
	if _, err := login(t, srv, local); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("local account via auto/ldap: %v", err)
	}
	// ...and works when the standard form is requested.
	if _, err := loginWith(t, srv, local, map[string]string{"login_method": "standard"}); err != nil {
		t.Errorf("standard form: %v", err)
	}
	// explicit ldap provider name
	if _, err := loginWith(t, srv, good(), map[string]string{"login_method": "ldap", "ldap_provider": "ldapmain"}); err != nil {
		t.Errorf("explicit provider: %v", err)
	}
}

func inspect(t *testing.T, o opts, options map[string]string) string {
	t.Helper()
	srv := fakeGitLab(o)
	defer srv.Close()
	d := &driver{}
	d.Configure(options)
	u, _ := url.Parse(srv.URL)
	out, err := d.Inspect(context.Background(), u, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}

func TestInspectDescribesTheServer(t *testing.T) {
	if got := inspect(t, opts{ldap: true}, nil); !strings.Contains(got, `LDAP sign-in tab found (provider "ldapmain")`) || !strings.Contains(got, "classic") {
		t.Errorf("ldap/classic:\n%s", got)
	}
	if got := inspect(t, opts{flavor: modern}, nil); !strings.Contains(got, "no LDAP tab") || !strings.Contains(got, "JavaScript") {
		t.Errorf("modern:\n%s", got)
	}
	if got := inspect(t, opts{ldap: true}, map[string]string{"login_method": "standard"}); !strings.Contains(got, "forces: standard") {
		t.Errorf("override not reported:\n%s", got)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if _, err := (&driver{}).Inspect(context.Background(), u, srv.Client()); err == nil {
		t.Error("a non-GitLab server was accepted")
	}
}
