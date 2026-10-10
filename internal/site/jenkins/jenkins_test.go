package jenkins

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
	"github.com/LeafAI/login/internal/site/sitetest"
)

type fake struct {
	action string // form action: j_acegi_security_check (2.226) or j_spring_security_check (newer)
	crumbs bool   // CSRF protection enabled
	extra  bool   // a 2FA-style second step: the form is accepted but the session stays anonymous
}

func (f fake) handler() http.Handler {
	login := func(w http.ResponseWriter, errMsg string) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID.abc", Value: "ANON", Path: "/"})
		w.Write([]byte(`<html><body>` + errMsg + `<form name="login" action="` + f.action + `" method="post">
<input name="j_username" id="j_username"/><input type="password" name="j_password"/><input type="hidden" name="from" value="/"/></form></body></html>`))
	}
	authed := func(r *http.Request) bool {
		c, err := r.Cookie("JSESSIONID.abc")
		return err == nil && c.Value == "SESS"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { login(w, "") })
	mux.HandleFunc("/loginError", func(w http.ResponseWriter, r *http.Request) {
		login(w, `<div class="alert">Invalid username or password</div>`)
	})
	mux.HandleFunc("/"+f.action, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Method != "POST" || r.PostForm.Get("j_username") != "alice" || r.PostForm.Get("j_password") != "pw" {
			http.Redirect(w, r, "/loginError", 302)
			return
		}
		if !f.extra { // the session id is replaced on login (session fixation protection)
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID.abc", Value: "SESS", Path: "/"})
		}
		http.Redirect(w, r, "/", 302)
	})
	mux.HandleFunc("/whoAmI/api/json", func(w http.ResponseWriter, r *http.Request) {
		if authed(r) {
			json.NewEncoder(w).Encode(map[string]any{"anonymous": false, "authenticated": true, "name": "alice", "authorities": []string{"authenticated"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"anonymous": true, "authenticated": true, "name": "anonymous"})
	})
	mux.HandleFunc("/crumbIssuer/api/json", func(w http.ResponseWriter, r *http.Request) {
		if !f.crumbs {
			http.NotFound(w, r)
			return
		}
		if !authed(r) {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"crumb": "C-sess-ip", "crumbRequestField": "Jenkins-Crumb"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("dashboard")) })
	return mux
}

func run(t *testing.T, f fake, base string, a *sitetest.Asker) (*site.Session, error) {
	srv := httptest.NewServer(http.StripPrefix(base, f.handler()))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + base)
	return driver{}.Login(context.Background(), u, a, srv.Client())
}

func creds(pw string) *sitetest.Asker {
	return &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": pw}}}
}

func TestLoginJenkins226ReturnsSessionAndCrumb(t *testing.T) {
	a := creds("pw")
	s, err := run(t, fake{action: "j_acegi_security_check", crumbs: true}, "", a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.Asked, ",") != "login" {
		t.Errorf("asked %v", a.Asked)
	}
	if got := site.CookieHeader(s.Cookies); !strings.Contains(got, "JSESSIONID.abc=SESS") {
		t.Errorf("cookies %q (the post-login session id must win over the anonymous one)", got)
	}
	if s.Headers["Jenkins-Crumb"] != "C-sess-ip" || s.Tokens["user"] != "alice" {
		t.Errorf("headers=%v tokens=%v", s.Headers, s.Tokens)
	}
}

func TestFormActionIsReadFromThePage(t *testing.T) {
	if _, err := run(t, fake{action: "j_spring_security_check"}, "", creds("pw")); err != nil {
		t.Fatalf("newer Jenkins form action: %v", err)
	}
	s, err := run(t, fake{action: "j_acegi_security_check"}, "", creds("pw"))
	if err != nil || len(s.Headers) != 0 {
		t.Errorf("CSRF protection off should mean no crumb header: %+v %v", s, err)
	}
}

func TestJenkinsUnderContextPath(t *testing.T) {
	if _, err := run(t, fake{action: "j_acegi_security_check", crumbs: true}, "/jenkins", creds("pw")); err != nil {
		t.Fatalf("under /jenkins: %v", err)
	}
}

func TestBadPasswordAndSecondStep(t *testing.T) {
	if _, err := run(t, fake{action: "j_acegi_security_check"}, "", creds("WRONG")); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad password: %v", err)
	}
	_, err := run(t, fake{action: "j_acegi_security_check", extra: true}, "", creds("pw"))
	if !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "anonymous") {
		t.Errorf("second step: %v", err)
	}
}

func TestNotJenkins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hello</html>")) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if _, err := (driver{}).Login(context.Background(), u, creds("pw"), srv.Client()); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("err = %v", err)
	}
}

func TestProbeDistinguishesAnonymousSessions(t *testing.T) {
	srv := httptest.NewServer(fake{action: "j_acegi_security_check"}.handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	good := &site.Session{Cookies: []*http.Cookie{{Name: "JSESSIONID.abc", Value: "SESS"}}}
	if err := (driver{}).Probe(context.Background(), u, good, srv.Client()); err != nil {
		t.Errorf("valid session: %v", err)
	}
	// anonymous read access makes whoAmI answer 200 with authenticated=true for anonymous too
	// (name "anonymous"): the fake mimics it, and the driver must still reject the session.
	anon := &site.Session{Cookies: []*http.Cookie{{Name: "JSESSIONID.abc", Value: "ANON"}}}
	if err := (driver{}).Probe(context.Background(), u, anon, srv.Client()); err == nil {
		t.Error("anonymous session accepted")
	}
}
