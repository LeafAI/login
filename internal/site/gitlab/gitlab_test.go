package gitlab

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/sitetest"
)

// fakeGitLab imitates the sign-in form flow, optionally with TOTP 2FA.
func fakeGitLab(twoFA bool) *httptest.Server {
	const form = `<form><input type="hidden" name="authenticity_token" value="TOK&#43;1"/><input name="user[login]"/><input name="user[password]"/></form>`
	const otp = `<form><input type="hidden" name="authenticity_token" value="TOK2"/><input name="user[otp_attempt]"/></form>`
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(form))
			return
		}
		r.ParseForm()
		ok := func() {
			http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "sess", Path: "/"})
			http.Redirect(w, r, "/", 302)
		}
		if code := r.PostForm.Get("user[otp_attempt]"); code != "" {
			if r.PostForm.Get("authenticity_token") == "TOK2" && code == "123456" {
				ok()
			} else {
				w.Write([]byte(otp))
			}
			return
		}
		if r.PostForm.Get("authenticity_token") != "TOK+1" || r.PostForm.Get("user[login]") != "alice" || r.PostForm.Get("user[password]") != "pw" {
			w.Write([]byte(form)) // GitLab re-renders the form on failure
			return
		}
		if twoFA {
			w.Write([]byte(otp))
			return
		}
		ok()
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
	u, _ := url.Parse(srv.URL)
	return driver{}.Login(context.Background(), u, a, srv.Client())
}

func TestLoginNo2FA(t *testing.T) {
	srv := fakeGitLab(false)
	defer srv.Close()
	a := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}}}
	s, err := login(t, srv, a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.Asked, ",") != "login" {
		t.Errorf("rounds asked: %v", a.Asked)
	}
	u, _ := url.Parse(srv.URL)
	if err := (driver{}).Probe(context.Background(), u, s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
}

func TestLoginDetects2FAAndLaunchesSecondRound(t *testing.T) {
	srv := fakeGitLab(true)
	defer srv.Close()
	a := &sitetest.Asker{Answers: map[string]site.Credentials{
		"login": {"username": "alice", "password": "pw"}, "totp": {"code": " 123456 "}}}
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
}

func TestBadPasswordAndBadCode(t *testing.T) {
	srv := fakeGitLab(true)
	defer srv.Close()
	a := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "WRONG"}}}
	if _, err := login(t, srv, a); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad password: %v", err)
	}
	a = &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}, "totp": {"code": "000000"}}}
	if _, err := login(t, srv, a); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad code: %v", err)
	}
}

func TestRejectPropagates(t *testing.T) {
	srv := fakeGitLab(false)
	defer srv.Close()
	_, err := login(t, srv, &sitetest.Asker{Reject: "not now"})
	var rj *sitetest.Rejected
	if !errors.As(err, &rj) || rj.Reason != "not now" {
		t.Errorf("err = %v", err)
	}
}
