package generic

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/sitetest"
)

const spec = `
name: grafana
match_host: grafana
steps:
  - method: POST
    path: /login
    json: {user: "{{username}}", password: "{{password}}"}
twofa:
  detect_body: "otp_required"
  step: {method: POST, path: /login/otp, form: {code: "{{code}}"}}
collect:
  tokens: {access: "data.token"}
  headers: {Authorization: "Bearer {{token:access}}"}
probe: {path: /api/user}
`

func TestGenericWithTOTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["user"] != "alice" || b["password"] != "pw" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"status":"otp_required"}`))
		case "/login/otp":
			r.ParseForm()
			if r.PostForm.Get("code") != "123456" {
				w.Write([]byte(`{"status":"otp_required"}`))
				return
			}
			w.Write([]byte(`{"data":{"token":"T"}}`))
		case "/api/user":
			if r.Header.Get("Authorization") != "Bearer T" {
				w.WriteHeader(401)
			}
		}
	}))
	defer srv.Close()
	var sp Spec
	if err := yaml.Unmarshal([]byte(spec), &sp); err != nil {
		t.Fatal(err)
	}
	d, err := New(sp)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	a := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}, "totp": {"code": "123456"}}}
	s, err := d.Login(context.Background(), u, a, srv.Client())
	if err != nil || s.Headers["Authorization"] != "Bearer T" || strings.Join(a.Asked, ",") != "login,totp" {
		t.Fatalf("%+v %v %v", s, err, a.Asked)
	}
	if err := d.Probe(context.Background(), u, s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := d.Login(context.Background(), u, bad, srv.Client()); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad creds: %v", err)
	}
}

func TestSpecRoundTripKeepsBodyKinds(t *testing.T) {
	spec := Spec{Name: "g", MatchHost: "g",
		Steps: []Step{{Method: "POST", Path: "/login", JSON: map[string]any{"u": "{{username}}"}}},
		TwoFA: &TwoFA{DetectBody: "otp", Step: Step{Method: "POST", Path: "/otp", Form: map[string]string{"code": "{{code}}"}}},
		Probe: Probe{Path: "/me"}}
	b, err := yaml.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, noise := range []string{"{}", "[]", "expect_status: 0"} {
		if strings.Contains(string(b), noise) {
			t.Errorf("empty fields must be omitted, found %q in:\n%s", noise, b)
		}
	}
	var back Spec
	if err := yaml.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.TwoFA.Step.JSON != nil || back.TwoFA.Step.Form["code"] != "{{code}}" {
		t.Fatalf("the 2FA step must stay a form, got %+v", back.TwoFA.Step)
	}
}

// A site defined in the configuration is checked the same way as the built-in ones: a session probe that cannot ask the
// site says ErrUnreachable (so the session is kept), and one that is told no does not.
func TestAConfiguredSitesProbeSeparatesCouldNotAskFromWasToldNo(t *testing.T) {
	d, err := New(Spec{Name: "g2", MatchHost: "g2",
		Steps: []Step{{Method: "POST", Path: "/login", JSON: map[string]any{"user": "{{username}}", "password": "{{password}}"}}},
		Probe: Probe{Path: "/api/me"}})
	if err != nil {
		t.Fatal(err)
	}
	sess := &site.Session{Headers: map[string]string{"Authorization": "Bearer TOKEN-VALUE-1234567890"}}

	down := httptest.NewServer(http.NotFoundHandler())
	base, _ := url.Parse(down.URL)
	down.Close()
	if err := d.Probe(context.Background(), base, sess, http.DefaultClient); !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a site that cannot be asked: %v", err)
	}

	no := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) }))
	defer no.Close()
	base2, _ := url.Parse(no.URL)
	if err := d.Probe(context.Background(), base2, sess, http.DefaultClient); err == nil || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a site that answered 401: %v", err)
	}
}

// A configured site may expect any status from its probe. A temporary status is "could not tell" unless the site is configured
// to expect exactly that status (a health endpoint that answers 503 on purpose is the site's own definition of "valid").
func TestAConfiguredSitesProbeReadsTemporaryStatusesAndHonoursTheExpectedOne(t *testing.T) {
	mk := func(expect int) site.Driver {
		d, err := New(Spec{Name: "g3", MatchHost: "g3",
			Steps: []Step{{Method: "POST", Path: "/login", JSON: map[string]any{"u": "{{username}}"}}},
			Probe: Probe{Path: "/me", ExpectStatus: expect}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	probe := func(d site.Driver, code int) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", code) }))
		defer srv.Close()
		base, _ := url.Parse(srv.URL)
		return d.Probe(context.Background(), base, &site.Session{}, http.DefaultClient)
	}
	d := mk(0)
	for _, code := range []int{502, 503, 504, 429} {
		if err := probe(d, code); !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("HTTP %d: %v", code, err)
		}
	}
	for _, code := range []int{401, 403, 500} {
		if err := probe(d, code); err == nil || errors.Is(err, site.ErrUnreachable) {
			t.Errorf("HTTP %d: %v", code, err)
		}
	}
	if err := probe(mk(503), 503); err != nil {
		t.Errorf("a site that is configured to expect 503 has a valid session when it answers 503: %v", err)
	}
	if err := probe(mk(302), 302); err != nil {
		t.Errorf("expect_status is still honoured: %v", err)
	}
	if err := probe(mk(302), 200); err == nil {
		t.Error("and any other status is not what it expects")
	}
}
