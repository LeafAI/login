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

	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/sitetest"
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
