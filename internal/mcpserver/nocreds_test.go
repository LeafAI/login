package mcpserver

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

// securl's promise is that the agent never holds a credential. session_open and session_wait therefore say that a
// session exists, for which site and how long, and nothing that could be used to act as the person.

func TestTheSessionResultTypeHasNoFieldThatCouldHoldACredential(t *testing.T) {
	ty := reflect.TypeFor[LoginOutput]()
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		tag := f.Tag.Get("json")
		low := strings.ToLower(f.Name + " " + tag)
		for _, bad := range []string{"cookie", "token", "header", "secret", "password", "credential", "redact"} {
			if strings.Contains(low, bad) {
				t.Errorf("LoginOutput.%s (%s): a result that can carry a credential will one day carry one", f.Name, tag)
			}
		}
		if f.Type.Kind() == reflect.Map {
			t.Errorf("LoginOutput.%s is a map: free-form data is where credentials hide", f.Name)
		}
	}
}

func TestNoTypeInTheMCPSurfaceCarriesACookieOrAToken(t *testing.T) {
	for _, ty := range []reflect.Type{reflect.TypeFor[LoginOutput](), reflect.TypeFor[SessionInfo](), reflect.TypeFor[SessionsOutput](), reflect.TypeFor[SitesOutput](),
		reflect.TypeFor[VaultUnlockOutput](), reflect.TypeFor[VaultStatusOutput](), reflect.TypeFor[LogoutOutput]()} {
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			if strings.Contains(strings.ToLower(f.Tag.Get("json")), "cookie") || strings.Contains(strings.ToLower(f.Tag.Get("json")), "token") {
				t.Errorf("%s.%s", ty.Name(), f.Name)
			}
		}
	}
	if _, ok := reflect.TypeFor[LoginOutput]().FieldByName("CookieHeader"); ok {
		t.Error("CookieHeader must not exist")
	}
}

func TestSessionOutputTellsWhichSiteAndHowItAuthenticatesButNotWithWhat(t *testing.T) {
	sess := &site.Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: "COOKIE-SECRET-aaaa1111", Path: "/", Secure: true}},
		Headers: map[string]string{"Authorization": "Bearer BEARER-SECRET-bbbb2222", "X-CSRFToken": "CSRF-SECRET-cccc3333"},
		Tokens:  map[string]string{"access_token": "TOKEN-SECRET-dddd4444", "api": "rest"},
	}
	out := sessionOutput("gitlab", mustURL(t, "https://gitlab.corp.example"), sess)
	raw, _ := json.Marshal(out)
	for _, secret := range []string{"COOKIE-SECRET", "BEARER-SECRET", "CSRF-SECRET", "TOKEN-SECRET", "sid", "Authorization", "X-CSRFToken", "access_token"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the session result carries %q: %s", secret, raw)
		}
	}
	if out.Status != "ok" || out.Site != "gitlab" || out.BaseURL != "https://gitlab.corp.example" {
		t.Errorf("it still says what exists: %+v", out)
	}
	// An Authorization header wins over cookies: a site that sends both is described by the stronger one.
	if out.Auth != "bearer" {
		t.Errorf("%+v", out)
	}
	cookieOnly := sessionOutput("gitlab", mustURL(t, "https://gitlab.corp.example"), &site.Session{Cookies: sess.Cookies})
	if cookieOnly.Auth != "cookie" {
		t.Errorf("%+v", cookieOnly)
	}
	bearer := sessionOutput("nightingale", mustURL(t, "https://n.example"), &site.Session{Headers: map[string]string{"Authorization": "Bearer x-secret-value"}})
	if bearer.Auth != "bearer" {
		t.Errorf("how the site authenticates is not a secret: %+v", bearer)
	}
	if none := sessionOutput("skywalking", mustURL(t, "https://s.example"), &site.Session{}); none.Auth != "none" {
		t.Errorf("%+v", none)
	}
}

func TestSessionOutputKeepsTheExpiry(t *testing.T) {
	out := sessionOutput("gitlab", mustURL(t, "https://g.example"), &site.Session{ExpiresAt: mustTime(t, "2031-01-02T03:04:05Z")})
	if out.ExpiresAt != "2031-01-02T03:04:05Z" {
		t.Errorf("when the session ends is what an agent needs to plan: %q", out.ExpiresAt)
	}
}

// Every site, cached or fresh: there is no site for which the credentials are handed over "by design" any more.
func TestEverySiteIsTreatedTheSame(t *testing.T) {
	for _, name := range []string{"gitlab", "jenkins", "kibana", "kubesphere", "nightingale", "archery", "skywalking", "some-configured-site"} {
		out := sessionOutput(name, mustURL(t, "https://x.example"), &site.Session{
			Cookies: []*http.Cookie{{Name: "sid", Value: "SECRET-VALUE-xyz98765"}}, Headers: map[string]string{"Authorization": "Bearer SECRET-VALUE-xyz98765"}})
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "SECRET-VALUE") {
			t.Errorf("%s: %s", name, raw)
		}
	}
}

func TestSessionsListNeverShowedCredentialsAndStillDoesNot(t *testing.T) {
	ty := reflect.TypeFor[SessionInfo]()
	for i := 0; i < ty.NumField(); i++ {
		low := strings.ToLower(ty.Field(i).Name)
		if strings.Contains(low, "cookie") || strings.Contains(low, "token") || strings.Contains(low, "header") {
			t.Errorf("%s", ty.Field(i).Name)
		}
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
