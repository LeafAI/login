package mcpserver

import "testing"

func fullLogin(site string) *LoginOutput {
	return &LoginOutput{Status: "ok", Site: site, BaseURL: "https://x.example", Auth: "cookie", CookieHeader: "sid=SECRET",
		Cookies: []CookieOut{{Name: "sid", Value: "SECRET"}}, Headers: map[string]string{"Authorization": "Bearer SECRET"},
		Tokens: map[string]string{"access_token": "SECRET"}}
}

func TestRedactOnlyForArchery(t *testing.T) {
	r := redactForAgent(fullLogin("archery"))
	if !r.Redacted || r.CookieHeader != "" || r.Cookies != nil || r.Headers != nil || r.Tokens != nil {
		t.Fatalf("archery must be redacted: %+v", r)
	}
	if r.Site != "archery" || r.Auth != "cookie" || r.BaseURL == "" || r.Status != "ok" {
		t.Errorf("the descriptive fields must survive: %+v", r)
	}
	for _, site := range []string{"gitlab", "kibana", "kubesphere", "nightingale", "jenkins", "skywalking", "grafana"} {
		o := redactForAgent(fullLogin(site))
		if o.Redacted || o.CookieHeader != "sid=SECRET" || len(o.Cookies) != 1 || o.Headers["Authorization"] == "" || o.Tokens["access_token"] == "" {
			t.Errorf("%s keeps its credentials, the agent uses them directly: %+v", site, o)
		}
	}
}

func TestRedactDoesNotTouchTheCachedOriginalNorPendingResults(t *testing.T) {
	orig := fullLogin("archery")
	_ = redactForAgent(orig)
	if orig.CookieHeader == "" || orig.Redacted {
		t.Fatal("redaction must work on a copy: the cache and the archery_* tools still need the session")
	}
	p := &LoginOutput{Status: "pending", Site: "archery", LoginID: "lg_1", NextTool: "login_wait"}
	if got := redactForAgent(p); got != p || got.Redacted {
		t.Errorf("a pending result is returned unchanged: %+v", got)
	}
	if redactForAgent(nil) != nil {
		t.Error("nil stays nil")
	}
}
