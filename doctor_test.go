package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs fn and returns what it printed to stdout.
func capture(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := fn()
	w.Close()
	os.Stdout = old
	return <-done, code
}

func TestDoctorSiteInspectsAJenkins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jenkins/login":
			w.Write([]byte(`<form name="login" action="j_acegi_security_check" method="post"></form>`))
		case "/jenkins/whoAmI/api/json":
			w.Write([]byte(`{"anonymous":true,"authenticated":true,"name":"anonymous"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()
	cfg := "keys: {dir: " + dir + "/keys}\naliases: {\"" + host + "\": jenkins}\nroots: {\"" + host + "\": " + srv.URL + "/jenkins}\n"
	if err := os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := capture(t, func() int {
		return runDoctor([]string{"-config", filepath.Join(dir, "c.yaml"), "-site", srv.URL + "/jenkins/job/x"})
	})
	for _, want := range []string{`driver "jenkins"`, "/jenkins", "posts to j_acegi_security_check", "anonymous=true"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// the DingTalk webhook is not configured in this test, so the overall exit code is 1, but the site part is ok
	if strings.Contains(out, "FAIL] site") || strings.Contains(out, "FAIL] inspect") {
		t.Errorf("site inspection failed:\n%s", out)
	}
	_ = code

	// a host outside allowed_hosts is refused with the same rule the tools use
	cfg2 := cfg + "security: {allowed_hosts: [\"*.corp.example\"]}\n"
	os.WriteFile(filepath.Join(dir, "d.yaml"), []byte(cfg2), 0o600)
	out, _ = capture(t, func() int {
		return runDoctor([]string{"-config", filepath.Join(dir, "d.yaml"), "-site", srv.URL})
	})
	if !strings.Contains(out, "host_not_allowed") {
		t.Errorf("allowed_hosts not enforced:\n%s", out)
	}
}

func TestDoctorReportsAuditAndLimits(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("limits: {per_site: 3}\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if !strings.Contains(out, "[ok  ] audit log: "+filepath.Join(dir, "audit.jsonl")) {
		t.Errorf("doctor should check the audit log:\n%s", out)
	}
	if !strings.Contains(out, "at most 3 times per site") || !strings.Contains(out, "login config init") {
		t.Errorf("doctor should show the limits and point at `login config init`:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Errorf("the audit file should be creatable: %v", err)
	}
}
