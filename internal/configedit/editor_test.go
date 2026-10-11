package configedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site/generic"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "login", "config.yaml")
	if content != "" {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func reload(t *testing.T, p string) *config.Config {
	t.Helper()
	c, err := config.Load(p)
	if err != nil {
		t.Fatalf("saved file does not load: %v", err)
	}
	return c
}

func TestSetKeepsCommentsAndOtherKeys(t *testing.T) {
	p := write(t, "# my login config\ndingtalk:\n  webhook: https://oapi.dingtalk.com/robot/send?access_token=abc # robot\nmcp: {max_block_seconds: 30}\n")
	e, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Set("dingtalk.secret", "SEC123"); err != nil {
		t.Fatal(err)
	}
	if err := e.Set("keys.max_age", "12h"); err != nil {
		t.Fatal(err)
	}
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	for _, want := range []string{"# my login config", "# robot", "max_block_seconds: 30", "SEC123", "max_age: 12h"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("saved file lost %q:\n%s", want, raw)
		}
	}
	c := reload(t, p)
	if c.DingTalk.Secret != "SEC123" || c.MCP.MaxBlockSeconds != 30 || c.Keys.MaxAge.Hours() != 12 {
		t.Fatalf("unexpected config %+v", c)
	}
}

func TestSaveCreatesPrivateFileAndBackup(t *testing.T) {
	p := write(t, "")
	e, _ := Open(p)
	if err := e.Set("dingtalk.keyword", "login"); err != nil {
		t.Fatal(err)
	}
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode: %v %v", st, err)
	}
	if _, err := os.Stat(p + ".bak"); err == nil {
		t.Fatal("no backup expected for a brand new file")
	}
	e2, _ := Open(p)
	_ = e2.Set("dingtalk.keyword", "other")
	if err := e2.Save(); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(p + ".bak")
	if err != nil || !strings.Contains(string(bak), "keyword: login") {
		t.Fatalf("backup should hold the previous version, got %q (%v)", bak, err)
	}
}

func TestSetRejectsBadInput(t *testing.T) {
	e, _ := Open(write(t, ""))
	cases := map[string][2]string{
		"unknown":       {"dingtalk.webhok", "x"},
		"section":       {"dingtalk", "x"},
		"bad bool":      {"sessions.persist", "maybe"},
		"bad int":       {"mcp.max_block_seconds", "fifty"},
		"bad duration":  {"keys.max_age", "tomorrow"},
		"sub key":       {"mcp.max_block_seconds.x", "1"},
		"entry list":    {"sites", "x"},
		"map w/o key":   {"aliases", "kibana"},
		"empty setting": {"", "x"},
	}
	for name, c := range cases {
		if err := e.Set(c[0], c[1]); err == nil {
			t.Errorf("%s: Set(%q,%q) should fail", name, c[0], c[1])
		}
	}
	if err := e.Set("dingtalk.webhok", "x"); err == nil || !strings.Contains(err.Error(), "dingtalk.webhook") {
		t.Errorf("a typo should suggest the right key, got %v", err)
	}
}

func TestMapsAndListsAndNestedOptions(t *testing.T) {
	p := write(t, "")
	e, _ := Open(p)
	for k, v := range map[string]string{
		"aliases.es.corp.example":                   "kibana", // host names contain dots
		"roots.elk.corp.example":                    "https://elk.corp.example/kibana",
		"site_options.gitlab.login_method":          "ldap",
		"security.allowed_hosts":                    "*.corp.example, 10.0.0.1",
		"tunnel.order":                              "pinggy,serveo",
		"archery.allow_ddl":                         "false",
		"dingtalk.at_mobiles":                       "13800000000",
		"site_options.kubesphere.identity_provider": "corp-ldap",
	} {
		if err := e.Set(k, v); err != nil {
			t.Fatalf("Set(%s): %v", k, err)
		}
	}
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	c := reload(t, p)
	if c.Aliases["es.corp.example"] != "kibana" || c.Roots["elk.corp.example"] == "" ||
		c.SiteOptions["gitlab"]["login_method"] != "ldap" || c.SiteOptions["kubesphere"]["identity_provider"] != "corp-ldap" ||
		len(c.Security.AllowedHosts) != 2 || c.Security.AllowedHosts[1] != "10.0.0.1" ||
		len(c.Tunnel.Order) != 2 || c.Archery.DDLAllowed() || len(c.DingTalk.Mobiles) != 1 {
		t.Fatalf("round trip lost data: %+v", c)
	}
	if v, ok, _ := e.Get("security.allowed_hosts"); !ok || v != "*.corp.example,10.0.0.1" {
		t.Fatalf("Get list = %q %v", v, ok)
	}
}

func TestUnsetRemovesEmptySections(t *testing.T) {
	p := write(t, "site_options:\n  gitlab:\n    login_method: ldap\nmcp: {max_block_seconds: 30}\n")
	e, _ := Open(p)
	if ok, err := e.Unset("site_options.gitlab.login_method"); !ok || err != nil {
		t.Fatalf("Unset = %v %v", ok, err)
	}
	if ok, _ := e.Unset("site_options.gitlab.login_method"); ok {
		t.Fatal("second Unset must report nothing removed")
	}
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "site_options") || !strings.Contains(string(raw), "max_block_seconds") {
		t.Fatalf("empty section should vanish, others stay:\n%s", raw)
	}
}

func TestSaveRefusesInvalidConfig(t *testing.T) {
	p := write(t, "dingtalk:\n  webhok: typo\n")
	e, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Save(); err == nil || !strings.Contains(err.Error(), "webhok") {
		t.Fatalf("a file with an unknown key must not be re-saved silently: %v", err)
	}
}

func TestOpenRejectsBrokenFiles(t *testing.T) {
	if _, err := Open(write(t, "dingtalk: [unclosed\n")); err == nil {
		t.Error("invalid YAML accepted")
	}
	if _, err := Open(write(t, "- a\n- b\n")); err == nil {
		t.Error("a top-level list accepted")
	}
}

func TestSites(t *testing.T) {
	p := write(t, "")
	e, _ := Open(p)
	spec := generic.Spec{Name: "grafana", MatchHost: "grafana",
		Steps: []generic.Step{{Method: "POST", Path: "/login", JSON: map[string]any{"user": "{{username}}", "password": "{{password}}"}}},
		Probe: generic.Probe{Path: "/api/user"}}
	if err := e.SetSite(spec); err != nil {
		t.Fatal(err)
	}
	spec.MatchHost = "graf"
	if err := e.SetSite(spec); err != nil { // same name: replaced, not duplicated
		t.Fatal(err)
	}
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	c := reload(t, p)
	if len(c.Sites) != 1 || c.Sites[0].MatchHost != "graf" || c.Sites[0].Probe.Path != "/api/user" {
		t.Fatalf("sites = %+v", c.Sites)
	}
	e2, _ := Open(p)
	if !e2.RemoveSite("grafana") || e2.RemoveSite("grafana") {
		t.Fatal("RemoveSite should succeed once")
	}
	if err := e2.Save(); err != nil {
		t.Fatal(err)
	}
	if len(reload(t, p).Sites) != 0 {
		t.Fatal("site not removed")
	}
	bad := generic.Spec{Name: "x"} // no steps
	if err := e2.SetSite(bad); err != nil {
		t.Fatal(err)
	}
	if err := e2.Save(); err == nil {
		t.Fatal("an unbuildable site must be refused at save time")
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	p := write(t, "dingtalk:\n  webhook: https://oapi.dingtalk.com/robot/send?access_token=0123456789abcdef\n  secret: SECabcdefghijkl\n")
	e, _ := Open(p)
	out, err := e.Redacted()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"0123456789abcdef", "SECabcdefghijkl"} {
		if strings.Contains(s, leak) {
			t.Errorf("secret %q leaked:\n%s", leak, s)
		}
	}
	if !strings.Contains(s, "oapi.dingtalk.com") || !strings.Contains(s, "cdef") {
		t.Errorf("the host and the last 4 characters should stay for recognition:\n%s", s)
	}
	raw, _ := e.Bytes()
	if !strings.Contains(string(raw), "0123456789abcdef") {
		t.Error("Redacted must not alter the editor's own document")
	}
	if Mask("short") != "****" || Mask("") != "" || !IsSecret("dingtalk.secret") || IsSecret("dingtalk.keyword") {
		t.Error("Mask/IsSecret behave unexpectedly")
	}
}

func TestSettingsCoverTheSchema(t *testing.T) {
	have := map[string]string{}
	for _, s := range Settings() {
		have[s.Path] = s.Type
	}
	for path, typ := range map[string]string{
		"dingtalk.webhook": "string", "keys.max_age": "duration", "sessions.persist": "bool",
		"mcp.max_block_seconds": "int", "security.allowed_hosts": "list", "archery.allow_ddl": "bool",
		"site_options.<name>.<key>": "string", "aliases.<host>": "string",
	} {
		if have[path] != typ {
			t.Errorf("setting %s: got type %q, want %q", path, have[path], typ)
		}
	}
	if _, ok := have["sites"]; ok {
		t.Error("lists of entries are not settable as plain values")
	}
}

func TestTOTPSettingsAreKnownAndTyped(t *testing.T) {
	have := map[string]string{}
	for _, s := range Settings() {
		have[s.Path] = s.Type
	}
	for path, typ := range map[string]string{
		"security.link_totp.enabled": "bool", "security.link_totp.period": "duration", "security.link_totp.digits": "int", "security.link_totp.secret_file": "string",
		"security.seal_totp.enabled": "bool", "security.seal_totp.period": "duration", "security.seal_totp.digits": "int", "security.seal_totp.secret_file": "string",
	} {
		if have[path] != typ {
			t.Errorf("setting %s: got type %q, want %q", path, have[path], typ)
		}
	}
	p := write(t, "")
	e, _ := Open(p)
	if err := e.Set("security.link_totp.period", "10m"); err != nil {
		t.Fatal(err)
	}
	if err := e.Set("security.link_totp.period", "tomorrow"); err == nil {
		t.Error("a period that is not a duration was accepted")
	}
	if err := e.Set("security.link_totp.digits", "eight"); err == nil {
		t.Error("digits that are not a number were accepted")
	}
}
