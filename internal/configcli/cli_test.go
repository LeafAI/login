package configcli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"

	_ "github.com/LeafAI/securl/internal/site/archery"
	_ "github.com/LeafAI/securl/internal/site/gitlab"
	_ "github.com/LeafAI/securl/internal/site/jenkins"
	_ "github.com/LeafAI/securl/internal/site/kibana"
	_ "github.com/LeafAI/securl/internal/site/kubesphere"
	_ "github.com/LeafAI/securl/internal/site/nightingale"
	_ "github.com/LeafAI/securl/internal/site/noauth"
)

type result struct {
	code     int
	out, err string
	path     string
}

// run executes `login config args` with the given typed answers against a fresh (or given) config file.
func run(t *testing.T, path, answers string, args ...string) result {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "login", "config.yaml")
	}
	var out, errb bytes.Buffer
	env := Env{Path: path, In: strings.NewReader(answers), Out: &out, Err: &errb}
	code := Run(args, env)
	return result{code, out.String(), errb.String(), path}
}

func load(t *testing.T, path string) *config.Config {
	t.Helper()
	c, err := config.Load(path)
	if err != nil {
		t.Fatalf("config does not load: %v", err)
	}
	return c
}

const hook = "https://oapi.dingtalk.com/robot/send?access_token=abcdef0123456789"

func TestInitWritesAValidConfig(t *testing.T) {
	sent := 0
	path := filepath.Join(t.TempDir(), "c.yaml")
	var out, errb bytes.Buffer
	env := Env{Path: path, Out: &out, Err: &errb,
		In: strings.NewReader(hook + "\nSEC123456789\nlogin\n13800000000\n*.corp.example\ny\ny\n"),
		SendTest: func(w, s, k string, m []string) error {
			sent++
			if w != hook || s != "SEC123456789" || k != "login" || len(m) != 1 {
				t.Errorf("test message got %q %q %q %v", w, s, k, m)
			}
			return nil
		}}
	if code := Run([]string{"init"}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	c := load(t, path)
	if c.DingTalk.Webhook != hook || c.DingTalk.Secret != "SEC123456789" || c.DingTalk.Keyword != "login" ||
		!c.Sessions.Persist || len(c.Security.AllowedHosts) != 1 || sent != 1 {
		t.Fatalf("config %+v sent=%d", c, sent)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("config must be private, mode %v", st.Mode())
	}
}

func TestInitRejectsBadWebhookThenAccepts(t *testing.T) {
	r := run(t, "", "http://example.com/x\n"+hook+"\n\n\n\n\nn\n", "init")
	if r.code != 0 {
		t.Fatalf("exit %d out=%s err=%s", r.code, r.out, r.err)
	}
	if !strings.Contains(r.out, "! expected the robot's https webhook") {
		t.Errorf("the wrong address should be explained:\n%s", r.out)
	}
	if load(t, r.path).DingTalk.Webhook != hook {
		t.Error("second answer not stored")
	}
}

func TestInitKeepsExistingValuesOnEnter(t *testing.T) {
	r := run(t, "", hook+"\nSEC111111111\nkw\n\n\nn\n", "init")
	if r.code != 0 {
		t.Fatal(r.err)
	}
	r2 := run(t, r.path, "\n\n\n\n\nn\n", "init") // everything: Enter
	if r2.code != 0 {
		t.Fatal(r2.err)
	}
	c := load(t, r.path)
	if c.DingTalk.Webhook != hook || c.DingTalk.Secret != "SEC111111111" || c.DingTalk.Keyword != "kw" {
		t.Fatalf("Enter must keep current values: %+v", c.DingTalk)
	}
}

func TestInitCancelledMidwayChangesNothing(t *testing.T) {
	r := run(t, "", hook+"\nSEC1\n", "init") // input ends before the end
	if r.code == 0 || !strings.Contains(r.err, "input ended") {
		t.Fatalf("exit %d err=%s", r.code, r.err)
	}
	if _, err := os.Stat(r.path); err == nil {
		t.Error("a half-answered wizard must not create the file")
	}
}

func TestSiteAddDetectedDriverWithOptions(t *testing.T) {
	// yes (use detected gitlab), no path prefix, option 2 = ldap, no provider name
	r := run(t, "", "y\n\n2\n\n", "site", "add", "https://gitlab.corp.example")
	if r.code != 0 {
		t.Fatalf("%s %s", r.out, r.err)
	}
	c := load(t, r.path)
	if c.SiteOptions["gitlab"]["login_method"] != "ldap" {
		t.Fatalf("site_options = %+v", c.SiteOptions)
	}
	if len(c.Aliases) != 0 || len(c.Roots) != 0 {
		t.Errorf("a detectable host needs no alias/root: %+v %+v", c.Aliases, c.Roots)
	}
}

func TestSiteAddUnknownHostGetsAliasAndRoot(t *testing.T) {
	// not detectable: pick kibana by name, served under /kibana (no kibana options to ask)
	r := run(t, "", "kibana\n/kibana\n", "site", "add", "es.corp.example")
	if r.code != 0 {
		t.Fatalf("%s %s", r.out, r.err)
	}
	c := load(t, r.path)
	if c.Aliases["es.corp.example"] != "kibana" || c.Roots["es.corp.example"] != "https://es.corp.example/kibana" {
		t.Fatalf("aliases=%v roots=%v", c.Aliases, c.Roots)
	}
}

func TestSiteAddPathInAddressBecomesRoot(t *testing.T) {
	r := run(t, "", "kibana\n", "site", "add", "https://elk.corp.example/kibana") // not detectable: pick by name
	if r.code != 0 {
		t.Fatalf("%s %s", r.out, r.err)
	}
	if got := load(t, r.path).Roots["elk.corp.example"]; got != "https://elk.corp.example/kibana" {
		t.Fatalf("root = %q", got)
	}
}

func TestSiteAddExtendsAllowList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if r := run(t, path, "", "set", "security.allowed_hosts", "*.other.example"); r.code != 0 {
		t.Fatal(r.err)
	}
	r := run(t, path, "y\n\n\n\ny\n", "site", "add", "https://gitlab.corp.example")
	if r.code != 0 {
		t.Fatalf("%s %s", r.out, r.err)
	}
	hosts := load(t, path).Security.AllowedHosts
	if len(hosts) != 2 || hosts[1] != "gitlab.corp.example" {
		t.Fatalf("allowed_hosts = %v", hosts)
	}
}

func TestSiteCustomBuildsAWorkingSpec(t *testing.T) {
	answers := strings.Join([]string{
		"grafana", "", "/login", "1", "user", "pass", // name, match host (default), path, json, fields
		"2", "data.token", "", // token, path, header default Authorization
		"y", "otp_required", "/login/otp", "", // 2FA
		"/api/user", // probe
	}, "\n") + "\n"
	r := run(t, "", answers, "site", "custom")
	if r.code != 0 {
		t.Fatalf("%s %s", r.out, r.err)
	}
	c := load(t, r.path)
	if len(c.Sites) != 1 {
		t.Fatalf("sites = %+v", c.Sites)
	}
	s := c.Sites[0]
	if s.Name != "grafana" || s.MatchHost != "grafana" || s.Steps[0].JSON["user"] != "{{username}}" || s.Steps[0].JSON["pass"] != "{{password}}" ||
		s.Collect.Tokens["access"] != "data.token" || s.Collect.Headers["Authorization"] != "Bearer {{token:access}}" ||
		s.TwoFA == nil || s.TwoFA.Step.Form["code"] != "{{code}}" || s.Probe.Path != "/api/user" {
		t.Fatalf("spec = %+v", s)
	}
}

func TestSiteCustomRefusesBuiltinNamesAndBadInput(t *testing.T) {
	if r := run(t, "", "gitlab\ngitlab\n/login\n1\n\n\n1\nn\n\n", "site", "custom"); r.code == 0 {
		t.Fatal("a built-in driver name must be refused")
	}
	r := run(t, "", "Bad Name\nx\nxx\n", "site", "custom") // three invalid names in a row
	if r.code == 0 || !strings.Contains(r.out, "lowercase") {
		t.Fatalf("exit %d out=%s", r.code, r.out)
	}
}

func TestSiteListAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	run(t, path, "kibana\n/kibana\n", "site", "add", "es.corp.example")
	l := run(t, path, "", "site", "list")
	if l.code != 0 || !strings.Contains(l.out, "es.corp.example  driver=kibana  root=https://es.corp.example/kibana") {
		t.Fatalf("list:\n%s%s", l.out, l.err)
	}
	if r := run(t, path, "", "site", "remove", "es.corp.example"); r.code != 0 {
		t.Fatal(r.err)
	}
	c := load(t, path)
	if len(c.Aliases) != 0 || len(c.Roots) != 0 {
		t.Fatalf("not removed: %+v %+v", c.Aliases, c.Roots)
	}
	if r := run(t, path, "", "site", "remove", "es.corp.example"); r.code == 0 {
		t.Error("removing something that is not configured should say so")
	}
}

func TestSetGetUnsetShow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	for _, a := range [][]string{
		{"set", "mcp.max_block_seconds", "90"},
		{"set", "dingtalk.webhook", hook},
		{"set", "security.allowed_hosts", "*.a.example, *.b.example"},
	} {
		if r := run(t, path, "", a...); r.code != 0 {
			t.Fatalf("%v: %s", a, r.err)
		}
	}
	if g := run(t, path, "", "get", "mcp.max_block_seconds"); strings.TrimSpace(g.out) != "90" {
		t.Errorf("get = %q", g.out)
	}
	if g := run(t, path, "", "get", "dingtalk.webhook"); strings.Contains(g.out, "abcdef0123456789") {
		t.Errorf("get must mask secrets: %q", g.out)
	}
	if g := run(t, path, "", "get", "-reveal", "dingtalk.webhook"); !strings.Contains(g.out, "abcdef0123456789") {
		t.Errorf("-reveal should show the value: %q", g.out)
	}
	if s := run(t, path, "", "show"); strings.Contains(s.out, "abcdef0123456789") || !strings.Contains(s.out, "max_block_seconds: 90") {
		t.Errorf("show:\n%s", s.out)
	}
	if r := run(t, path, "", "unset", "mcp.max_block_seconds"); r.code != 0 {
		t.Fatal(r.err)
	}
	if g := run(t, path, "", "get", "mcp.max_block_seconds"); g.code == 0 {
		t.Error("an unset value must be reported as not set")
	}
	if r := run(t, path, "", "unset", "mcp.max_block_seconds"); r.code != 0 || !strings.Contains(r.out, "nothing to do") {
		t.Errorf("unsetting twice is harmless: %d %s", r.code, r.out)
	}
}

func TestSetSecretIsAskedNotTyped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if r := run(t, path, "SECtopsecret1\n", "set", "dingtalk.secret"); r.code != 0 {
		t.Fatal(r.err)
	}
	if load(t, path).DingTalk.Secret != "SECtopsecret1" {
		t.Error("secret not stored")
	}
	if r := run(t, path, "", "set", "mcp.max_block_seconds"); r.code == 0 {
		t.Error("a non-secret setting needs its value on the command line")
	}
}

func TestSetWithoutArgumentsListsSettings(t *testing.T) {
	r := run(t, "", "", "set")
	for _, want := range []string{"dingtalk.webhook", "keys.max_age", "aliases.<host>", "site_options.<name>.<key>"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q in:\n%s", want, r.out)
		}
	}
}

func TestInvalidChangesAreRefusedAndFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	run(t, path, "", "set", "mcp.max_block_seconds", "30")
	before, _ := os.ReadFile(path)
	for _, a := range [][]string{
		{"set", "site_options.gitlab.login_method", "saml"},
		{"set", "site_options.gitlab.nope", "x"},
		{"set", "aliases.x.example", "nosuchdriver"},
		{"set", "tunnel.order", "pinggy,nosuch"},
		{"set", "keys.max_age", "soon"},
		{"set", "no.such.key", "1"},
	} {
		if r := run(t, path, "", a...); r.code == 0 {
			t.Errorf("%v should have been refused", a)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Errorf("refused changes altered the file:\n%s", after)
	}
}

func TestPathHelpAndUnknown(t *testing.T) {
	if r := run(t, "/x/y.yaml", "", "path"); strings.TrimSpace(r.out) != "/x/y.yaml" {
		t.Errorf("path = %q", r.out)
	}
	if r := run(t, "", "", "help"); r.code != 0 || !strings.Contains(r.out, "site add") {
		t.Errorf("help: %d %s", r.code, r.out)
	}
	if r := run(t, "", ""); r.code != 0 || !strings.Contains(r.out, "usage") {
		t.Errorf("no args should print usage: %d", r.code)
	}
	if r := run(t, "", "", "frobnicate"); r.code != 2 {
		t.Errorf("unknown command exit = %d", r.code)
	}
}

func TestConfigFlagAnywhere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elsewhere.yaml")
	var out, errb bytes.Buffer
	code := Run([]string{"set", "mcp.max_block_seconds", "70", "-config", path}, Env{Path: "/nonexistent/dir/x.yaml", In: strings.NewReader(""), Out: &out, Err: &errb})
	if code != 0 || load(t, path).MCP.MaxBlockSeconds != 70 {
		t.Fatalf("exit %d %s", code, errb.String())
	}
}

func TestPrompterBehaviour(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("maybe\ny\n3\nzz\nlast"), &out, nil)
	if ok, err := p.Confirm("go", false); err != nil || !ok {
		t.Fatalf("Confirm = %v %v", ok, err)
	}
	if c, err := p.Choose("pick", []string{"a", "b", "c"}, "a"); err != nil || c != "c" {
		t.Fatalf("Choose = %q %v", c, err)
	}
	if v, err := p.Ask("free", "", func(s string) error {
		if s == "zz" {
			return errors.New("no zz")
		}
		return nil
	}); err != nil || v != "last" {
		t.Fatalf("Ask = %q %v (output %q)", v, err, out.String())
	}
	if _, err := p.Ask("more", "", nil); !errors.Is(err, ErrNoInput) {
		t.Fatalf("exhausted input should say so, got %v", err)
	}
}

func TestSecretUsesNoEchoReaderWhenGiven(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("this-must-not-be-read\n"), &out, func() (string, error) { return " hidden ", nil })
	v, err := p.Secret("pw", false)
	if err != nil || v != "hidden" {
		t.Fatalf("Secret = %q %v", v, err)
	}
}

func TestSecretOnCommandLineWarns(t *testing.T) {
	r := run(t, "", "", "set", "dingtalk.secret", "SECabcdefghij")
	if r.code != 0 || !strings.Contains(r.err, "shell history") {
		t.Fatalf("exit %d, stderr %q", r.code, r.err)
	}
	if r2 := run(t, "", "", "set", "mcp.max_block_seconds", "60"); strings.Contains(r2.err, "shell history") {
		t.Error("non-secret values need no warning")
	}
}
