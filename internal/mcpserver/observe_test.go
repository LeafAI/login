package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/audit"
	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/flow"
	"github.com/LeafAI/login/internal/site/archery"
	"github.com/LeafAI/login/internal/totp"
)

func events(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func newTestServer(t *testing.T, tweak func(*config.Config)) (*Server, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg, _ := config.Load(dir + "/none.yaml")
	cfg.Keys.Dir = dir + "/keys"
	cfg.Audit.File = filepath.Join(dir, "audit.jsonl")
	if tweak != nil {
		tweak(cfg)
	}
	_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	return s, cfg
}

type quiet struct{}

func (quiet) Markdown(context.Context, string, string) error { return nil }

type noTunnels struct{}

func (noTunnels) Start(context.Context, int) (flow.Tunnel, error) {
	return nil, errors.New("no tunnel in this test")
}

func TestAuditRecordsCallsWithoutSecretsOrSQL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s, cfg := newTestServer(t, nil)
	in := LoginInput{URL: ts.URL, Site: "skywalking", Reason: "check traces"}
	out, terr := s.login(context.Background(), nil, in)
	s.observe("login", nil, in, out, terr, 5*time.Millisecond)
	run := RunSQLInput{ArcheryURL: ArcheryURL{URL: "https://archery.corp.example"}, SQL: "UPDATE accounts SET pw='hunter2'"}
	s.observe("archery_run_sql", nil, run, ArcheryOut{Outcome: archery.Outcome{Status: "pending", WorkflowID: 42}}, nil, time.Millisecond)
	s.observe("login", nil, in, nil, errf("host_not_allowed", false, "nope"), time.Millisecond)

	got := events(t, cfg.Audit.File)
	if len(got) != 3 {
		t.Fatalf("events: %+v", got)
	}
	if got[0].Tool != "login" || got[0].Site != "skywalking" || got[0].Result != "ok" || got[0].Reason != "check traces" || got[0].Host == "" {
		t.Errorf("login event %+v", got[0])
	}
	if got[1].SQLBytes != len(run.SQL) || got[1].SQLHash == "" || got[1].Workflow != 42 || got[1].Host != "archery.corp.example" {
		t.Errorf("sql event %+v", got[1])
	}
	if got[2].Result != "host_not_allowed" {
		t.Errorf("error event %+v", got[2])
	}
	raw, _ := os.ReadFile(cfg.Audit.File)
	for _, secret := range []string{"hunter2", "UPDATE", "accounts", "cookie", "token"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("audit log leaked %q:\n%s", secret, raw)
		}
	}
}

func TestAuditCanBeDisabled(t *testing.T) {
	off := false
	s, cfg := newTestServer(t, func(c *config.Config) { c.Audit.Enabled = &off })
	s.observe("login", nil, LoginInput{URL: "https://x.example"}, nil, nil, 0)
	if _, err := os.Stat(cfg.Audit.File); err == nil {
		t.Error("a disabled audit log must not create a file")
	}
}

func TestRateLimitStopsFlooding(t *testing.T) {
	s, cfg := newTestServer(t, func(c *config.Config) { c.Limits.PerSite = 2 })
	var lastErr *ToolError
	for i := 0; i < 4; i++ {
		_, lastErr = s.ensureLogin(context.Background(), nil, "https://gitlab.corp.example", "gitlab", "r", false, true, time.Second)
	}
	// every attempt fails at the (missing) tunnel; from the third on the limiter refuses first
	if lastErr == nil || lastErr.Code != "rate_limited" || !lastErr.Retryable || lastErr.Hint == "" {
		t.Fatalf("4th attempt: %+v", lastErr)
	}
	var human, limited int
	for _, e := range events(t, cfg.Audit.File) {
		switch e.Event {
		case "human_request":
			human++
		case "rate_limited":
			limited++
		}
	}
	if human != 2 || limited != 2 {
		t.Fatalf("human_request=%d rate_limited=%d, want 2 and 2", human, limited)
	}
}

func TestCachedLoginDoesNotSpendTheBudget(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s, _ := newTestServer(t, func(c *config.Config) { c.Limits.PerSite, c.Limits.Total = 1, 1 })
	for i := 0; i < 5; i++ { // a site without login never reaches a human
		if _, terr := s.ensureLogin(context.Background(), nil, ts.URL, "skywalking", "", false, true, time.Second); terr != nil {
			t.Fatalf("call %d: %v", i, terr)
		}
	}
}

func TestRejectStartsCooldownForThatSite(t *testing.T) {
	s, _ := newTestServer(t, func(c *config.Config) { c.Limits.RejectCooldown = time.Hour })
	base, _ := baseOf("https://gitlab.corp.example")
	s.limiter.Rejected(siteKey(base))
	_, terr := s.ensureLogin(context.Background(), nil, "https://gitlab.corp.example", "gitlab", "", false, true, time.Second)
	if terr == nil || terr.Code != "rate_limited" || !strings.Contains(terr.Message, "rejected") {
		t.Fatalf("after a rejection: %+v", terr)
	}
}

func reflectTypeOf(v any) reflect.Type { return reflect.TypeOf(v) }

// testConfig is a config with everything pointing into dir, as the other tests of this package use.
func testConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	cfg, err := config.Load(dir + "/none.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Keys.Dir = dir + "/keys"
	cfg.Audit.File = filepath.Join(dir, "audit.jsonl")
	return cfg
}

func TestAuditClipsAgentControlledReason(t *testing.T) {
	s, cfg := newTestServer(t, nil)
	s.observe("login", nil, LoginInput{URL: "https://x.example", Reason: strings.Repeat("界", 500)}, nil, nil, 0)
	got := events(t, cfg.Audit.File)
	if len(got) != 1 || len(got[0].Reason) > maxReasonBytes || !strings.HasPrefix(got[0].Reason, "界") {
		t.Fatalf("reason must be bounded and still valid UTF-8, got %d bytes", len(got[0].Reason))
	}
}

// ---- the two TOTP factors at start-up ----

func writeSecret(t *testing.T, path string) {
	t.Helper()
	s, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := totp.SaveSecret(path, s); err != nil {
		t.Fatal(err)
	}
}

func newWith(t *testing.T, tweak func(*config.Config)) error {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	tweak(cfg)
	_, _, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}})
	return err
}

// A factor that is on without a usable secret stops the server from starting. Carrying on would hand out plain links
// to people who switched the protection on.
func TestServerRefusesToStartWithAFactorOnAndNoSecret(t *testing.T) {
	for name, tweak := range map[string]func(*config.Config){
		"unlock":  func(c *config.Config) { c.Security.LinkTOTP.Enabled = true },
		"sealing": func(c *config.Config) { c.Security.SealTOTP.Enabled = true },
	} {
		err := newWith(t, tweak)
		if err == nil || !strings.Contains(err.Error(), "totp init") {
			t.Errorf("%s: the server started with a factor on and no secret (err=%v)", name, err)
		}
	}
}

func TestServerStartsWithTheFactorsAndTheSecretsPresent(t *testing.T) {
	err := newWith(t, func(c *config.Config) {
		c.Security.LinkTOTP.Enabled, c.Security.SealTOTP.Enabled = true, true
		writeSecret(t, c.Security.LinkTOTP.SecretFile)
		writeSecret(t, c.Security.SealTOTP.SecretFile)
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
}

func TestServerRefusesAnInvalidFactorSetting(t *testing.T) {
	err := newWith(t, func(c *config.Config) {
		c.Security.SealTOTP = config.TOTP{Enabled: true, Period: 5 * time.Second, Digits: 8, SecretFile: c.Security.SealTOTP.SecretFile}
		writeSecret(t, c.Security.SealTOTP.SecretFile)
	})
	if err == nil {
		t.Fatal("a 5 second period was accepted")
	}
}

// The policy resource tells the agent which protections are on, without ever exposing a code or a secret path.
func TestPolicyReportsTheFactorsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	cfg.Security.LinkTOTP.Enabled, cfg.Security.SealTOTP.Enabled = true, true
	writeSecret(t, cfg.Security.LinkTOTP.SecretFile)
	writeSecret(t, cfg.Security.SealTOTP.SecretFile)
	_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	pol := s.policy()
	if !pol.LinkUnlockRequired || !pol.SealingCodeRequired {
		t.Errorf("the policy must report both factors: %+v", pol)
	}
	raw, _ := json.Marshal(pol)
	for _, leak := range []string{cfg.Security.LinkTOTP.SecretFile, cfg.Security.SealTOTP.SecretFile, "link.secret", "seal.secret"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the policy leaks %q: %s", leak, raw)
		}
	}
}
