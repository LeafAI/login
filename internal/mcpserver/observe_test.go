package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/archery"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
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
	cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
	cfg.Audit.File = filepath.Join(dir, "audit.jsonl")
	if tweak != nil {
		tweak(cfg)
	}
	_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}, Vault: testVault(t, cfg)})
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

// The limit has to hold however quickly the requests follow each other. A flow that has ended stays in the manager's table
// until its onDone callback returns, and a request made in that moment used to be handed the finished flow: no question to
// the limiter, no audit entry, and the old error back instead of rate_limited. On a slow CI runner that made
// TestRateLimitStopsFlooding fail ("4th attempt: tunnel_unavailable"). Here the moment is made to last, so that it does not
// depend on the machine.
func TestRateLimitHoldsForARequestMadeWhileTheLastFlowIsStillBeingWrappedUp(t *testing.T) {
	s, cfg := newTestServer(t, func(c *config.Config) { c.Limits.PerSite = 1 })
	c, terr := s.gate()
	if terr != nil {
		t.Fatal(terr)
	}
	base := mustURL(t, "https://gitlab.corp.example")
	d, err := site.Resolve("gitlab", base)
	if err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	entered := make(chan struct{})
	first := c.mgr.Start(d, base, "r", s.hc, func(*flow.Flow, flow.Result) { close(entered); <-hold })
	<-first.Done() // ended (no tunnel in this test), its onDone still running
	<-entered

	// The second request is the one that the limit (1 per site) refuses.
	_, lastErr := s.ensureLogin(context.Background(), nil, "https://gitlab.corp.example", "gitlab", "r", false, true, time.Second)
	close(hold)
	if lastErr == nil || lastErr.Code != "rate_limited" {
		t.Fatalf("2nd attempt: %+v, want rate_limited", lastErr)
	}
	var limited int
	for _, e := range events(t, cfg.Audit.File) {
		if e.Event == "rate_limited" {
			limited++
		}
	}
	if limited != 1 {
		t.Errorf("rate_limited events = %d, want 1: the refusal must be audited", limited)
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
	cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
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

// putSecret stores a fresh TOTP secret in the vault under a factor's entry.
func putSecret(t *testing.T, v *vault.Vault, entry string) {
	t.Helper()
	sec, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(entry, []byte(totp.FormatSecret(sec))); err != nil {
		t.Fatal(err)
	}
}

// newWith starts a server with an open vault, after tweak has changed the config and put secrets in the vault.
func newWith(t *testing.T, tweak func(*config.Config, *vault.Vault)) error {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	v := testVault(t, cfg)
	tweak(cfg, v)
	_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}, Vault: v})
	if s != nil {
		t.Cleanup(s.Close)
	}
	return err
}

// A factor that is on without a usable secret stops the server from opening. Carrying on would hand out plain links
// to people who switched the protection on. (The vault opens only with the passphrase now, so this is checked then.)
func TestServerRefusesToOpenWithAFactorOnAndNoSecret(t *testing.T) {
	for name, tweak := range map[string]func(*config.Config, *vault.Vault){
		"unlock":  func(c *config.Config, _ *vault.Vault) { c.Security.LinkTOTP.Enabled = true },
		"sealing": func(c *config.Config, _ *vault.Vault) { c.Security.SealTOTP.Enabled = true },
	} {
		err := newWith(t, tweak)
		if err == nil || !strings.Contains(err.Error(), "totp init") {
			t.Errorf("%s: the server opened with a factor on and no secret (err=%v)", name, err)
		}
	}
}

func TestServerOpensWithTheFactorsAndTheSecretsPresent(t *testing.T) {
	err := newWith(t, func(c *config.Config, v *vault.Vault) {
		c.Security.LinkTOTP.Enabled, c.Security.SealTOTP.Enabled = true, true
		putSecret(t, v, config.LinkSecretName)
		putSecret(t, v, config.SealSecretName)
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
}

func TestServerRefusesAnInvalidFactorSetting(t *testing.T) {
	err := newWith(t, func(c *config.Config, v *vault.Vault) {
		c.Security.SealTOTP = config.TOTP{Enabled: true, Period: 5 * time.Second, Digits: 8}
		putSecret(t, v, config.SealSecretName)
	})
	if err == nil {
		t.Fatal("a 5 second period was accepted")
	}
}

// The policy resource tells the agent which protections are on, without ever exposing a code or a secret.
func TestPolicyReportsTheFactorsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	cfg.Security.LinkTOTP.Enabled, cfg.Security.SealTOTP.Enabled = true, true
	v := testVault(t, cfg)
	putSecret(t, v, config.LinkSecretName)
	putSecret(t, v, config.SealSecretName)
	link, _ := v.Get(config.LinkSecretName)
	_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	pol := s.policy()
	if !pol.LinkUnlockRequired || !pol.SealingCodeRequired {
		t.Errorf("the policy must report both factors: %+v", pol)
	}
	raw, _ := json.Marshal(pol)
	for _, leak := range []string{string(link), "link.secret", "seal.secret", config.LinkSecretName} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the policy leaks %q: %s", leak, raw)
		}
	}
}

func TestPolicyReportsLocalAddressAccess(t *testing.T) {
	for _, allow := range []bool{false, true} {
		cfg := testConfig(t, t.TempDir())
		cfg.Security.AllowLocalAddresses = allow
		_, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}, Vault: testVault(t, cfg)})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(s.policy())
		want := fmt.Sprintf(`"local_addresses_allowed":%v`, allow)
		if !strings.Contains(string(raw), want) {
			t.Errorf("the policy must tell the agent whether local addresses are reachable (%s): %s", want, raw)
		}
	}
}
