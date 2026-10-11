package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

const gatePass = "correct horse battery staple"

type gateEnv struct {
	s   *Server
	cs  *mcp.ClientSession
	v   *vault.Vault
	cfg *config.Config
	dir string
}

// gateServer starts a server whose vault is in the given state: "none" (never initialized), "locked" or "open".
func gateServer(t *testing.T, state string, tweak func(*config.Config)) *gateEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	cfg.Vault.Dir = dir + "/vault"
	if tweak != nil {
		tweak(cfg)
	}
	v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
	switch state {
	case "locked":
		if err := v.Init(gatePass); err != nil {
			t.Fatal(err)
		}
		v.Lock()
	case "open":
		if err := v.Init(gatePass); err != nil {
			t.Fatal(err)
		}
	}
	srv, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return &gateEnv{s: s, cs: connect(t, s, srv), v: v, cfg: cfg, dir: dir}
}

func (g *gateEnv) call(t *testing.T, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := g.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out, res.IsError
}

// Every tool that touches a site, a session or a credential must refuse while the vault is closed, and say which of
// the two situations it is, because the remedies differ.
var sensitiveCalls = map[string]map[string]any{
	"session_open":            {"url": "https://x.example"},
	"session_wait":            {"login_id": "lg_x"},
	"archery_instances":       {"url": "https://a.example"},
	"archery_groups":          {"url": "https://a.example"},
	"archery_query":           {"url": "https://a.example", "instance": "i", "database": "d", "sql": "select 1"},
	"archery_run_sql":         {"url": "https://a.example", "instance": "i", "database": "d", "sql": "select 1", "title": "t"},
	"archery_wait":            {"url": "https://a.example", "workflow_id": 1},
	"archery_workflow_status": {"url": "https://a.example", "workflow_id": 1},
	"archery_cancel":          {"url": "https://a.example", "workflow_id": 1},
	"session_list":            {},
	"session_close":           {"all": true},
}

func TestSensitiveToolsRefuseWhileTheVaultIsNotInitialized(t *testing.T) {
	g := gateServer(t, "none", nil)
	for tool, args := range sensitiveCalls {
		out, isErr := g.call(t, tool, args)
		if !isErr || out["code"] != "vault_not_initialized" {
			t.Errorf("%s: want vault_not_initialized, got isErr=%v %v", tool, isErr, out)
		}
		if h, _ := out["hint"].(string); !strings.Contains(h, "securl vault init") {
			t.Errorf("%s: the hint must say how to fix it: %q", tool, h)
		}
	}
}

func TestSensitiveToolsRefuseWhileTheVaultIsLocked(t *testing.T) {
	g := gateServer(t, "locked", nil)
	for tool, args := range sensitiveCalls {
		out, isErr := g.call(t, tool, args)
		if !isErr || out["code"] != "vault_locked" {
			t.Errorf("%s: want vault_locked, got isErr=%v %v", tool, isErr, out)
		}
		if h, _ := out["hint"].(string); !strings.Contains(h, "vault_unlock") {
			t.Errorf("%s: the hint must name the tool that unlocks it: %q", tool, h)
		}
		if out["retryable"] != true {
			t.Errorf("%s: a locked vault can be unlocked, so the call is retryable: %v", tool, out)
		}
	}
}

func TestARefusedCallContactsNothing(t *testing.T) {
	var hits int
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer site.Close()
	g := gateServer(t, "locked", func(c *config.Config) {
		c.Aliases = map[string]string{strings.TrimPrefix(site.URL, "http://"): "skywalking"}
	})
	// skywalking needs no login: it is the case that would reach the site if the gate were missing
	if _, isErr := g.call(t, "session_open", map[string]any{"url": site.URL, "site": "skywalking"}); !isErr {
		t.Error("login must refuse while locked, even for a site that needs no credentials")
	}
	if hits != 0 {
		t.Errorf("the site was contacted %d times while the vault was locked", hits)
	}
}

// Only what is static works while the vault is closed. A session list or a logout would have to answer from the vault:
// an empty list would say "no sessions" when the vault is merely shut, and "removed 0" would hide that the stored
// sessions are still there. Both say so instead.
func TestOnlyStaticToolsWorkWhileLocked(t *testing.T) {
	g := gateServer(t, "locked", nil)
	if out, isErr := g.call(t, "site_list", map[string]any{}); isErr || out["sites"] == nil {
		t.Errorf("site_list lists drivers, nothing secret: %v %v", isErr, out)
	}
	for tool, args := range map[string]map[string]any{
		"session_list":  {},
		"session_close": {"all": true},
	} {
		if out, isErr := g.call(t, tool, args); !isErr || out["code"] != "vault_locked" {
			t.Errorf("%s must say the vault is locked rather than answer from nothing: %v %v", tool, isErr, out)
		}
	}
}

func TestPolicyReportsTheVaultState(t *testing.T) {
	for _, state := range []string{"none", "locked", "open"} {
		g := gateServer(t, state, nil)
		want := map[string]string{"none": "not_initialized", "locked": "locked", "open": "unlocked"}[state]
		if got := g.s.policy().VaultState; got != want {
			t.Errorf("%s: policy says %q, want %q", state, got, want)
		}
	}
}

func TestOpenVaultLetsToolsRun(t *testing.T) {
	g := gateServer(t, "open", nil)
	out, isErr := g.call(t, "session_open", map[string]any{"url": "not a url"})
	if !isErr || out["code"] != "invalid_argument" {
		t.Errorf("with the vault open the call reaches the normal validation: %v", out)
	}
}

func TestLockingAgainClosesTheDoor(t *testing.T) {
	g := gateServer(t, "open", nil)
	if out, _ := g.call(t, "session_open", map[string]any{"url": "not a url"}); out["code"] != "invalid_argument" {
		t.Fatalf("setup: %v", out)
	}
	g.v.Lock()
	if out, isErr := g.call(t, "session_open", map[string]any{"url": "not a url"}); !isErr || out["code"] != "vault_locked" {
		t.Errorf("after the vault locks the tools must refuse again: %v", out)
	}
	if err := g.v.Unlock(gatePass); err != nil {
		t.Fatal(err)
	}
	if out, _ := g.call(t, "session_open", map[string]any{"url": "not a url"}); out["code"] != "invalid_argument" {
		t.Errorf("and work again after it is unlocked: %v", out)
	}
}

// The server starts with the vault shut even when a factor is on: the secrets are not readable yet. The refusal that
// a missing secret used to be at start-up now happens when the vault opens, and is still a refusal, not a downgrade.
func TestServerStartsLockedWithFactorsOn(t *testing.T) {
	g := gateServer(t, "locked", func(c *config.Config) { c.Security.LinkTOTP.Enabled, c.Security.SealTOTP.Enabled = true, true })
	if out, isErr := g.call(t, "session_open", map[string]any{"url": "https://x.example"}); !isErr || out["code"] != "vault_locked" {
		t.Errorf("%v", out)
	}
}

func TestUnlockWithAFactorOnAndNoSecretFailsClosed(t *testing.T) {
	g := gateServer(t, "locked", func(c *config.Config) { c.Security.LinkTOTP.Enabled = true })
	err := g.s.UnlockWith(gatePass)
	if err == nil || !strings.Contains(err.Error(), "totp init") {
		t.Fatalf("the vault opens but a factor that is on has no secret: that must refuse, not run unprotected: %v", err)
	}
	if g.v.State() != vault.Locked {
		t.Error("a refused unlock must leave the vault locked")
	}
	if out, isErr := g.call(t, "session_open", map[string]any{"url": "https://x.example"}); !isErr || out["code"] != "vault_locked" {
		t.Errorf("%v", out)
	}
}

func TestUnlockWithTheFactorSecretsPresentOpensEverything(t *testing.T) {
	g := gateServer(t, "locked", func(c *config.Config) { c.Security.LinkTOTP.Enabled, c.Security.SealTOTP.Enabled = true, true })
	for _, name := range []string{config.LinkSecretName, config.SealSecretName} {
		sec, _ := totp.NewSecret()
		if err := g.v.Unlock(gatePass); err != nil {
			t.Fatal(err)
		}
		if err := g.v.Put(name, []byte(totp.FormatSecret(sec))); err != nil {
			t.Fatal(err)
		}
	}
	g.v.Lock()
	if err := g.s.UnlockWith(gatePass); err != nil {
		t.Fatal(err)
	}
	pol := g.s.policy()
	if !pol.LinkUnlockRequired || !pol.SealingCodeRequired || pol.VaultState != "unlocked" {
		t.Errorf("%+v", pol)
	}
}

func TestWrongPassphraseLeavesTheServerLocked(t *testing.T) {
	g := gateServer(t, "locked", nil)
	if err := g.s.UnlockWith("this is not the passphrase"); err == nil {
		t.Fatal("a wrong passphrase unlocked the vault")
	}
	if g.v.State() != vault.Locked {
		t.Error("still locked")
	}
}

// A vault that locks (an idle timeout, or `securl vault lock` from another process) must take the parts that can use a
// credential down with it: pending logins end, their tunnels close, and the transport keys are forgotten.
func TestLockingDropsEverythingThatHoldsASecret(t *testing.T) {
	g := gateServer(t, "open", nil)
	g.s.mu.Lock()
	before := g.s.core
	g.s.mu.Unlock()
	if before == nil {
		t.Fatal("an open vault has a core")
	}
	k1, _ := before.keys.Acquire()
	g.v.Lock() // locked behind the server's back, as another process or an idle timeout would
	if _, terr := g.s.gate(); terr == nil || terr.Code != "vault_locked" {
		t.Fatalf("%v", terr)
	}
	g.s.mu.Lock()
	after := g.s.core
	g.s.mu.Unlock()
	if after != nil {
		t.Error("the core (sessions, flows, tracker) must be dropped as soon as the vault is found locked")
	}
	if err := g.v.Unlock(gatePass); err != nil {
		t.Fatal(err)
	}
	c, terr := g.s.gate()
	if terr != nil {
		t.Fatal(terr)
	}
	if c == before {
		t.Error("after a lock the server must build a fresh core, not revive the old one")
	}
	k2, _ := c.keys.Acquire()
	if k1.Fingerprint() == k2.Fingerprint() {
		t.Error("the transport key used before the lock must not survive it")
	}
}

func TestExplicitLockDropsTheCoreToo(t *testing.T) {
	g := gateServer(t, "open", nil)
	g.s.Lock()
	g.s.mu.Lock()
	c := g.s.core
	g.s.mu.Unlock()
	if c != nil || g.v.State() != vault.Locked {
		t.Errorf("core=%v state=%v", c, g.v.State())
	}
}

// The refusal comes before anything else: a locked vault answers vault_locked even to a call whose arguments are wrong,
// so a probing agent cannot learn anything (such as which argument checks exist) from a vault it has no access to.
func TestTheGateComesBeforeArgumentValidation(t *testing.T) {
	g := gateServer(t, "locked", nil)
	for tool, args := range map[string]map[string]any{
		"archery_query":   {"url": "https://a.example", "sql": "drop table t"},
		"archery_run_sql": {"url": "https://a.example", "sql": "x"},
		"session_open":    {"url": "not a url"},
	} {
		if out, isErr := g.call(t, tool, args); !isErr || out["code"] != "vault_locked" {
			t.Errorf("%s with bad arguments: want vault_locked, got %v", tool, out)
		}
	}
}

// No tool takes a passphrase, so no tool can be used to guess one. The only way to try one is the page behind a DingTalk
// link, and that goes through the guard.
func TestNoToolTakesAPassphraseParameter(t *testing.T) {
	g := gateServer(t, "locked", nil)
	res, err := g.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		raw, _ := json.Marshal(tl.InputSchema)
		low := strings.ToLower(string(raw))
		for _, bad := range []string{"passphrase", "password", "secret", "token", "cookie"} {
			if strings.Contains(low, `"`+bad) {
				t.Errorf("tool %s accepts an input named like %q: an agent could be made to pass a secret through it\n%s", tl.Name, bad, raw)
			}
		}
	}
}

// A tool call that sneaks an extra argument in is refused, not ignored: DisallowUnknownFields is the guard against a
// passphrase being smuggled into a call that would then log it.
func TestUnknownArgumentsAreRefusedNotIgnored(t *testing.T) {
	g := gateServer(t, "locked", nil)
	out, isErr := g.call(t, "vault_unlock", map[string]any{"passphrase": gatePass})
	if !isErr || out["code"] != "invalid_argument" {
		t.Errorf("a passphrase passed as an argument must be refused outright: %v", out)
	}
	if g.v.State() != vault.Locked {
		t.Error("and certainly must not open the vault")
	}
	if strings.Contains(fmt.Sprint(out), gatePass) {
		t.Errorf("the refusal must not echo the argument back: %v", out)
	}
}

// The audit log records that an unlock happened, never what was typed.
func TestTheUnlockAuditNamesTheEventButNotThePassphrase(t *testing.T) {
	g := gateServer(t, "locked", nil)
	g.s.audit.Record(auditEvent("vault_unlock", "wrong_passphrase"))
	raw, _ := os.ReadFile(g.cfg.Audit.File)
	if !strings.Contains(string(raw), "vault_unlock") {
		t.Fatalf("the event must be recorded: %s", raw)
	}
	if strings.Contains(string(raw), gatePass) {
		t.Errorf("%s", raw)
	}
}

func auditEvent(event, result string) audit.Event { return audit.Event{Event: event, Result: result} }

func TestInstructionsTellTheAgentToUnlockFirstAndNotToLoop(t *testing.T) {
	for _, want := range []string{"vault_unlock", "vault_locked", "You never see it", "rate_limited", "unlock_id"} {
		if !strings.Contains(instructions, want) {
			t.Errorf("the instructions must mention %q", want)
		}
	}
}
