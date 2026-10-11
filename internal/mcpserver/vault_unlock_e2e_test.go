package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/web"
)

const e2ePass = "correct horse battery staple"

type unlockEnv struct {
	cs    *mcp.ClientSession
	rec   *recorder
	dir   string
	v     *vault.Vault
	app   *mcpserver.Server
	cfg   *config.Config
	audit string
}

// unlockSetup starts a server over a vault that exists and is locked, with the real page on disk.
func unlockSetup(t *testing.T, tweak func(*config.Config)) *unlockEnv {
	t.Helper()
	browsertest.Require(t)
	dir := t.TempDir()
	if err := web.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir + "/nonexistent.yaml")
	cfg.Security.AllowLocalAddresses = true
	cfg.Web.PageURL = "file://" + dir + "/index.html"
	cfg.Web.TTL = time.Minute
	cfg.Vault.UnlockTTL = time.Minute
	cfg.MCP.MaxBlockSeconds = 1
	cfg.Audit.File = dir + "/audit.jsonl"
	if tweak != nil {
		tweak(cfg)
	}
	v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
	if err := v.Init(e2ePass); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	rec := &recorder{}
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Notifier: rec, Tunnels: localTunnels{}, Log: func(string, ...any) {}, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return &unlockEnv{cs: cs, rec: rec, dir: dir, v: v, app: app, cfg: cfg, audit: cfg.Audit.File}
}

func (e *unlockEnv) call(t *testing.T, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out, res.IsError
}

// typePassphrase is the person: they open the link from the n-th DingTalk message and type what they are given.
func (e *unlockEnv) typePassphrase(t *testing.T, n int, pass string) string {
	t.Helper()
	vals, _ := json.Marshal(map[string]string{"passphrase": pass})
	return human(t, e.rec.wait(t, n), e.dir, "submit", string(vals), "")
}

func TestRemoteUnlockWithThePassphraseOpensTheServer(t *testing.T) {
	e := unlockSetup(t, nil)
	out, isErr := e.call(t, "vault_status", map[string]any{})
	if isErr || out["state"] != "locked" {
		t.Fatalf("status: %v %v", isErr, out)
	}
	out, isErr = e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	if isErr || out["status"] != "pending" || out["login_id"] == nil {
		t.Fatalf("the first call asks a person and returns pending: %v %v", isErr, out)
	}
	msg := e.rec.wait(t, 1)
	if !strings.Contains(msg, "Vault") && !strings.Contains(msg, "vault") {
		t.Errorf("the message must say what is being asked for:\n%s", msg)
	}
	e.typePassphrase(t, 1, e2ePass)
	out, isErr = e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20, "unlock_id": out["login_id"]})
	if isErr || out["status"] != "unlocked" {
		t.Fatalf("after the person typed it the vault must be open: %v %v", isErr, out)
	}
	if e.v.State() != vault.Unlocked {
		t.Error("the vault is open")
	}
	if out, _ := e.call(t, "vault_status", map[string]any{}); out["state"] != "unlocked" {
		t.Errorf("%v", out)
	}
	// and the tools that were refused now run
	if out, isErr := e.call(t, "session_open", map[string]any{"url": "not a url"}); !isErr || out["code"] != "invalid_argument" {
		t.Errorf("with the vault open the gate lets calls through to their own validation: %v", out)
	}
}

func TestTheAgentNeverSeesThePassphraseAnywhere(t *testing.T) {
	e := unlockSetup(t, nil)
	var seen []string
	collect := func(out map[string]any) { b, _ := json.Marshal(out); seen = append(seen, string(b)) }
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	collect(out)
	e.typePassphrase(t, 1, e2ePass)
	out, _ = e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20, "unlock_id": out["login_id"]})
	collect(out)
	st, _ := e.call(t, "vault_status", map[string]any{})
	collect(st)
	for _, s := range seen {
		if strings.Contains(s, e2ePass) {
			t.Errorf("a tool result carries the passphrase: %s", s)
		}
	}
	for _, m := range e.rec.all() {
		if strings.Contains(m, e2ePass) {
			t.Errorf("a DingTalk message carries the passphrase:\n%s", m)
		}
	}
	if raw, err := os.ReadFile(e.audit); err == nil && strings.Contains(string(raw), e2ePass) {
		t.Errorf("the audit log carries the passphrase:\n%s", raw)
	}
}

func TestAWrongPassphraseKeepsItLockedAndLetsThePersonTryAgain(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	page := e.typePassphrase(t, 1, "this is not the passphrase")
	if !strings.Contains(strings.ToLower(page), "wrong") && !strings.Contains(strings.ToLower(page), "another") {
		t.Logf("page said: %q", page)
	}
	if e.v.State() != vault.Locked {
		t.Fatal("a wrong passphrase must not open the vault")
	}
	// a second message is sent for another try, on the same unlock
	e.typePassphrase(t, 2, e2ePass)
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20, "unlock_id": id})
	if isErr || out["status"] != "unlocked" {
		t.Fatalf("a second try with the right passphrase must open it: %v %v", isErr, out)
	}
}

func TestRejectingTheUnlockLeavesItLocked(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "not now")
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20, "unlock_id": out["login_id"]})
	if !isErr || out["code"] != "user_rejected" {
		t.Fatalf("%v %v", isErr, out)
	}
	if e.v.State() != vault.Locked {
		t.Error("still locked")
	}
}

func TestUnlockingAnOpenVaultBothersNobody(t *testing.T) {
	e := unlockSetup(t, nil)
	if err := e.app.UnlockWith(e2ePass); err != nil {
		t.Fatal(err)
	}
	out, isErr := e.call(t, "vault_unlock", map[string]any{})
	if isErr || out["status"] != "unlocked" || out["already_unlocked"] != true {
		t.Fatalf("%v %v", isErr, out)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("nobody should have been messaged, %d were", n)
	}
}

func TestUnlockWithNoVaultSaysSoWithoutAskingAnyone(t *testing.T) {
	e := unlockSetup(t, func(c *config.Config) {})
	os.RemoveAll(e.cfg.Vault.Dir)
	out, isErr := e.call(t, "vault_unlock", map[string]any{})
	if !isErr || out["code"] != "vault_not_initialized" {
		t.Fatalf("%v %v", isErr, out)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("there is nothing to unlock, so nobody is asked: %d messages", n)
	}
}

func TestOnlyOneUnlockIsOpenAtATime(t *testing.T) {
	e := unlockSetup(t, nil)
	a, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	b, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	if a["login_id"] != b["login_id"] {
		t.Errorf("a second call joins the running unlock instead of sending a second link: %v vs %v", a["login_id"], b["login_id"])
	}
	if n := len(e.rec.all()); n != 1 {
		t.Errorf("one message, not %d", n)
	}
}

// The passphrase is guessable by whoever can reach the page, so repeated failures are slowed, and the same counter
// serves every route.
func TestRepeatedWrongPassphrasesAreSlowedDown(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	for n := 1; n <= 3; n++ {
		e.typePassphrase(t, n, fmt.Sprintf("wrong passphrase number %d....", n))
		if n < 3 {
			e.rec.wait(t, n+1) // the next try is offered
		}
		// after the third wrong one the penalty starts at once: no further message is sent
	}
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 5, "unlock_id": id})
	if !isErr || out["code"] != "rate_limited" {
		t.Fatalf("after the free attempts the unlock must be refused with a retry time: %v %v", isErr, out)
	}
	if !strings.Contains(fmt.Sprint(out["message"]), "retry in") {
		t.Errorf("%v", out)
	}
	if e.v.State() != vault.Locked {
		t.Error("still locked")
	}
	// even the right passphrase is not tried while the penalty runs
	before := len(e.rec.all())
	out2, isErr2 := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	if !isErr2 || out2["code"] != "rate_limited" {
		t.Errorf("a new unlock during the penalty is refused before anyone is asked: %v", out2)
	}
	if len(e.rec.all()) != before {
		t.Error("no message may be sent while the penalty runs")
	}
}

func TestTheUnlockToolsNeverTouchSessionsOrSites(t *testing.T) {
	e := unlockSetup(t, nil)
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range res.Tools {
		have[tl.Name] = true
	}
	for _, want := range []string{"vault_unlock", "vault_status"} {
		if !have[want] {
			t.Errorf("tool %s is missing", want)
		}
	}
}

// After a success the penalty is gone: the person must not be refused the next time they have to unlock (the server
// locks again, an idle timeout passes) because of mistakes made before they got it right.
func TestASuccessWipesTheEarlierMistakes(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	e.typePassphrase(t, 1, "wrong passphrase number one...")
	e.rec.wait(t, 2)
	e.typePassphrase(t, 2, e2ePass)
	if out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20, "unlock_id": id}); isErr || out["status"] != "unlocked" {
		t.Fatalf("%v %v", isErr, out)
	}
	if st, _ := e.call(t, "vault_status", map[string]any{}); st["failed_attempts"] != nil && st["failed_attempts"] != float64(0) {
		t.Errorf("a success clears the count: %v", st)
	}
}

// While a penalty runs, not even a request that starts fresh may reach a person: the check happens before the message.
func TestAFreshUnlockDuringAPenaltySendsNothing(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	for n := 1; n <= 3; n++ {
		e.typePassphrase(t, n, fmt.Sprintf("wrong passphrase number %d....", n))
		if n < 3 {
			e.rec.wait(t, n+1)
		}
	}
	e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 5, "unlock_id": id}) // the first request ends rate limited
	before := len(e.rec.all())
	// no unlock_id: a brand new request
	out2, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	if !isErr || out2["code"] != "rate_limited" {
		t.Fatalf("%v %v", isErr, out2)
	}
	if len(e.rec.all()) != before {
		t.Error("no message may go out while the penalty runs")
	}
	if st, _ := e.call(t, "vault_status", map[string]any{}); st["retry_after_seconds"] == nil || st["failed_attempts"] != float64(3) {
		t.Errorf("status must show the penalty to the agent so that it can stop trying: %v", st)
	}
}

// Two agents (or one agent twice) asking while a link is out must not send a second link: people would not know which
// to open, and each link would be another thing to guess at.
func TestACallWithoutAnIdJoinsTheUnlockThatIsWaiting(t *testing.T) {
	e := unlockSetup(t, nil)
	a, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	b, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1}) // no unlock_id
	if a["login_id"] == nil || a["login_id"] != b["login_id"] {
		t.Fatalf("it must be the same unlock: %v vs %v", a["login_id"], b["login_id"])
	}
	e.typePassphrase(t, 1, e2ePass)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20}) // still no id
	if out["status"] != "unlocked" {
		t.Errorf("a caller who lost the id still learns that the vault is open: %v", out)
	}
	if n := len(e.rec.all()); n != 1 {
		t.Errorf("exactly one message in all: %d", n)
	}
}

// A request lets the person try a few times, not for ever. The guard slows them down earlier; this bounds one request
// even if it is configured not to.
func TestOneRequestGivesUpAfterAFewWrongPassphrases(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	e.typePassphrase(t, 1, "wrong passphrase number one...")
	e.rec.wait(t, 2)
	e.typePassphrase(t, 2, "wrong passphrase number two...")
	e.rec.wait(t, 3)
	e.typePassphrase(t, 3, "wrong passphrase number 3....")
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 10, "unlock_id": id})
	if !isErr {
		t.Fatalf("the request must have ended: %v", out)
	}
	if e.v.State() != vault.Locked {
		t.Error("locked")
	}
}

// A right passphrase that the server still cannot use (a factor is on and its secret is missing) must say so, and must
// not offer another try: typing it again would give the same answer, and the person would never learn why.
func TestARightPassphraseThatCannotOpenTheServerSaysWhyAndStops(t *testing.T) {
	e := unlockSetup(t, func(c *config.Config) { c.Security.LinkTOTP.Enabled = true }) // no secret in the vault
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	e.typePassphrase(t, 1, e2ePass)
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 20, "unlock_id": id})
	if !isErr {
		t.Fatalf("the server cannot open: %v", out)
	}
	if !strings.Contains(fmt.Sprint(out["message"]), "totp init") {
		t.Errorf("the real reason must reach the agent so that it can tell the user: %v", out)
	}
	if n := len(e.rec.all()); n != 1 {
		t.Errorf("no second link for a problem a second try cannot fix: %d messages", n)
	}
	if e.v.State() != vault.Locked {
		t.Error("and the vault is shut again")
	}
	if st, _ := e.call(t, "vault_status", map[string]any{}); st["failed_attempts"] != nil && st["failed_attempts"] != float64(0) {
		t.Errorf("a right passphrase is not a failed attempt: %v", st)
	}
}

// requestsInAudit counts the unlock requests the audit log says were made.
func requestsInAudit(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), `"event":"vault_unlock_requested"`)
}

// The audit log is the record of who was asked. A request that was refused before anyone was asked, or that joined one
// already waiting, is not a new request and must not look like one.
func TestOnlyRealRequestsReachTheAuditLog(t *testing.T) {
	e := unlockSetup(t, nil)
	e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1}) // joins the first
	e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1}) // joins it too
	if n := requestsInAudit(t, e.audit); n != 1 {
		t.Errorf("three calls, one person asked: the audit log must say 1 request, not %d", n)
	}
}

func TestARequestRefusedForThePenaltyIsNotLoggedAsMade(t *testing.T) {
	e := unlockSetup(t, nil)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	id := out["login_id"]
	for n := 1; n <= 3; n++ {
		e.typePassphrase(t, n, fmt.Sprintf("wrong passphrase number %d....", n))
		if n < 3 {
			e.rec.wait(t, n+1)
		}
	}
	e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 5, "unlock_id": id})
	before := requestsInAudit(t, e.audit)
	if _, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1}); !isErr {
		t.Fatal("must be refused")
	}
	if after := requestsInAudit(t, e.audit); after != before {
		t.Errorf("a request that never reached a person was logged as made (%d -> %d)", before, after)
	}
}
