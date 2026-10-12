package mcpserver_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site/archery/archerytest"
)

func forGenerations(t *testing.T, fn func(t *testing.T, legacy bool)) {
	t.Run("v1.12", func(t *testing.T) { fn(t, true) })
	t.Run("rest", func(t *testing.T) { fn(t, false) })
}

// loginArchery completes the (password-only) login round through the real page.
func loginArchery(t *testing.T, e *env, fake *httptest.Server) {
	t.Helper()
	out, _ := e.call(t, "session_open", map[string]any{"url": fake.URL, "site": "archery", "max_block_seconds": 1})
	if out["status"] != "pending" {
		t.Fatalf("expected pending login, got %v", out)
	}
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw"}`, "")
	out, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if isErr || out["status"] != "ok" {
		t.Fatalf("archery login: %v", out)
	}
	// No site hands its credentials to the agent: the archery_* tools use the session on the agent's behalf.
	assertNoCredentials(t, out, "sessionid", "csrftoken", "X-CSRFToken")
	if out["site"] != "archery" || out["auth"] != "cookie" {
		t.Errorf("the result still says which site and how it authenticates: %v", out)
	}
	// ...and a repeated login (cached) says the same.
	again, _ := e.call(t, "session_open", map[string]any{"url": fake.URL, "site": "archery"})
	if again["cached"] != true {
		t.Fatalf("cached archery login: %v", again)
	}
	assertNoCredentials(t, again, "sessionid", "csrftoken")
}

func TestArcheryToolsEndToEnd(t *testing.T) {
	forGenerations(t, testArcheryToolsEndToEnd)
}

func testArcheryToolsEndToEnd(t *testing.T, legacy bool) {
	f := &archerytest.Fake{Legacy: legacy}
	arch := httptest.NewTLSServer(f.Handler())
	defer arch.Close()
	e := setupWithClient(t, arch.Client(), func(c *config.Config) {
		c.Archery.PollInterval = 20 * time.Millisecond
		c.Archery.DefaultGroup = "dba"
	})
	loginArchery(t, e, arch)
	args := func(m map[string]any) map[string]any { m["url"] = arch.URL; return m }

	// discover the resource group without ever seeing a credential
	g, isErr := e.call(t, "archery_groups", args(map[string]any{"group": "dba"}))
	if isErr || fmt.Sprint(g["groups"]) != "[dba dev]" {
		t.Fatalf("groups: %v", g)
	}
	if wi, _ := g["writable_instances"].([]any); len(wi) != 1 || wi[0].(map[string]any)["name"] != "prod" {
		t.Errorf("writable instances: %v", g)
	}
	if strings.Contains(fmt.Sprint(g), "group-id") || strings.Contains(fmt.Sprint(g), "sessionid") {
		t.Errorf("groups must expose names only: %v", g)
	}
	if bad, isErr := e.call(t, "archery_groups", args(map[string]any{"group": "nope"})); !isErr || bad["code"] != "archery_error" || !strings.Contains(bad["message"].(string), "available: dba, dev") {
		t.Errorf("unknown group should list the available ones: %v", bad)
	}

	// read-only query, and refusal of a write through the query tool
	q, isErr := e.call(t, "archery_query", args(map[string]any{"instance": "prod", "database": "d", "sql": "select * from t"}))
	if isErr || q["row_count"] != float64(2) {
		t.Fatalf("query: %v", q)
	}
	if q, isErr = e.call(t, "archery_query", args(map[string]any{"instance": "prod", "database": "d", "sql": "delete from t"})); !isErr || q["code"] != "invalid_argument" {
		t.Errorf("write via query: %v", q)
	}
	if ins, _ := e.call(t, "archery_instances", args(map[string]any{})); len(ins["instances"].([]any)) != 1 {
		t.Errorf("instances: %v", ins)
	}

	// submit without waiting, approve as a human would in Archery, then wait -> executes once
	run, isErr := e.call(t, "archery_run_sql", args(map[string]any{
		"instance": "prod", "database": "d", "sql": "UPDATE t SET a=1", "title": "fix a", "wait": false}))
	if isErr || run["status"] != "pending" || run["workflow_id"] != float64(9) || run["next_tool"] != "archery_wait" {
		t.Fatalf("run_sql: %v", run)
	}
	if !strings.Contains(e.rec.wait(t, 2), "/detail/9/") {
		t.Error("approver notification missing")
	}
	if wf, _ := f.Submitted["workflow"].(map[string]any); wf["group_id"] != float64(3) {
		t.Errorf("default group not used: %v", f.Submitted)
	}
	w, _ := e.call(t, "archery_wait", args(map[string]any{"workflow_id": 9, "max_block_seconds": 1}))
	if w["status"] != "pending" || w["phase"] != "awaiting_approval" || f.Executed != 0 {
		t.Fatalf("before approval: %v executed=%d", w, f.Executed)
	}
	f.Mu.Lock()
	f.Status = "workflow_review_pass"
	f.Mu.Unlock()
	w, isErr = e.call(t, "archery_wait", args(map[string]any{"workflow_id": 9, "max_block_seconds": 10}))
	if isErr || w["status"] != "done" || f.Executed != 1 {
		t.Fatalf("after approval: %v executed=%d", w, f.Executed)
	}
	if res := w["results"].([]any); len(res) != 1 || res[0].(map[string]any)["affected_rows"] != float64(3) {
		t.Errorf("results: %v", w["results"])
	}
	st, _ := e.call(t, "archery_workflow_status", args(map[string]any{"workflow_id": 9}))
	if st["status"] != "done" {
		t.Errorf("status: %v", st)
	}
}

func TestArcheryDDLSwitchAndValidation(t *testing.T) {
	forGenerations(t, testArcheryDDLSwitchAndValidation)
}

func testArcheryDDLSwitchAndValidation(t *testing.T, legacy bool) {
	arch := httptest.NewTLSServer((&archerytest.Fake{Legacy: legacy}).Handler())
	defer arch.Close()
	off := false
	e := setupWithClient(t, arch.Client(), func(c *config.Config) { c.Archery.AllowDDL = &off; c.Archery.DefaultGroup = "dba" })
	loginArchery(t, e, arch)
	out, isErr := e.call(t, "archery_run_sql", map[string]any{"url": arch.URL, "instance": "prod", "database": "d",
		"sql": "ALTER TABLE t ADD c int", "title": "ddl"})
	if !isErr || out["code"] != "ddl_disabled" {
		t.Errorf("ddl: %v", out)
	}
	out, isErr = e.call(t, "archery_run_sql", map[string]any{"url": arch.URL, "instance": "prod", "database": "d", "sql": "BADSQL", "title": "bad"})
	if !isErr || out["code"] != "sql_check_failed" {
		t.Errorf("check: %v", out)
	}
	out, isErr = e.call(t, "archery_run_sql", map[string]any{"url": arch.URL, "instance": "prod"})
	if !isErr || out["code"] != "invalid_argument" {
		t.Errorf("validation: %v", out)
	}
}

func TestArcheryCancelAndRejectedReporting(t *testing.T) {
	forGenerations(t, testArcheryCancelAndRejectedReporting)
}

func testArcheryCancelAndRejectedReporting(t *testing.T, legacy bool) {
	f := &archerytest.Fake{Legacy: legacy}
	arch := httptest.NewTLSServer(f.Handler())
	defer arch.Close()
	e := setupWithClient(t, arch.Client(), func(c *config.Config) { c.Archery.PollInterval = 20 * time.Millisecond; c.Archery.DefaultGroup = "dba" })
	loginArchery(t, e, arch)
	args := func(m map[string]any) map[string]any { m["url"] = arch.URL; return m }

	run, _ := e.call(t, "archery_run_sql", args(map[string]any{"instance": "prod", "database": "d", "sql": "UPDATE t SET a=1", "title": "x", "wait": false}))
	if run["workflow_id"] != float64(9) {
		t.Fatalf("run: %v", run)
	}
	out, isErr := e.call(t, "archery_cancel", args(map[string]any{"workflow_id": 9, "reason": "no longer needed"}))
	if isErr || out["status"] != "aborted" || !f.Cancelled || f.CancelRemark != "no longer needed" {
		t.Fatalf("cancel: %v cancelled=%v remark=%q", out, f.Cancelled, f.CancelRemark)
	}
	// A cancelled workflow cannot be cancelled again.
	if out, isErr = e.call(t, "archery_cancel", args(map[string]any{"workflow_id": 9})); !isErr || out["code"] != "invalid_argument" {
		t.Errorf("second cancel: %v", out)
	}
	// An approver's rejection is reported as such, with their reason.
	f.Mu.Lock()
	f.Status, f.LogOp, f.LogInfo = "workflow_abort", "审核不通过", "touches orders"
	f.Mu.Unlock()
	w, _ := e.call(t, "archery_wait", args(map[string]any{"workflow_id": 9, "max_block_seconds": 5}))
	if w["status"] != "rejected" || w["reason"] != "touches orders" {
		t.Errorf("rejected: %v", w)
	}
	if out, isErr = e.call(t, "archery_workflow_status", args(map[string]any{"workflow_id": 999})); !isErr || out["code"] != "workflow_not_found" {
		t.Errorf("unknown workflow: %v", out)
	}
}
