package mcpserver_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/site/archery/archerytest"
)

// loginArchery completes the (password-only) login round through the real page.
func loginArchery(t *testing.T, e *env, fake *httptest.Server) {
	t.Helper()
	out, _ := e.call(t, "login", map[string]any{"url": fake.URL, "site": "archery", "max_block_seconds": 1})
	if out["status"] != "pending" {
		t.Fatalf("expected pending login, got %v", out)
	}
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw"}`, "")
	out, isErr := e.call(t, "login_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if isErr || out["status"] != "ok" || !strings.Contains(out["cookie_header"].(string), "sessionid=S") {
		t.Fatalf("archery login: %v", out)
	}
}

func TestArcheryToolsEndToEnd(t *testing.T) {
	f := &archerytest.Fake{}
	arch := httptest.NewServer(f.Handler())
	defer arch.Close()
	e := setupWith(t, func(c *config.Config) {
		c.Archery.PollInterval = 20 * time.Millisecond
		c.Archery.DefaultGroup = "dba"
	})
	loginArchery(t, e, arch)
	args := func(m map[string]any) map[string]any { m["url"] = arch.URL; return m }

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
	if isErr || run["status"] != "pending" || run["workflow_id"] != float64(42) || run["next_tool"] != "archery_wait" {
		t.Fatalf("run_sql: %v", run)
	}
	if !strings.Contains(e.rec.wait(t, 2), "workflow #42") {
		t.Error("approver notification missing")
	}
	if f.Submitted.Get("group_name") != "dba" {
		t.Errorf("default group not used: %v", f.Submitted)
	}
	w, _ := e.call(t, "archery_wait", args(map[string]any{"workflow_id": 42, "max_block_seconds": 1}))
	if w["status"] != "pending" || w["phase"] != "awaiting_approval" || f.Executed != 0 {
		t.Fatalf("before approval: %v executed=%d", w, f.Executed)
	}
	f.Mu.Lock()
	f.Status = "workflow_review_pass"
	f.Mu.Unlock()
	w, isErr = e.call(t, "archery_wait", args(map[string]any{"workflow_id": 42, "max_block_seconds": 10}))
	if isErr || w["status"] != "done" || f.Executed != 1 {
		t.Fatalf("after approval: %v executed=%d", w, f.Executed)
	}
	if res := w["results"].([]any); len(res) != 1 || res[0].(map[string]any)["affected_rows"] != float64(3) {
		t.Errorf("results: %v", w["results"])
	}
	st, _ := e.call(t, "archery_workflow_status", args(map[string]any{"workflow_id": 42}))
	if st["status"] != "done" {
		t.Errorf("status: %v", st)
	}
}

func TestArcheryDDLSwitchAndValidation(t *testing.T) {
	arch := httptest.NewServer((&archerytest.Fake{}).Handler())
	defer arch.Close()
	off := false
	e := setupWith(t, func(c *config.Config) { c.Archery.AllowDDL = &off; c.Archery.DefaultGroup = "dba" })
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
