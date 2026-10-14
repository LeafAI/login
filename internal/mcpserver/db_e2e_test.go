package mcpserver_test

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
)

// The full path with real databases: the tool asks for a session, a person types the account on the real page, and the
// database tools use it. SECURL_TEST_PG and SECURL_TEST_MYSQL name the servers (see the dbexec tests).
func dbTarget(t *testing.T, driver, name, mode string) config.Database {
	t.Helper()
	env := map[string]string{config.DriverPostgres: "SECURL_TEST_PG", config.DriverMySQL: "SECURL_TEST_MYSQL"}[driver]
	addr := os.Getenv(env)
	if addr == "" {
		t.Skipf("%s is not set", env)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	return config.Database{Name: name, Driver: driver, Host: host, Port: p, Environment: "dev", Mode: mode,
		TLS: config.TLSDisable, Databases: []string{"appdb"}, MaxChangedRows: 10, MaxRows: 100}
}

func loginDB(t *testing.T, e *env, target, user, pass string) map[string]any {
	t.Helper()
	out, _ := e.call(t, "session_open", map[string]any{"url": "db://" + target, "reason": "run a query", "max_block_seconds": 1})
	if out["status"] != "pending" {
		t.Fatalf("expected a pending login, got %v", out)
	}
	n := len(e.rec.all())
	human(t, e.rec.wait(t, n), e.dir, "submit", fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass), "")
	res, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if isErr {
		t.Fatalf("login: %v", res)
	}
	return res
}

func TestDatabaseEndToEnd(t *testing.T) {
	for _, tc := range []struct{ driver, user, pass string }{
		{config.DriverPostgres, "rw", "rw-pass-1"},
		{config.DriverMySQL, "rw", "rw-pass-1"},
	} {
		t.Run(tc.driver, func(t *testing.T) {
			e := setupWith(t, func(c *config.Config) {
				c.Databases = []config.Database{dbTarget(t, tc.driver, "dev", config.ModeReadWrite)}
			})
			q := func(sql string) (map[string]any, bool) {
				return e.call(t, "db_query", map[string]any{"target": "dev", "sql": sql})
			}
			if out, isErr := q("SELECT 1"); !isErr || out["code"] != "no_session" {
				t.Fatalf("no session yet: %v", out)
			}
			res := loginDB(t, e, "dev", tc.user, tc.pass)
			if res["status"] != "ok" {
				t.Fatalf("%v", res)
			}
			assertNoCredentials(t, res, tc.pass, tc.user)

			out, isErr := q("SELECT id, name FROM items ORDER BY id")
			if isErr {
				t.Fatalf("%v", out)
			}
			if rows, _ := out["rows"].([]any); len(rows) != 50 {
				t.Errorf("%d rows", len(rows))
			}
			if out, isErr := q("DELETE FROM items"); !isErr || out["code"] != "not_read_only" {
				t.Errorf("a write through db_query: %v", out)
			}
			ex, isErr := e.call(t, "db_exec", map[string]any{"target": "dev", "sql": "UPDATE items SET qty = qty WHERE id <= 3", "reason": "touch three rows"})
			if isErr || ex["rows_affected"] != float64(3) {
				t.Fatalf("%v", ex)
			}
			if ex, isErr := e.call(t, "db_exec", map[string]any{"target": "dev", "sql": "UPDATE items SET qty = 0", "reason": "too many"}); !isErr || ex["code"] != "too_many_rows" {
				t.Errorf("%v", ex)
			}
			after, _ := q("SELECT count(*) AS n FROM items WHERE qty = 0")
			if rows, _ := after["rows"].([]any); fmt.Sprint(rows[0]) != "[0]" {
				t.Errorf("the rolled back change must have left nothing: %v", after)
			}
			var told int
			for _, m := range e.rec.all() {
				if strings.Contains(m, "Database change") {
					told++
					if strings.Contains(m, tc.pass) {
						t.Errorf("a message carries the password: %s", m)
					}
				}
			}
			if told != 2 {
				t.Errorf("one message for the change and one for the rollback, got %d", told)
			}
			raw, _ := os.ReadFile(e.auditFile)
			if strings.Contains(string(raw), tc.pass) {
				t.Error("the audit log carries the password")
			}
			if out, _ := e.call(t, "session_close", map[string]any{"url": "db://dev"}); out["removed"] != float64(1) {
				t.Errorf("%v", out)
			}
			if out, isErr := q("SELECT 1"); !isErr || out["code"] != "no_session" {
				t.Errorf("after session_close: %v", out)
			}
		})
	}
}

func TestADatabaseLoginWithAWrongPasswordIsReported(t *testing.T) {
	e := setupWith(t, func(c *config.Config) {
		c.Databases = []config.Database{dbTarget(t, config.DriverPostgres, "dev", config.ModeReadOnly)}
	})
	out, _ := e.call(t, "session_open", map[string]any{"url": "db://dev", "max_block_seconds": 1})
	human(t, e.rec.wait(t, len(e.rec.all())), e.dir, "submit", `{"username":"ro","password":"WRONG-PASSWORD-1"}`, "")
	res, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if !isErr || res["code"] != "bad_credentials" {
		t.Errorf("%v", res)
	}
	if strings.Contains(fmt.Sprint(res), "WRONG-PASSWORD-1") {
		t.Errorf("the answer carries the password: %v", res)
	}
	if out, isErr := e.call(t, "db_query", map[string]any{"target": "dev", "sql": "SELECT 1"}); !isErr || out["code"] != "no_session" {
		t.Errorf("a failed login must leave no session: %v", out)
	}
}

func TestAReadOnlyAccountOnAReadOnlyTarget(t *testing.T) {
	e := setupWith(t, func(c *config.Config) {
		c.Databases = []config.Database{dbTarget(t, config.DriverMySQL, "dev", config.ModeReadOnly)}
	})
	loginDB(t, e, "dev", "ro", "ro-pass-1")
	out, isErr := e.call(t, "db_query", map[string]any{"target": "dev", "sql": "SELECT count(*) AS n FROM items"})
	if isErr {
		t.Fatalf("%v", out)
	}
	if out, isErr := e.call(t, "db_exec", map[string]any{"target": "dev", "sql": "DELETE FROM items", "reason": "x"}); !isErr || out["code"] != "target_read_only" {
		t.Errorf("%v", out)
	}
}
