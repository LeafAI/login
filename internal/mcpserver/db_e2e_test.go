package mcpserver_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
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

// Two targets of the same engine, on the same server, each logged in with its own account on the real page: the read-only
// account can read and cannot write, the other can write, and neither login replaced the other.
func TestTwoTargetsOfOneEngineEachKeepTheirOwnAccountEndToEnd(t *testing.T) {
	for _, driver := range []string{config.DriverPostgres, config.DriverMySQL} {
		t.Run(driver, func(t *testing.T) {
			ro := dbTarget(t, driver, "reader", config.ModeReadOnly)
			rw := dbTarget(t, driver, "writer", config.ModeReadWrite)
			e := setupWith(t, func(c *config.Config) { c.Databases = []config.Database{ro, rw} })
			loginDB(t, e, "reader", "ro", "ro-pass-1")
			loginDB(t, e, "writer", "rw", "rw-pass-1")

			if out, isErr := e.call(t, "db_query", map[string]any{"target": "reader", "sql": "SELECT count(*) AS n FROM items"}); isErr {
				t.Fatalf("the read-only target must still work after the second login: %v", out)
			}
			if out, isErr := e.call(t, "db_exec", map[string]any{"target": "writer", "sql": "UPDATE items SET qty = qty WHERE id <= 2", "reason": "two accounts"}); isErr || out["rows_affected"] != float64(2) {
				t.Fatalf("the writing target must use the writing account: %v", out)
			}
			// What the database itself says about who it was: the same server, two different accounts.
			who := map[string]string{config.DriverPostgres: "SELECT current_user AS u", config.DriverMySQL: "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1) AS u"}[driver]
			got := map[string]string{}
			for _, target := range []string{"reader", "writer"} {
				out, isErr := e.call(t, "db_query", map[string]any{"target": target, "sql": who})
				if isErr {
					t.Fatalf("%s: %v", target, out)
				}
				got[target] = fmt.Sprint(out["rows"].([]any)[0].([]any)[0])
			}
			if got["reader"] != "ro" || got["writer"] != "rw" {
				t.Errorf("each target must connect as its own account: %v", got)
			}
			// Closing one leaves the other.
			e.call(t, "session_close", map[string]any{"url": "db://reader"})
			if out, isErr := e.call(t, "db_query", map[string]any{"target": "reader", "sql": "SELECT 1"}); !isErr || out["code"] != "no_session" {
				t.Errorf("%v", out)
			}
			if out, isErr := e.call(t, "db_query", map[string]any{"target": "writer", "sql": "SELECT 1"}); isErr {
				t.Errorf("the other target must be untouched: %v", out)
			}
		})
	}
}

// The case that cost a person their login: the database cannot be reached for a while (a VPN is off, a server restarts), and a
// session older than the freshness window is probed in that moment. The account is good, so it must be kept; and when the
// database is back the same account works, with nobody asked to type it again. Run on real servers: the database is stopped
// and started for real.
func TestAnAccountSurvivesTheDatabaseGoingAwayAndComingBack(t *testing.T) {
	for _, tc := range []struct{ driver, container string }{
		{config.DriverPostgres, "securl-test-pg"},
		{config.DriverMySQL, "securl-test-my"},
	} {
		t.Run(tc.driver, func(t *testing.T) {
			e := setupFull(t, nil, mcpserver.Options{SessionFreshness: -1}, func(c *config.Config) {
				c.Databases = []config.Database{dbTarget(t, tc.driver, "dev", config.ModeReadOnly)}
			})
			loginDB(t, e, "dev", "ro", "ro-pass-1")
			q := func() (map[string]any, bool) {
				return e.call(t, "db_query", map[string]any{"target": "dev", "sql": "SELECT 1 AS one"})
			}
			if out, isErr := q(); isErr {
				t.Fatalf("%v", out)
			}
			// SessionFreshness is negative: every use asks the database, as one does once enough time has passed.

			docker(t, "pause", tc.container) // the network goes away: connections hang, nothing answers
			out, isErr := q()
			docker(t, "unpause", tc.container)
			if !isErr || (out["code"] != "site_unreachable" && out["code"] != "statement_timeout") {
				t.Fatalf("a database that cannot be reached is reported as such: %v", out)
			}
			if out["code"] == "no_session" || out["code"] == "session_expired" {
				t.Fatalf("the account must not be reported lost: %v", out)
			}

			if out, isErr := q(); isErr {
				t.Fatalf("with the database back the same account works, and nobody was asked again: %v", out)
			}
			if n := len(e.rec.all()); n != 1 {
				t.Errorf("exactly one login message was ever sent (the first); got %d", n)
			}
		})
	}
}

// docker runs one docker command for a test and fails it if the command fails.
func docker(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Skipf("docker %v: %v: %s (the servers are not containers of this machine)", args, err, out)
	}
}
