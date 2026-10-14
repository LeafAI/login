package dbexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
)

// The integration tests need real servers. SECURL_TEST_PG and SECURL_TEST_MYSQL name them as host:port; each test is
// skipped when its server is not named, so `go test` works on a machine without Docker. CI starts both as services.
//
// Both servers hold database appdb with a table items(id, name, qty) of 50 rows, and two accounts: rw (everything on
// appdb) and ro (SELECT only), each with the password "<name>-pass-1".
const (
	pgEnv = "SECURL_TEST_PG"
	myEnv = "SECURL_TEST_MYSQL"
)

type rig struct {
	target config.Database
	rw, ro Credentials
	name   string
}

func rigFor(t *testing.T, driver string, tweak func(*config.Database)) rig {
	t.Helper()
	env := map[string]string{config.DriverPostgres: pgEnv, config.DriverMySQL: myEnv}[driver]
	addr := os.Getenv(env)
	if addr == "" {
		t.Skipf("%s is not set", env)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	d := config.Database{Name: driver + "-test", Driver: driver, Host: host, Port: p, Environment: "dev",
		Mode: config.ModeReadWrite, TLS: config.TLSDisable, MaxRows: 100, MaxChangedRows: 10, StatementTimeout: 10 * time.Second,
		Databases: []string{"appdb"}}
	if tweak != nil {
		tweak(&d)
	}
	r := rig{target: d, name: driver,
		rw: Credentials{Username: "rw", Password: "rw-pass-1"}, ro: Credentials{Username: "ro", Password: "ro-pass-1"}}
	r.reset(t)
	return r
}

// reset puts the table back as it should be, through the root account of the test servers (SECURL_TEST_PG_ADMIN and
// SECURL_TEST_MYSQL_ADMIN hold "user:password"; the defaults are the ones the CI services and the local containers use).
// Tests change and drop things, and a code mutation under test can do so for real, so no test trusts what an earlier one
// left behind.
func (r rig) reset(t *testing.T) {
	t.Helper()
	admin := Credentials{Username: map[string]string{config.DriverPostgres: "postgres", config.DriverMySQL: "root"}[r.name], Password: "rootpw"}
	d := r.target
	d.Mode, d.AllowDDL, d.MaxChangedRows, d.MaxRows = config.ModeReadWrite, true, 1000, 1000
	cn, err := OpenDatabase(context.Background(), d, admin, "appdb", Options{AllowLocal: true})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	defer cn.Close()
	script := map[string][]string{
		config.DriverPostgres: {
			"DROP TABLE IF EXISTS items, scratch_postgres, sneaky, sneaky2",
			"CREATE TABLE items (id serial primary key, name text not null, qty int not null default 0)",
			"INSERT INTO items(name,qty) SELECT 'item'||g, g FROM generate_series(1,50) g",
			"GRANT ALL ON ALL TABLES IN SCHEMA public TO rw", "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO rw",
			"GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro"},
		config.DriverMySQL: {
			"DROP TABLE IF EXISTS items, scratch_mysql, sneaky, sneaky2",
			"CREATE TABLE items (id int auto_increment primary key, name varchar(100) not null, qty int not null default 0)",
			"INSERT INTO items(name,qty) WITH RECURSIVE n(g) AS (SELECT 1 UNION ALL SELECT g+1 FROM n WHERE g<50) SELECT CONCAT('item',g), g FROM n"},
	}[r.name]
	for _, q := range script {
		if _, err := cn.Exec(context.Background(), q); err != nil {
			t.Fatalf("reset %q: %v", q, err)
		}
	}
}

func (r rig) open(t *testing.T, c Credentials) *Conn {
	t.Helper()
	cn, err := OpenDatabase(context.Background(), r.target, c, "appdb", Options{AllowLocal: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(cn.Close)
	return cn
}

func eachDriver(t *testing.T, tweak func(*config.Database), f func(t *testing.T, r rig)) {
	for _, d := range []string{config.DriverPostgres, config.DriverMySQL} {
		t.Run(d, func(t *testing.T) { f(t, rigFor(t, d, tweak)) })
	}
}

func TestAQueryReturnsRowsAndColumns(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		cn := r.open(t, r.ro)
		res, err := cn.Query(context.Background(), "SELECT id, name FROM items ORDER BY id", 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Columns) != 2 || res.Columns[0] != "id" || res.Columns[1] != "name" {
			t.Errorf("columns %v", res.Columns)
		}
		if len(res.Rows) != 5 || !res.Truncated {
			t.Errorf("%d rows, truncated=%v", len(res.Rows), res.Truncated)
		}
		if fmt.Sprint(res.Rows[0][1]) != "item1" {
			t.Errorf("row 0: %v", res.Rows[0])
		}
	})
}

func TestTheRowLimitIsTheTargetsCeiling(t *testing.T) {
	eachDriver(t, func(d *config.Database) { d.MaxRows = 7 }, func(t *testing.T, r rig) {
		cn := r.open(t, r.ro)
		res, err := cn.Query(context.Background(), "SELECT id FROM items", 5000)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Rows) != 7 || !res.Truncated {
			t.Errorf("max_rows must cap the query: %d rows, truncated=%v", len(res.Rows), res.Truncated)
		}
	})
}

func TestAQueryThatFitsIsNotTruncated(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		res, err := r.open(t, r.ro).Query(context.Background(), "SELECT id FROM items WHERE id <= 3", 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Rows) != 3 || res.Truncated {
			t.Errorf("%d rows, truncated=%v", len(res.Rows), res.Truncated)
		}
	})
}

// A read-only target must refuse a change even when the statement scanner is fooled, and even when the account could
// write: the transaction itself is read-only.
func TestQueryIsReadOnlyEvenForAnAccountThatCanWrite(t *testing.T) {
	eachDriver(t, func(d *config.Database) { d.Mode = config.ModeReadOnly }, func(t *testing.T, r rig) {
		cn := r.open(t, r.rw)
		for name, sql := range map[string]string{
			"update":      "UPDATE items SET qty = 0",
			"insert":      "INSERT INTO items(name, qty) VALUES ('x', 1)",
			"delete":      "DELETE FROM items",
			"cte writes":  "WITH d AS (DELETE FROM items RETURNING 1) SELECT * FROM d",
			"create":      "CREATE TABLE sneaky (a int)",
			"select into": "SELECT * INTO sneaky2 FROM items",
		} {
			if r.name == config.DriverMySQL && (name == "cte writes" || name == "select into") {
				continue // not MySQL syntax
			}
			if _, err := cn.Query(context.Background(), sql, 10); err == nil {
				t.Errorf("%s: a read-only target must refuse it", name)
			}
		}
		res, err := cn.Query(context.Background(), "SELECT count(*) FROM items", 10)
		if err != nil || fmt.Sprint(res.Rows[0][0]) != "50" {
			t.Errorf("nothing may have changed: %v %v", res, err)
		}
	})
}

func TestQueryRefusesWhatIsNotASingleReadStatement(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		cn := r.open(t, r.rw)
		for name, sql := range map[string]string{
			"two statements": "SELECT 1; DELETE FROM items",
			"comment trick":  "SELECT 1 /* x */; DELETE FROM items",
			"update":         "UPDATE items SET qty = 0",
			"empty":          "  ",
			"only comment":   "-- nothing",
			"unterminated":   "SELECT 'oops",
		} {
			_, err := cn.Query(context.Background(), sql, 10)
			if !errors.Is(err, ErrNotReadOnly) && !errors.Is(err, ErrEmptyStatement) {
				t.Errorf("%s: want ErrNotReadOnly or ErrEmptyStatement, got %v", name, err)
			}
		}
		res, _ := cn.Query(context.Background(), "SELECT count(*) FROM items", 10)
		if fmt.Sprint(res.Rows[0][0]) != "50" {
			t.Error("a refused statement must not have run")
		}
	})
}

func TestExecChangesRowsAndSaysHowMany(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		cn := r.open(t, r.rw)
		res, err := cn.Exec(context.Background(), "UPDATE items SET qty = qty WHERE id <= 4")
		if err != nil {
			t.Fatal(err)
		}
		if res.RowsAffected != 4 || res.RolledBack {
			t.Errorf("%+v", res)
		}
	})
}

func TestAChangeThatTouchesTooManyRowsIsRolledBack(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) { // max_changed_rows is 10
		cn := r.open(t, r.rw)
		res, err := cn.Exec(context.Background(), "UPDATE items SET qty = 999")
		if !errors.Is(err, ErrTooManyRows) {
			t.Fatalf("want ErrTooManyRows, got %v", err)
		}
		if res == nil || !res.RolledBack || res.RowsAffected != 50 {
			t.Errorf("%+v", res)
		}
		after, _ := cn.Query(context.Background(), "SELECT count(*) FROM items WHERE qty = 999", 10)
		if fmt.Sprint(after.Rows[0][0]) != "0" {
			t.Errorf("the change must be undone, %v rows still carry it", after.Rows[0][0])
		}
	})
}

func TestExecOnAReadOnlyTargetIsRefusedBeforeItRuns(t *testing.T) {
	eachDriver(t, func(d *config.Database) { d.Mode = config.ModeReadOnly }, func(t *testing.T, r rig) {
		_, err := r.open(t, r.rw).Exec(context.Background(), "UPDATE items SET qty = 1 WHERE id = 1")
		if !errors.Is(err, ErrReadOnlyTarget) {
			t.Errorf("want ErrReadOnlyTarget, got %v", err)
		}
	})
}

func TestDDLIsRefusedUnlessTheTargetAllowsIt(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) { // allow_ddl is off
		cn := r.open(t, r.rw)
		for _, sql := range []string{"DROP TABLE items", "TRUNCATE items", "ALTER TABLE items ADD COLUMN z int", "UPDATE items SET qty = qty WHERE id = 1; DROP TABLE items"} {
			if _, err := cn.Exec(context.Background(), sql); !errors.Is(err, ErrDDLRefused) {
				t.Errorf("%q: want ErrDDLRefused, got %v", sql, err)
			}
		}
		res, _ := cn.Query(context.Background(), "SELECT count(*) FROM items", 10)
		if fmt.Sprint(res.Rows[0][0]) != "50" {
			t.Error("the table must be intact")
		}
	})
	eachDriver(t, func(d *config.Database) { d.AllowDDL = true }, func(t *testing.T, r rig) {
		cn := r.open(t, r.rw)
		if _, err := cn.Exec(context.Background(), "CREATE TABLE scratch_"+r.name+" (a int)"); err != nil {
			t.Fatalf("allow_ddl: %v", err)
		}
		if _, err := cn.Exec(context.Background(), "DROP TABLE scratch_"+r.name); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAStatementThatRunsTooLongIsStopped(t *testing.T) {
	eachDriver(t, func(d *config.Database) { d.StatementTimeout = time.Second }, func(t *testing.T, r rig) {
		sleep := map[string]string{config.DriverPostgres: "SELECT pg_sleep(5)", config.DriverMySQL: "SELECT SLEEP(5)"}[r.name]
		start := time.Now()
		_, err := r.open(t, r.ro).Query(context.Background(), sleep, 10)
		if err == nil {
			t.Fatal("must time out")
		}
		if took := time.Since(start); took > 4*time.Second {
			t.Errorf("stopped after %s", took)
		}
	})
}

func TestBadCredentialsAreReportedAsSuch(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		_, err := OpenDatabase(context.Background(), r.target, Credentials{Username: "rw", Password: "WRONG-PASSWORD-123"}, "appdb", Options{AllowLocal: true})
		if !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("want ErrBadCredentials, got %v", err)
		}
		if strings.Contains(err.Error(), "WRONG-PASSWORD-123") {
			t.Errorf("the error carries the password: %v", err)
		}
	})
}

func TestNoErrorCarriesThePassword(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		cn := r.open(t, r.rw)
		for _, sql := range []string{"SELECT * FROM no_such_table", "SELEC 1", "UPDATE items SET nope = 1"} {
			_, err := cn.Query(context.Background(), sql, 10)
			_, err2 := cn.Exec(context.Background(), sql)
			for _, e := range []error{err, err2} {
				if e != nil && (strings.Contains(e.Error(), "rw-pass-1") || strings.Contains(e.Error(), "rootpw")) {
					t.Errorf("the error carries a password: %v", e)
				}
			}
		}
	})
}

func TestNoConnectionToThisMachineUnlessAllowed(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		_, err := OpenDatabase(context.Background(), r.target, r.ro, "appdb", Options{AllowLocal: false})
		if err == nil {
			t.Fatal("a database on this machine must be refused when local addresses are not allowed")
		}
		if errors.Is(err, ErrBadCredentials) {
			t.Errorf("it must be refused before any credential is sent: %v", err)
		}
	})
}

func TestTheUsedDatabaseIsOnlyOneTheTargetNames(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		if _, err := OpenDatabase(context.Background(), r.target, r.ro, "appdb", Options{AllowLocal: true}); err != nil {
			t.Fatalf("appdb: %v", err)
		}
		for _, name := range []string{"postgres", "mysql", "information_schema", "appdb;drop", ""} {
			if _, err := OpenDatabase(context.Background(), r.target, r.ro, name, Options{AllowLocal: true}); !errors.Is(err, ErrDatabaseNotAllowed) {
				t.Errorf("%q: want ErrDatabaseNotAllowed, got %v", name, err)
			}
		}
	})
}

func TestValuesOfEveryTypeComeBackAsJSONFriendlyValues(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		sql := map[string]string{
			config.DriverPostgres: "SELECT 1::int AS i, 2.5::numeric AS n, 'x'::text AS s, now() AS ts, '{\"a\":1}'::jsonb AS j, NULL::int AS nul, true AS b, '\\x0102'::bytea AS bin, ARRAY[1,2] AS arr",
			config.DriverMySQL:    "SELECT 1 AS i, 2.5 AS n, 'x' AS s, now() AS ts, JSON_OBJECT('a',1) AS j, NULL AS nul, true AS b, X'0102' AS bin",
		}[r.name]
		res, err := r.open(t, r.ro).Query(context.Background(), sql, 10)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := marshalRows(res.Rows); err != nil {
			t.Errorf("the rows must encode as JSON: %v", err)
		}
		if res.Rows[0][5] != nil {
			t.Errorf("NULL must stay null: %v", res.Rows[0][5])
		}
	})
}

func TestAHugeValueIsClippedAndTheResultIsBounded(t *testing.T) {
	eachDriver(t, func(d *config.Database) { d.MaxRows = 1000 }, func(t *testing.T, r rig) {
		sql := map[string]string{
			config.DriverPostgres: "SELECT repeat('a', 5000000) AS big FROM generate_series(1,200)",
			config.DriverMySQL:    "SELECT REPEAT('a', 5000000) AS big FROM items LIMIT 50",
		}[r.name]
		res, err := r.open(t, r.ro).Query(context.Background(), sql, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if res.TotalBytes > MaxResultBytes+MaxCellBytes {
			t.Errorf("the result is %d bytes, over the %d bound", res.TotalBytes, MaxResultBytes)
		}
		if !res.Truncated {
			t.Error("a result cut for size must say so")
		}
		for _, row := range res.Rows {
			if s, ok := row[0].(string); ok && len(s) > MaxCellBytes+64 {
				t.Fatalf("a cell of %d bytes", len(s))
			}
		}
	})
}

func TestExecRefusesAnEmptyText(t *testing.T) {
	eachDriver(t, nil, func(t *testing.T, r rig) {
		cn := r.open(t, r.rw)
		for _, sql := range []string{"", "   ", "\n\t"} {
			if _, err := cn.Exec(context.Background(), sql); !errors.Is(err, ErrEmptyStatement) {
				t.Errorf("%q: want ErrEmptyStatement, got %v", sql, err)
			}
		}
	})
}

// An empty name would open the account's default database, which the target's list never named.
func TestNoDatabaseNameMeansNoConnectionWhenTheTargetNamesSome(t *testing.T) {
	d := config.Database{Databases: []string{"appdb"}}
	if err := checkDatabase(d, ""); !errors.Is(err, ErrDatabaseNotAllowed) {
		t.Errorf("an empty name: %v", err)
	}
	open := config.Database{}
	if err := checkDatabase(open, ""); err != nil {
		t.Errorf("a target that lists no names takes the account's default database: %v", err)
	}
	if err := checkDatabase(open, "anything_plain"); err != nil {
		t.Errorf("a target that lists no names accepts a plain one: %v", err)
	}
	if err := checkDatabase(d, "appdb"); err != nil {
		t.Errorf("a listed name: %v", err)
	}
}

// A target that lists no databases lets the account open any it can: the login must work without naming one, since
// nothing names one. (It was refused as an empty name, so such a target could never be logged in to.)
func TestATargetThatListsNoDatabasesCanBeOpenedWithoutOne(t *testing.T) {
	eachDriver(t, func(d *config.Database) { d.Databases = nil }, func(t *testing.T, r rig) {
		cn, err := OpenDatabase(context.Background(), r.target, r.ro, "", Options{AllowLocal: true})
		if err != nil {
			t.Fatalf("a target without a database list: %v", err)
		}
		defer cn.Close()
		if _, err := cn.Query(context.Background(), "SELECT 1", 10); err != nil {
			t.Errorf("the connection must work: %v", err)
		}
	})
}

// A name still has to be plain, whether or not the target lists names.
func TestAnEmptyNameIsOnlyAcceptedWhenTheTargetListsNone(t *testing.T) {
	if err := checkDatabase(config.Database{}, ""); err != nil {
		t.Errorf("no list and no name: %v", err)
	}
	if err := checkDatabase(config.Database{Databases: []string{"appdb"}}, ""); !errors.Is(err, ErrDatabaseNotAllowed) {
		t.Errorf("a list and no name must be refused: %v", err)
	}
	for _, bad := range []string{"a;b", "a b", "a'b", "a\"b", "a`b", "a\\b", "a\nb"} {
		if err := checkDatabase(config.Database{}, bad); !errors.Is(err, ErrDatabaseNotAllowed) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
