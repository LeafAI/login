package config

import (
	"strings"
	"testing"
)

const goodDB = `
databases:
  - name: gm-dev-pg
    driver: postgres
    host: pg.dev.corp.example
    port: 5432
    environment: dev
    databases: [blockchain_watcher]
    mode: read_only
`

func parseDB(t *testing.T, y string) (*Config, error) {
	t.Helper()
	if err := ParseStrict([]byte(y)); err != nil {
		return nil, err
	}
	c, err := Parse([]byte(y), t.TempDir())
	if err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func TestADatabaseTargetIsReadFromTheConfiguration(t *testing.T) {
	c, err := parseDB(t, goodDB)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Databases) != 1 {
		t.Fatalf("%d targets", len(c.Databases))
	}
	d := c.Databases[0]
	if d.Name != "gm-dev-pg" || d.Driver != "postgres" || d.Host != "pg.dev.corp.example" || d.Port != 5432 || d.Environment != "dev" {
		t.Errorf("%+v", d)
	}
	if d.Writable() {
		t.Error("read_only must not be writable")
	}
	if d.TLSMode() != TLSVerify {
		t.Errorf("the default must verify the server certificate, got %q", d.TLSMode())
	}
}

func TestDatabaseDefaults(t *testing.T) {
	c, err := parseDB(t, "databases:\n  - {name: m, driver: mysql, host: db.corp.example, environment: test}\n")
	if err != nil {
		t.Fatal(err)
	}
	d := c.Databases[0]
	if d.Port != 3306 {
		t.Errorf("mysql default port: %d", d.Port)
	}
	if d.Writable() || d.AllowsDDL() {
		t.Error("a target is read-only and refuses DDL unless it says otherwise")
	}
	if d.RowLimit() != 1000 || d.MaxRowLimit() != 10000 || d.ChangedRowsLimit() != 1000 {
		t.Errorf("limits: %d %d %d", d.RowLimit(), d.MaxRowLimit(), d.ChangedRowsLimit())
	}
	pg, _ := parseDB(t, "databases:\n  - {name: p, driver: postgres, host: db.corp.example, environment: dev}\n")
	if pg.Databases[0].Port != 5432 {
		t.Errorf("postgres default port: %d", pg.Databases[0].Port)
	}
}

func TestADatabaseTargetThatCannotBeTrustedIsRefusedAtStartup(t *testing.T) {
	ok := "driver: postgres, host: db.corp.example, environment: dev"
	for name, tc := range map[string]struct{ y, want string }{
		"production":        {"databases:\n  - {name: a, driver: postgres, host: db.corp.example, environment: prod}\n", "environment"},
		"production long":   {"databases:\n  - {name: a, driver: postgres, host: db.corp.example, environment: production}\n", "environment"},
		"no environment":    {"databases:\n  - {name: a, driver: postgres, host: db.corp.example}\n", "environment"},
		"unknown env":       {"databases:\n  - {name: a, driver: postgres, host: db.corp.example, environment: live}\n", "environment"},
		"unknown driver":    {"databases:\n  - {name: a, driver: oracle, host: db.corp.example, environment: dev}\n", "driver"},
		"no name":           {"databases:\n  - {" + ok + "}\n", "name"},
		"bad name":          {"databases:\n  - {name: 'a b', " + ok + "}\n", "name"},
		"long name":         {"databases:\n  - {name: " + strings.Repeat("a", 65) + ", " + ok + "}\n", "name"},
		"no host":           {"databases:\n  - {name: a, driver: postgres, environment: dev}\n", "host"},
		"host with port":    {"databases:\n  - {name: a, driver: postgres, host: 'db.corp.example:5432', environment: dev}\n", "host"},
		"host with scheme":  {"databases:\n  - {name: a, driver: postgres, host: 'postgres://db', environment: dev}\n", "host"},
		"host with at":      {"databases:\n  - {name: a, driver: postgres, host: 'u@db.corp.example', environment: dev}\n", "host"},
		"port too big":      {"databases:\n  - {name: a, " + ok + ", port: 70000}\n", "port"},
		"negative port":     {"databases:\n  - {name: a, " + ok + ", port: -1}\n", "port"},
		"unknown mode":      {"databases:\n  - {name: a, " + ok + ", mode: admin}\n", "mode"},
		"unknown tls":       {"databases:\n  - {name: a, " + ok + ", tls: maybe}\n", "tls"},
		"duplicate name":    {"databases:\n  - {name: a, " + ok + "}\n  - {name: a, " + ok + "}\n", "twice"},
		"empty db name":     {"databases:\n  - {name: a, " + ok + ", databases: ['']}\n", "databases"},
		"bad db name":       {"databases:\n  - {name: a, " + ok + ", databases: ['x;drop']}\n", "databases"},
		"max over the hard": {"databases:\n  - {name: a, " + ok + ", max_rows: 20000}\n", "max_rows"},
		"negative rows":     {"databases:\n  - {name: a, " + ok + ", max_rows: -1}\n", "max_rows"},
		"negative changed":  {"databases:\n  - {name: a, " + ok + ", max_changed_rows: -5}\n", "max_changed_rows"},
		"timeout too long":  {"databases:\n  - {name: a, " + ok + ", statement_timeout: 1h}\n", "statement_timeout"},
		"ddl on read only":  {"databases:\n  - {name: a, " + ok + ", allow_ddl: true}\n", "allow_ddl"},
		"unknown key":       {"databases:\n  - {name: a, " + ok + ", pasword: x}\n", "pasword"},
	} {
		_, err := parseDB(t, tc.y)
		if err == nil {
			t.Errorf("%s: must be refused", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the error should name %q: %v", name, tc.want, err)
		}
	}
}

func TestTheEnvironmentsThatAreNotProduction(t *testing.T) {
	for _, env := range []string{"dev", "test", "staging"} {
		if _, err := parseDB(t, "databases:\n  - {name: a, driver: mysql, host: db.corp.example, environment: "+env+"}\n"); err != nil {
			t.Errorf("%s: %v", env, err)
		}
	}
}

func TestTheSecurityChoicesAreExplicit(t *testing.T) {
	y := "databases:\n  - {name: a, driver: postgres, host: db.corp.example, environment: dev, mode: read_write, allow_ddl: true, tls: skip-verify, max_rows: 50, max_changed_rows: 7, statement_timeout: 5s}\n"
	c, err := parseDB(t, y)
	if err != nil {
		t.Fatal(err)
	}
	d := c.Databases[0]
	if !d.Writable() || !d.AllowsDDL() || d.TLSMode() != TLSSkipVerify || d.ChangedRowsLimit() != 7 || d.StatementTimeoutOrDefault().Seconds() != 5 {
		t.Errorf("%+v", d)
	}
	if d.MaxRowLimit() != 50 {
		t.Errorf("max_rows is the ceiling for one query: %d", d.MaxRowLimit())
	}
}

func TestADatabaseTargetIsFoundByName(t *testing.T) {
	c, err := parseDB(t, goodDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Database("gm-dev-pg"); !ok {
		t.Error("not found")
	}
	if _, ok := c.Database("GM-DEV-PG"); ok {
		t.Error("names are exact: an agent must not reach a target by a lookalike")
	}
	if _, ok := c.Database(""); ok {
		t.Error("empty name")
	}
}

// allow_ddl on a read-only target is refused at startup, but the answer the tools get must not depend on that alone.
func TestDDLIsNeverAllowedOnAReadOnlyTarget(t *testing.T) {
	d := Database{Mode: ModeReadOnly, AllowDDL: true}
	if d.AllowsDDL() {
		t.Error("a read-only target allows no DDL, whatever allow_ddl says")
	}
	if !(Database{Mode: ModeReadWrite, AllowDDL: true}).AllowsDDL() {
		t.Error("a read_write target with allow_ddl allows it")
	}
	if (Database{Mode: ModeReadWrite}).AllowsDDL() {
		t.Error("allow_ddl is off unless it is written")
	}
}

func TestOnlyReadWriteIsWritable(t *testing.T) {
	for mode, want := range map[string]bool{ModeReadOnly: false, ModeReadWrite: true, "": false, "admin": false, "READ_WRITE": false} {
		if got := (Database{Mode: mode}).Writable(); got != want {
			t.Errorf("mode %q: Writable() = %v, want %v", mode, got, want)
		}
	}
}

func TestHostsThatAreNotPlainHostsAreRefused(t *testing.T) {
	for _, h := range []string{"db:5432", "db/x", "u@db", "db name", "-db", "db-", "[::1]", "db.corp.example.", "db\n"} {
		d := Database{Name: "a", Driver: DriverPostgres, Host: h, Port: 5432, Environment: "dev", Mode: ModeReadOnly}
		if err := d.validate(); err == nil {
			t.Errorf("host %q must be refused", h)
		}
	}
	for _, h := range []string{"db", "db.corp.example", "10.0.0.5", "fd00::5", "pg-1.dev.corp.example"} {
		d := Database{Name: "a", Driver: DriverPostgres, Host: h, Port: 5432, Environment: "dev", Mode: ModeReadOnly}
		if err := d.validate(); err != nil {
			t.Errorf("host %q: %v", h, err)
		}
	}
}
