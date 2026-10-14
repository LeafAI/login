package config

import (
	"fmt"
	"net"
	"regexp"
	"time"
)

// Database is one database an agent may run SQL against. Only a target the owner has written down here can be reached:
// the agent names it, it never supplies a host, a port or a connection string.
//
// The environment is a label that stops a slip of the pen (a production host pasted into the wrong place); securl cannot
// tell whether a host really is production. The real boundary is the database account the person types in: give it only
// what an agent may do there.
type Database struct {
	Name        string   `yaml:"name"`
	Driver      string   `yaml:"driver"`      // postgres | mysql
	Host        string   `yaml:"host"`        // a name or an address, with no port
	Port        int      `yaml:"port"`        // default: the driver's own
	Environment string   `yaml:"environment"` // dev | test | staging; production is refused
	Databases   []string `yaml:"databases"`   // the database names an agent may use; empty: any the account can open
	Mode        string   `yaml:"mode"`        // read_only (default) | read_write
	TLS         string   `yaml:"tls"`         // verify (default) | skip-verify | disable
	AllowDDL    bool     `yaml:"allow_ddl"`   // only with mode: read_write
	// MaxRows is the most rows one query returns, and RowsDefault what it returns when the call gives no limit.
	MaxRows          int           `yaml:"max_rows"`
	MaxChangedRows   int           `yaml:"max_changed_rows"`  // a change that touches more is rolled back
	StatementTimeout time.Duration `yaml:"statement_timeout"` // per statement
}

// The values a target may take.
const (
	DriverPostgres = "postgres"
	DriverMySQL    = "mysql"

	ModeReadOnly  = "read_only"
	ModeReadWrite = "read_write"

	TLSVerify     = "verify"
	TLSSkipVerify = "skip-verify"
	TLSDisable    = "disable"
)

// Limits that no configuration can raise.
const (
	hardMaxRows         = 10000
	hardStatementTimout = 5 * time.Minute

	defaultRows           = 1000
	defaultMaxChangedRows = 1000
	defaultStatementTime  = 30 * time.Second
)

var (
	dbNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	dbSchemaPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$.-]{0,62}$`)
	hostPattern     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
)

// Writable reports whether the target takes changes.
func (d Database) Writable() bool { return d.Mode == ModeReadWrite }

// AllowsDDL reports whether schema changes are allowed (never on a read-only target).
func (d Database) AllowsDDL() bool { return d.Writable() && d.AllowDDL }

// TLSMode returns the TLS mode, defaulting to full verification.
func (d Database) TLSMode() string {
	if d.TLS == "" {
		return TLSVerify
	}
	return d.TLS
}

// RowLimit is how many rows a query returns when the call does not say.
func (d Database) RowLimit() int {
	if d.MaxRows > 0 && d.MaxRows < defaultRows {
		return d.MaxRows
	}
	return defaultRows
}

// MaxRowLimit is the most rows a query may ask for.
func (d Database) MaxRowLimit() int {
	if d.MaxRows > 0 {
		return d.MaxRows
	}
	return hardMaxRows
}

// ChangedRowsLimit is how many rows one change may touch before it is rolled back.
func (d Database) ChangedRowsLimit() int {
	if d.MaxChangedRows > 0 {
		return d.MaxChangedRows
	}
	return defaultMaxChangedRows
}

// StatementTimeoutOrDefault is how long one statement may run.
func (d Database) StatementTimeoutOrDefault() time.Duration {
	if d.StatementTimeout > 0 {
		return d.StatementTimeout
	}
	return defaultStatementTime
}

// Database finds a target by its exact name.
func (c *Config) Database(name string) (Database, bool) {
	if name == "" {
		return Database{}, false
	}
	for _, d := range c.Databases {
		if d.Name == name {
			return d, true
		}
	}
	return Database{}, false
}

// applyDatabaseDefaults fills what a target leaves out, without changing the slice the caller passed.
func applyDatabaseDefaults(in []Database) []Database {
	out := make([]Database, len(in))
	for i, d := range in {
		if d.Port == 0 {
			switch d.Driver {
			case DriverPostgres:
				d.Port = 5432
			case DriverMySQL:
				d.Port = 3306
			}
		}
		if d.Mode == "" {
			d.Mode = ModeReadOnly
		}
		out[i] = d
	}
	return out
}

func (d Database) validate() error {
	if !dbNamePattern.MatchString(d.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", d.Name)
	}
	if d.Driver != DriverPostgres && d.Driver != DriverMySQL {
		return fmt.Errorf("driver %q: use %s or %s", d.Driver, DriverPostgres, DriverMySQL)
	}
	if err := validateEnvironment(d.Environment); err != nil {
		return err
	}
	if !plainHost(d.Host) {
		return fmt.Errorf("host %q: give a host name or an address only, with no port, scheme or user", d.Host)
	}
	if d.Port < 1 || d.Port > 65535 {
		return fmt.Errorf("port %d: use 1-65535", d.Port)
	}
	if d.Mode != ModeReadOnly && d.Mode != ModeReadWrite {
		return fmt.Errorf("mode %q: use %s or %s", d.Mode, ModeReadOnly, ModeReadWrite)
	}
	switch d.TLS {
	case "", TLSVerify, TLSSkipVerify, TLSDisable:
	default:
		return fmt.Errorf("tls %q: use %s, %s or %s", d.TLS, TLSVerify, TLSSkipVerify, TLSDisable)
	}
	if d.AllowDDL && !d.Writable() {
		return fmt.Errorf("allow_ddl: true needs mode: %s", ModeReadWrite)
	}
	return d.validateLimits()
}

// plainHost accepts a host name or an IP address, nothing that carries a port, a scheme or a user. An IPv6 address is
// checked by parsing it: a pattern of hex digits and colons would also accept "db:5432".
func plainHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	return hostPattern.MatchString(h)
}

func validateEnvironment(env string) error {
	switch env {
	case "dev", "test", "staging":
		return nil
	case "":
		return fmt.Errorf("environment is required: dev, test or staging (production databases are not reachable here; use Archery)")
	}
	return fmt.Errorf("environment %q: use dev, test or staging (production databases are not reachable here; use Archery)", env)
}

func (d Database) validateLimits() error {
	for _, n := range d.Databases {
		if !dbSchemaPattern.MatchString(n) {
			return fmt.Errorf("databases: %q is not a plain database name", n)
		}
	}
	if d.MaxRows < 0 || d.MaxRows > hardMaxRows {
		return fmt.Errorf("max_rows %d: use 1-%d", d.MaxRows, hardMaxRows)
	}
	if d.MaxChangedRows < 0 {
		return fmt.Errorf("max_changed_rows %d: must not be negative", d.MaxChangedRows)
	}
	if d.StatementTimeout < 0 || d.StatementTimeout > hardStatementTimout {
		return fmt.Errorf("statement_timeout %s: use up to %s", d.StatementTimeout, hardStatementTimout)
	}
	return nil
}

// validateDatabases checks every target and that no name is used twice.
func validateDatabases(ds []Database) error {
	seen := map[string]bool{}
	for i, d := range ds {
		if err := d.validate(); err != nil {
			return fmt.Errorf("databases[%d] (%s): %w", i, d.Name, err)
		}
		if seen[d.Name] {
			return fmt.Errorf("databases: the name %q is used twice", d.Name)
		}
		seen[d.Name] = true
	}
	return nil
}
