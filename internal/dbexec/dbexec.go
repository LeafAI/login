// Package dbexec runs SQL on a PostgreSQL or MySQL database the owner has listed in the configuration.
//
// The credentials come from a person (typed on the login page and kept in the vault); the agent names a target and sends
// SQL, nothing else. This package is where the limits are enforced, whatever the caller does: a read-only target runs
// every statement in a read-only transaction, a change touching too many rows is rolled back, DDL is refused unless the
// target allows it, a statement that runs too long is stopped, and a result is bounded in rows and in bytes.
package dbexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/sqlscan"
)

// Errors with a stable meaning for the MCP layer.
var (
	ErrBadCredentials     = errors.New("the database refused the username or password")
	ErrUnreachable        = errors.New("the database cannot be reached")
	ErrNotReadOnly        = errors.New("only a single read-only statement (SELECT, SHOW, EXPLAIN, WITH ... SELECT) is accepted here")
	ErrEmptyStatement     = errors.New("there is no statement to run")
	ErrReadOnlyTarget     = errors.New("this database is read-only (mode: read_only)")
	ErrDDLRefused         = errors.New("schema changes are not allowed on this database (allow_ddl is off)")
	ErrTooManyRows        = errors.New("the change touched more rows than this database allows (max_changed_rows) and was rolled back")
	ErrDatabaseNotAllowed = errors.New("that database name is not one this target allows")
	ErrTimeout            = errors.New("the statement ran longer than the target allows (statement_timeout) and was stopped")
	ErrLocalAddress       = errors.New("connection not permitted: loopback, link-local and cloud-metadata addresses are refused (security.allow_local_addresses lifts this)")
)

// The bounds of one result. A single value is cut at MaxCellBytes, and rows stop once MaxResultBytes of values have been
// collected; either way the result says it was truncated.
const (
	MaxResultBytes = 1 << 20
	MaxCellBytes   = 64 << 10
)

// Credentials are what a person typed. They are held only to open a connection.
type Credentials struct {
	Username string
	Password string
}

// Options are the parts of the policy that are not the target's own.
type Options struct {
	// AllowLocal is security.allow_local_addresses: without it a connection to this machine's own addresses is refused.
	AllowLocal bool
}

// QueryResult is what a read returns.
type QueryResult struct {
	Columns    []string `json:"columns"`
	Rows       [][]any  `json:"rows"`
	Truncated  bool     `json:"truncated,omitempty"`
	TotalBytes int      `json:"-"`
}

// ExecResult is what a change returns.
type ExecResult struct {
	RowsAffected int64 `json:"rows_affected"`
	RolledBack   bool  `json:"rolled_back,omitempty"`
}

// session is what one driver offers; Conn adds the limits on top, so they are the same for both.
type session interface {
	query(ctx context.Context, sql string, readOnly bool, maxRows int) (*QueryResult, error)
	exec(ctx context.Context, sql string, maxChanged int64) (*ExecResult, error)
	close()
}

// Conn is an open connection to one database of a target.
type Conn struct {
	target config.Database
	s      session
}

// Open connects to the target without choosing a database (the account's default one).
func Open(ctx context.Context, t config.Database, c Credentials, o Options) (*Conn, error) {
	return open(ctx, t, c, "", o)
}

// OpenDatabase connects to one database. The name must be one the target lists; when the target lists none, any plain
// name (or none, for the account's default database) is accepted, since the account itself decides what it can open.
func OpenDatabase(ctx context.Context, t config.Database, c Credentials, database string, o Options) (*Conn, error) {
	if err := checkDatabase(t, database); err != nil {
		return nil, err
	}
	return open(ctx, t, c, database, o)
}

func checkDatabase(t config.Database, name string) error {
	if strings.ContainsAny(name, ";'\"`\\ \t\r\n") {
		return ErrDatabaseNotAllowed
	}
	if len(t.Databases) == 0 {
		return nil // the owner named none: the account decides what it can open, and an empty name is its default database
	}
	if name == "" {
		return ErrDatabaseNotAllowed // the list names databases, and the account's default is not one of them
	}
	for _, d := range t.Databases {
		if d == name {
			return nil
		}
	}
	return ErrDatabaseNotAllowed
}

func open(ctx context.Context, t config.Database, c Credentials, database string, o Options) (*Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	var (
		s   session
		err error
	)
	switch t.Driver {
	case config.DriverPostgres:
		s, err = openPostgres(ctx, t, c, database, o)
	case config.DriverMySQL:
		s, err = openMySQL(ctx, t, c, database, o)
	default:
		return nil, fmt.Errorf("unknown database driver %q", t.Driver)
	}
	if err != nil {
		return nil, err
	}
	return &Conn{target: t, s: s}, nil
}

const connectTimeout = 20 * time.Second

// Close ends the connection.
func (c *Conn) Close() { c.s.close() }

// Query runs one read-only statement and returns at most limit rows (the target's own ceiling applies as well).
func (c *Conn) Query(ctx context.Context, sql string, limit int) (*QueryResult, error) {
	if err := checkRead(sql); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.target.StatementTimeoutOrDefault())
	defer cancel()
	res, err := c.s.query(ctx, sql, true, c.rowLimit(limit))
	return res, c.classify(ctx, err)
}

func (c *Conn) rowLimit(asked int) int {
	max := c.target.MaxRowLimit()
	if asked <= 0 {
		asked = c.target.RowLimit()
	}
	return min(asked, max)
}

// Exec runs statements that change data. A target that is not read_write refuses them before anything is sent, DDL needs
// allow_ddl, and a change that touches more than max_changed_rows rows is rolled back.
func (c *Conn) Exec(ctx context.Context, sql string) (*ExecResult, error) {
	if !c.target.Writable() {
		return nil, ErrReadOnlyTarget
	}
	if strings.TrimSpace(sql) == "" {
		return nil, ErrEmptyStatement
	}
	if !c.target.AllowsDDL() && sqlscan.HasDDL(sql) {
		return nil, ErrDDLRefused
	}
	ctx, cancel := context.WithTimeout(ctx, c.target.StatementTimeoutOrDefault())
	defer cancel()
	res, err := c.s.exec(ctx, sql, int64(c.target.ChangedRowsLimit()))
	return res, c.classify(ctx, err)
}

// checkRead accepts a single read statement: one statement, and one that starts with a reading keyword. The transaction
// is read-only as well, so this is the second net, and the one that gives a clear message.
func checkRead(sql string) error {
	if strings.TrimSpace(sql) == "" || sqlscan.OnlyComments(sql) {
		return ErrEmptyStatement
	}
	if !sqlscan.IsSingleRead(sql) {
		return ErrNotReadOnly
	}
	return nil
}

// classify turns what a driver says into the errors above. The driver's own text is kept out of the answer unless it is
// the database's message about the statement, which never holds the password.
func (c *Conn) classify(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTooManyRows), errors.Is(err, ErrNotReadOnly):
		return err
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrTimeout
	}
	return err
}
