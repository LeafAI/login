package dbexec

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/netguard"
)

type myError = *mysql.MySQLError

// serverGrace is how much later than the client the server cuts off a statement.
const serverGrace = 5 * time.Second

type mySession struct {
	db *sql.DB
	t  config.Database
}

func openMySQL(ctx context.Context, t config.Database, c Credentials, database string, o Options) (session, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.DBName = c.Username, c.Password, database
	cfg.Net, cfg.Addr = "tcp", fmt.Sprintf("%s:%d", t.Host, t.Port)
	cfg.DialFunc = netguard.DialContext(o.AllowLocal)
	cfg.Timeout = connectTimeout
	cfg.ReadTimeout = t.StatementTimeoutOrDefault() + connectTimeout
	cfg.TLS = myTLS(t)
	// The server is only ever asked for what this package sends: no several statements in one text for a read, no
	// LOAD DATA LOCAL INFILE (a hostile server could otherwise ask for any file of this machine), no cleartext password.
	cfg.MultiStatements = t.Writable()
	cfg.AllowAllFiles, cfg.AllowCleartextPasswords, cfg.AllowOldPasswords = false, false, false
	// The server stops a read that runs long as a second line of defence, but it must never be the first: MySQL ends an
	// interrupted SLEEP() quietly and answers "1" instead of an error, which would read as a result. The client's own
	// timeout comes first and says so; this one is a few seconds later, for a client that has gone away.
	cfg.Params = map[string]string{
		"max_execution_time": strconv.FormatInt((t.StatementTimeoutOrDefault() + serverGrace).Milliseconds(), 10),
	}
	// Count the rows a statement matched, not only those whose value changed: "SET qty = qty" changes nothing yet touches
	// every row, and a limit on touched rows must see it.
	cfg.ClientFoundRows = true
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("mysql: %w", err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, classifyMySQLConnect(err)
	}
	return &mySession{db: db, t: t}, nil
}

func myTLS(t config.Database) *tls.Config {
	switch t.TLSMode() {
	case config.TLSDisable:
		return nil
	case config.TLSSkipVerify:
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 -- the owner chose tls: skip-verify
	}
	return &tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS12}
}

func classifyMySQLConnect(err error) error {
	var me myError
	if errors.As(err, &me) {
		if me.Number == 1045 || me.Number == 1044 {
			return ErrBadCredentials
		}
		return fmt.Errorf("%w: %s", ErrUnreachable, safeMessage(me.Message))
	}
	if errors.Is(err, netguard.ErrBlocked) {
		return ErrLocalAddress
	}
	return fmt.Errorf("%w: %s", ErrUnreachable, connectReason(err))
}

func (s *mySession) close() { _ = s.db.Close() }

func (s *mySession) query(ctx context.Context, q string, readOnly bool, maxRows int) (*QueryResult, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	b := newBounded(cols, maxRows)
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		if !b.add(vals) {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b.result(), nil
}

// exec runs a text of statements in one transaction. With several statements, RowsAffected of the driver is only the
// last one's, so the statements are run one at a time and the counts are added up.
func (s *mySession) exec(ctx context.Context, q string, maxChanged int64) (*ExecResult, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, stmt := range statements(q) {
		r, err := tx.ExecContext(ctx, stmt)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		n, _ := r.RowsAffected()
		total += n
		if total > maxChanged {
			_ = tx.Rollback()
			return &ExecResult{RowsAffected: total, RolledBack: true}, ErrTooManyRows
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ExecResult{RowsAffected: total}, nil
}
