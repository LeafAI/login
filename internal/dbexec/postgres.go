package dbexec

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/netguard"
)

type pgSession struct {
	conn *pgx.Conn
	t    config.Database
}

func openPostgres(ctx context.Context, t config.Database, c Credentials, database string, o Options) (session, error) {
	// ParseConfig reads PGHOST, PGSERVICE, ~/.pgpass and friends from this machine. None of that may reach a connection
	// the agent can trigger, so every field that decides where we connect, as whom and how safely is set below from the
	// target and the person's credentials, and the fallback hosts a service file could add are dropped.
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	cfg.Host, cfg.Port = t.Host, uint16(t.Port)
	cfg.User, cfg.Password, cfg.Database = c.Username, c.Password, database
	cfg.TLSConfig, cfg.Fallbacks = pgTLS(t), nil
	cfg.ConnectTimeout = connectTimeout
	cfg.DialFunc = netguard.DialContext(o.AllowLocal)
	cfg.OAuthTokenProvider, cfg.AfterConnect, cfg.ValidateConnect = nil, nil, nil
	cfg.RuntimeParams = map[string]string{
		"application_name": "securl",
		// The server stops a statement on its own, whatever the client does with the connection.
		"statement_timeout":                   strconv.FormatInt(t.StatementTimeoutOrDefault().Milliseconds(), 10),
		"idle_in_transaction_session_timeout": "60000",
	}
	if !t.Writable() {
		// A read-only target is read-only for the whole session, so a statement cannot start a read-write transaction.
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, classifyPostgresConnect(err)
	}
	return &pgSession{conn: conn, t: t}, nil
}

func pgTLS(t config.Database) *tls.Config {
	switch t.TLSMode() {
	case config.TLSDisable:
		return nil
	case config.TLSSkipVerify:
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 -- the owner chose tls: skip-verify
	}
	return &tls.Config{ServerName: t.Host, MinVersion: tls.VersionTLS12}
}

func classifyPostgresConnect(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		if pe.Code == "28P01" || pe.Code == "28000" {
			return ErrBadCredentials
		}
		return fmt.Errorf("%w: %s", ErrUnreachable, safeMessage(pe.Message))
	}
	if errors.Is(err, netguard.ErrBlocked) {
		return ErrLocalAddress
	}
	return fmt.Errorf("%w: %s", ErrUnreachable, connectReason(err))
}

func (s *pgSession) close() { _ = s.conn.Close(context.Background()) }

func (s *pgSession) query(ctx context.Context, sql string, readOnly bool, maxRows int) (*QueryResult, error) {
	tx, err := s.conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	rows, err := tx.Query(ctx, sql, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := make([]string, 0, len(rows.FieldDescriptions()))
	for _, f := range rows.FieldDescriptions() {
		cols = append(cols, f.Name)
	}
	b := newBounded(cols, maxRows)
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
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

// exec runs one text of statements in a transaction and adds up what every statement changed: with several statements
// in one text, the last statement's count alone would let an earlier one go past the limit unnoticed.
func (s *pgSession) exec(ctx context.Context, sql string, maxChanged int64) (*ExecResult, error) {
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	results, err := s.conn.PgConn().Exec(ctx, sql).ReadAll()
	if err != nil {
		_ = tx.Rollback(context.Background())
		return nil, err
	}
	var total int64
	for _, r := range results {
		total += r.CommandTag.RowsAffected()
	}
	res := &ExecResult{RowsAffected: total}
	if total > maxChanged {
		_ = tx.Rollback(context.Background())
		res.RolledBack = true
		return res, ErrTooManyRows
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}
