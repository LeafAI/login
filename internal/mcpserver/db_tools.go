package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dbexec"
	"github.com/LeafAI/securl/internal/dbsite"
	"github.com/LeafAI/securl/internal/notify"
	"github.com/LeafAI/securl/internal/redact"
	"github.com/LeafAI/securl/internal/site"
)

// dbConn is one open database connection, as the tools use it.
type dbConn interface {
	Query(ctx context.Context, sql string, limit int) (*dbexec.QueryResult, error)
	Exec(ctx context.Context, sql string) (*dbexec.ExecResult, error)
	Close()
}

// dbOpener opens a connection. The product connects for real; a test hands in a fake.
type dbOpener interface {
	Open(ctx context.Context, t config.Database, c dbexec.Credentials, database string, o dbexec.Options) (dbConn, error)
}

type realDB struct{}

func (realDB) Open(ctx context.Context, t config.Database, c dbexec.Credentials, database string, o dbexec.Options) (dbConn, error) {
	return dbexec.OpenDatabase(ctx, t, c, database, o)
}

// maxReasonRunes bounds the agent's reason in a message to people.
const maxReasonRunes = 200

// sqlPreviewRunes is how much of a statement a notification shows.
const sqlPreviewRunes = 500

func (s *Server) dbOptions() dbexec.Options {
	return dbexec.Options{AllowLocal: s.cfg.Security.AllowLocalAddresses}
}

// openDriver is the login driver of every database target.
func (s *Server) openDriver() *dbsite.Driver {
	return dbsite.New(s.cfg.Database, func(ctx context.Context, t config.Database, c dbexec.Credentials, database string) error {
		cn, err := s.db.Open(ctx, t, c, database, s.dbOptions())
		if err != nil {
			return err
		}
		cn.Close()
		return nil
	})
}

// dbTarget resolves a target the agent named and the credentials of the session for it. The target must be configured;
// the session must exist (a person types the account with session_open, never an agent).
func (s *Server) dbTarget(k *core, name string) (config.Database, *site.Session, *ToolError) {
	t, ok := s.cfg.Database(name)
	if !ok {
		e := errf("unknown_target", false, "there is no database target named %q", clipName(name))
		e.Hint = "Call " + toolDBTargets + " to see the targets the owner has configured."
		return t, nil, e
	}
	e, ok := k.cache.GetWithin(context.Background(), dbsite.BaseURL(t.Name), nil, sessionFreshness)
	if !ok {
		te := errf("no_session", false, "there is no session for the database %s", t.Name)
		te.Hint = "Call " + toolSessionOpen + " with url " + dbsite.BaseURL(t.Name).String() + ": a person types the database account once, then " + toolDBQuery + " uses it."
		return t, nil, te
	}
	return t, e.Session, nil
}

func clipName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// pickDatabase decides which database a call uses: the one it names (which the target must list), or the only one the
// target lists, or, when the owner listed none, none at all (the account decides what it can open). The agent never
// reaches a database that a list of the owner's excludes.
func pickDatabase(t config.Database, asked string) (string, *ToolError) {
	switch {
	case asked != "":
		if len(t.Databases) > 0 && !contains(t.Databases, asked) {
			e := errf("database_not_allowed", false, "%q is not one of the databases of %s", clipName(asked), t.Name)
			e.Hint = "Use one of: " + strings.Join(t.Databases, ", ") + "."
			return "", e
		}
		return asked, nil
	case len(t.Databases) == 1:
		return t.Databases[0], nil
	case len(t.Databases) == 0:
		return "", nil // the owner named none: the account's default database (PostgreSQL: postgres) is where it starts
	}
	return "", errf("invalid_argument", false, "database is required: %s has several (%s)", t.Name, strings.Join(t.Databases, ", "))
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// scrubber removes the account's password from anything that goes back to the agent. The user name is left alone: it is
// not a secret (the database says it to anybody who asks, in CURRENT_USER() and in every list of grants), and removing it
// damaged ordinary answers, since the name of a company or a product is usually in the name of the account and of every
// database it owns.
func scrubber(sess *site.Session) *redact.Scrubber {
	return redact.New([]string{sess.Tokens[dbsite.TokenPassword]})
}

func (s *Server) dbTargets(_ context.Context, _ *mcp.CallToolRequest, _ Empty) (any, *ToolError) {
	out := DBTargetsOutput{Targets: []DBTargetInfo{}}
	var k *core
	if c, terr := s.gate(); terr == nil {
		k = c
	}
	for _, t := range s.cfg.Databases {
		info := DBTargetInfo{Name: t.Name, Driver: t.Driver, Environment: t.Environment, Mode: t.Mode, AllowDDL: t.AllowsDDL(),
			Databases: append([]string{}, t.Databases...), MaxRows: t.MaxRowLimit(), MaxChangedRows: t.ChangedRowsLimit()}
		if k != nil {
			_, ok := k.cache.GetWithin(context.Background(), dbsite.BaseURL(t.Name), nil, sessionFreshness)
			info.HasSession = ok
		}
		out.Targets = append(out.Targets, info)
	}
	return out, nil
}

func (s *Server) dbQuery(ctx context.Context, _ *mcp.CallToolRequest, in DBQueryInput) (any, *ToolError) {
	k, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	t, sess, terr := s.dbTarget(k, in.Target)
	if terr != nil {
		return nil, terr
	}
	database, terr := pickDatabase(t, in.Database)
	if terr != nil {
		return nil, terr
	}
	cn, err := s.db.Open(ctx, t, credsOf(sess), database, s.dbOptions())
	if err != nil {
		return nil, s.dbErr(k, t, sess, err)
	}
	defer cn.Close()
	res, err := cn.Query(ctx, in.SQL, in.Limit)
	if err != nil {
		return nil, s.dbErr(k, t, sess, err)
	}
	out := DBQueryOutput{Columns: res.Columns, Rows: res.Rows, Truncated: res.Truncated}
	out.Rows, out.Columns, out.Redactions = scrubResult(scrubber(sess), res)
	s.audit.Record(audit.Event{Event: "db_query", Site: t.Name, Host: t.Environment, Bytes: res.TotalBytes})
	return out, nil
}

func (s *Server) dbExec(ctx context.Context, _ *mcp.CallToolRequest, in DBExecInput) (any, *ToolError) {
	k, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return nil, errf("invalid_argument", false, "reason is required: the team is told about every change, and reads it there")
	}
	t, sess, terr := s.dbTarget(k, in.Target)
	if terr != nil {
		return nil, terr
	}
	if !t.Writable() {
		e := errf("target_read_only", false, "%s is read-only (mode: read_only)", t.Name)
		e.Hint = "Only the owner can make a target writable, in the securl configuration. " + toolDBQuery + " reads from it."
		return nil, e
	}
	database, terr := pickDatabase(t, in.Database)
	if terr != nil {
		return nil, terr
	}
	cn, err := s.db.Open(ctx, t, credsOf(sess), database, s.dbOptions())
	if err != nil {
		return nil, s.dbErr(k, t, sess, err)
	}
	defer cn.Close()
	res, err := cn.Exec(ctx, in.SQL)
	if err != nil && !errors.Is(err, dbexec.ErrTooManyRows) {
		return nil, s.dbErr(k, t, sess, err)
	}
	notified := s.announceChange(ctx, t, database, in.SQL, reason, res, err)
	s.audit.Record(audit.Event{Event: "db_exec", Site: t.Name, Host: t.Environment, Result: execResult(res, err)})
	if err != nil {
		return nil, s.dbErr(k, t, sess, err)
	}
	return DBExecOutput{RowsAffected: res.RowsAffected, Notified: notified}, nil
}

func execResult(res *dbexec.ExecResult, err error) string {
	switch {
	case err != nil:
		return "rolled_back"
	case res != nil:
		return "ok"
	}
	return "error"
}

// announceChange tells the team what was changed, after it was. It reports whether the message went out; a failure to
// send it is not an error of the change, which has been made (or rolled back) either way.
func (s *Server) announceChange(ctx context.Context, t config.Database, database, sql, reason string, res *dbexec.ExecResult, runErr error) bool {
	if s.notify == nil {
		return false
	}
	outcome := "**Changed**: " + fmt.Sprint(rowsOf(res)) + " row(s)"
	title := "Database change: " + notify.Escape(t.Name, 50)
	if runErr != nil {
		outcome = "**Rolled back**: the change touched " + fmt.Sprint(rowsOf(res)) + " rows, more than the " + fmt.Sprint(t.ChangedRowsLimit()) + " this target allows, so nothing was kept"
		title = "Database change rolled back: " + notify.Escape(t.Name, 50)
	}
	text := fmt.Sprintf("### %s\n\n- **Target**: %s (%s, %s)\n- **Database**: %s\n- **Requested by AI agent**: %s\n- %s\n\n```sql\n%s\n```\n",
		title, notify.Escape(t.Name, 64), t.Driver, t.Environment, notify.Escape(database, 64),
		notify.Escape(reason, maxReasonRunes), outcome, notify.CodeBlock(sql, sqlPreviewRunes))
	return s.notify.Markdown(ctx, title, text) == nil
}

func rowsOf(r *dbexec.ExecResult) int64 {
	if r == nil {
		return 0
	}
	return r.RowsAffected
}

func credsOf(sess *site.Session) dbexec.Credentials {
	return dbexec.Credentials{Username: sess.Tokens[dbsite.TokenUser], Password: sess.Tokens[dbsite.TokenPassword]}
}

// dbErr turns what the database layer says into a tool error. A password the database refused ends the session.
func (s *Server) dbErr(k *core, t config.Database, sess *site.Session, err error) *ToolError {
	switch {
	case errors.Is(err, dbexec.ErrBadCredentials):
		k.cache.Delete(dbsite.Key(t.Name))
		e := errf("session_expired", true, "the database no longer accepts the saved account for %s", t.Name)
		e.Hint = "Call " + toolSessionOpen + " with url " + dbsite.BaseURL(t.Name).String() + " and force_refresh=true: a person types the account again."
		return e
	case errors.Is(err, dbexec.ErrNotReadOnly):
		e := errf("not_read_only", false, "%v", err)
		e.Hint = "Use " + toolDBExec + " for changes, on a target whose mode is read_write."
		return e
	case errors.Is(err, dbexec.ErrEmptyStatement):
		return errf("invalid_argument", false, "%v", err)
	case errors.Is(err, dbexec.ErrReadOnlyTarget):
		return errf("target_read_only", false, "%v", err)
	case errors.Is(err, dbexec.ErrDDLRefused):
		e := errf("ddl_disabled", false, "%v", err)
		e.Hint = "Only the owner can allow schema changes, with allow_ddl on the target."
		return e
	case errors.Is(err, dbexec.ErrTooManyRows):
		return errf("too_many_rows", false, "%v", err)
	case errors.Is(err, dbexec.ErrDatabaseNotAllowed):
		return errf("database_not_allowed", false, "%v", err)
	case errors.Is(err, dbexec.ErrTimeout):
		return errf("statement_timeout", true, "%v", err)
	case errors.Is(err, dbexec.ErrUnreachable):
		return errf("site_unreachable", true, "%s cannot be reached", t.Name)
	case errors.Is(err, dbexec.ErrLocalAddress):
		return errf("host_not_allowed", false, "%v", err)
	}
	msg, _ := scrubber(sess).Text(err.Error())
	return errf("sql_error", false, "%s", msg)
}

// scrubResult removes the account's values from every cell and column name, and counts what it removed.
func scrubResult(sc *redact.Scrubber, res *dbexec.QueryResult) (rows [][]any, cols []string, n int) {
	cols = make([]string, len(res.Columns))
	for i, c := range res.Columns {
		var k int
		cols[i], k = sc.Text(c)
		n += k
	}
	rows = make([][]any, len(res.Rows))
	for i, r := range res.Rows {
		rows[i] = make([]any, len(r))
		for j, v := range r {
			if str, ok := v.(string); ok {
				var k int
				rows[i][j], k = sc.Text(str)
				n += k
				continue
			}
			rows[i][j] = v
		}
	}
	return rows, cols, n
}

// openDatabaseSession is session_open for db://<name>: it asks a person for the account through the usual page.
func (s *Server) databaseTarget(raw string) (config.Database, *url.URL, *ToolError) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != dbsite.Scheme || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return config.Database{}, nil, errf("invalid_argument", false, "a database is named db://<target>, with a target from %s", toolDBTargets)
	}
	t, ok := s.cfg.Database(u.Host)
	if !ok {
		e := errf("unknown_target", false, "there is no database target named %q", clipName(u.Host))
		e.Hint = "Call " + toolDBTargets + " to see the targets the owner has configured."
		return t, nil, e
	}
	return t, dbsite.BaseURL(t.Name), nil
}
