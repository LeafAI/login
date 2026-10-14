package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dbexec"
	"github.com/LeafAI/securl/internal/dbsite"
	"github.com/LeafAI/securl/internal/site"
)

// fakeDB stands in for the databases: it records what the tools asked of it, so these tests check the tools' own rules
// (which target, which account, what is refused, what is audited and announced) without a server. The real servers are
// the business of the dbexec tests.
type fakeDB struct {
	mu       sync.Mutex
	opened   []openCall
	queries  []string
	execs    []string
	loginErr error
	queryErr error
	execErr  error
	rows     [][]any
	affected int64
}

type openCall struct {
	target, db, user, pass string
}

func (f *fakeDB) Open(_ context.Context, t config.Database, c dbexec.Credentials, database string, _ dbexec.Options) (dbConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened = append(f.opened, openCall{t.Name, database, c.Username, c.Password})
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	return &fakeConn{f: f}, nil
}

type fakeConn struct{ f *fakeDB }

func (c *fakeConn) Close() {}
func (c *fakeConn) Query(_ context.Context, sql string, limit int) (*dbexec.QueryResult, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.queries = append(c.f.queries, sql)
	if c.f.queryErr != nil {
		return nil, c.f.queryErr
	}
	return &dbexec.QueryResult{Columns: []string{"id"}, Rows: c.f.rows}, nil
}
func (c *fakeConn) Exec(_ context.Context, sql string) (*dbexec.ExecResult, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.execs = append(c.f.execs, sql)
	if c.f.execErr != nil {
		return &dbexec.ExecResult{RowsAffected: c.f.affected, RolledBack: errors.Is(c.f.execErr, dbexec.ErrTooManyRows)}, c.f.execErr
	}
	return &dbexec.ExecResult{RowsAffected: c.f.affected}, nil
}

func (f *fakeDB) opens() []openCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]openCall{}, f.opened...)
}

const dbPass = "DB-PASSWORD-7f3a9c"

type dbEnv struct {
	*gateEnv
	fake *fakeDB
	rec  *notes
}

type notes struct {
	mu   sync.Mutex
	msgs []string
}

func (n *notes) Markdown(_ context.Context, title, text string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, title+"\n"+text)
	return nil
}
func (n *notes) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string{}, n.msgs...)
}

func dbTargets() []config.Database {
	return []config.Database{
		{Name: "dev-pg", Driver: config.DriverPostgres, Host: "pg.dev.corp.example", Port: 5432, Environment: "dev", Mode: config.ModeReadOnly, Databases: []string{"appdb"}},
		{Name: "dev-my", Driver: config.DriverMySQL, Host: "my.dev.corp.example", Port: 3306, Environment: "test", Mode: config.ModeReadWrite, Databases: []string{"appdb", "other"}},
		{Name: "dev-my-ddl", Driver: config.DriverMySQL, Host: "my2.dev.corp.example", Port: 3306, Environment: "dev", Mode: config.ModeReadWrite, AllowDDL: true},
	}
}

// withDB starts an open server that has the three targets and a fake database layer. A session for dev-pg and dev-my
// exists, as if a person had typed the account.
func withDB(t *testing.T, sessions ...string) *dbEnv {
	t.Helper()
	fake := &fakeDB{rows: [][]any{{1}, {2}}, affected: 3}
	rec := &notes{}
	g := gateServer(t, "open", func(c *config.Config) { c.Databases = dbTargets() })
	g.s.db = fake
	g.s.notify = rec
	for _, name := range sessions {
		tg, _ := g.cfg.Database(name)
		_ = tg
		g.s.core.cache.Put(dbsite.BaseURL(name), dbsite.New(g.cfg.Database, nil), &site.Session{
			Tokens: map[string]string{dbsite.TokenUser: "alice", dbsite.TokenPassword: dbPass}})
	}
	return &dbEnv{gateEnv: g, fake: fake, rec: rec}
}

func raw(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestDBTargetsListsWhatIsConfiguredAndNothingSecret(t *testing.T) {
	e := withDB(t, "dev-pg")
	out, isErr := e.call(t, toolDBTargets, map[string]any{})
	if isErr {
		t.Fatalf("%v", out)
	}
	ts, _ := out["targets"].([]any)
	if len(ts) != 3 {
		t.Fatalf("%d targets: %v", len(ts), out)
	}
	byName := map[string]map[string]any{}
	for _, x := range ts {
		m := x.(map[string]any)
		byName[m["name"].(string)] = m
	}
	pg := byName["dev-pg"]
	if pg["driver"] != "postgres" || pg["mode"] != "read_only" || pg["environment"] != "dev" || pg["has_session"] != true {
		t.Errorf("%v", pg)
	}
	if byName["dev-my"]["has_session"] != false || byName["dev-my"]["mode"] != "read_write" || byName["dev-my"]["allow_ddl"] != false {
		t.Errorf("%v", byName["dev-my"])
	}
	if byName["dev-my-ddl"]["allow_ddl"] != true {
		t.Errorf("%v", byName["dev-my-ddl"])
	}
	s := raw(out)
	for _, bad := range []string{dbPass, "alice", "pg.dev.corp.example", "5432", "password"} {
		if strings.Contains(s, bad) {
			t.Errorf("db_targets must not show %q: %s", bad, s)
		}
	}
}

func TestDBQueryNeedsAConfiguredTargetAndASession(t *testing.T) {
	e := withDB(t, "dev-pg")
	out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "nope", "sql": "SELECT 1"})
	if !isErr || out["code"] != "unknown_target" {
		t.Errorf("%v", out)
	}
	out, isErr = e.call(t, toolDBQuery, map[string]any{"target": "dev-my", "database": "appdb", "sql": "SELECT 1"})
	if !isErr || out["code"] != "no_session" || !strings.Contains(raw(out), toolSessionOpen) || !strings.Contains(raw(out), "db://dev-my") {
		t.Errorf("without a session the answer says how to get one: %v", out)
	}
	if len(e.fake.opens()) != 0 {
		t.Error("nothing is opened without a session")
	}
}

func TestDBQueryRunsAsThePersonWhoTypedTheAccount(t *testing.T) {
	e := withDB(t, "dev-pg")
	out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "database": "appdb", "sql": "SELECT id FROM t"})
	if isErr {
		t.Fatalf("%v", out)
	}
	o := e.fake.opens()
	if len(o) != 1 || o[0].target != "dev-pg" || o[0].db != "appdb" || o[0].user != "alice" || o[0].pass != dbPass {
		t.Errorf("%+v", o)
	}
	if len(e.fake.queries) != 1 || e.fake.queries[0] != "SELECT id FROM t" {
		t.Errorf("%v", e.fake.queries)
	}
	if rows, _ := out["rows"].([]any); len(rows) != 2 {
		t.Errorf("%v", out)
	}
	if strings.Contains(raw(out), dbPass) || strings.Contains(raw(out), "alice") {
		t.Errorf("the answer carries the account: %v", out)
	}
}

func TestDBQueryUsesTheOnlyDatabaseWhenTheTargetListsOne(t *testing.T) {
	e := withDB(t, "dev-pg")
	if out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT 1"}); isErr {
		t.Fatalf("%v", out)
	}
	if o := e.fake.opens(); len(o) != 1 || o[0].db != "appdb" {
		t.Errorf("%+v", o)
	}
	e2 := withDB(t, "dev-my")
	out, isErr := e2.call(t, toolDBQuery, map[string]any{"target": "dev-my", "sql": "SELECT 1"})
	if !isErr || out["code"] != "invalid_argument" || !strings.Contains(raw(out), "appdb") || !strings.Contains(raw(out), "other") {
		t.Errorf("with two databases the call must choose, and the answer lists them: %v", out)
	}
}

func TestDBQueryRefusesADatabaseTheTargetDoesNotList(t *testing.T) {
	e := withDB(t, "dev-my")
	out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-my", "database": "mysql", "sql": "SELECT 1"})
	if !isErr || out["code"] != "database_not_allowed" {
		t.Errorf("%v", out)
	}
	if len(e.fake.opens()) != 0 {
		t.Error("a database that is not listed is never opened")
	}
}

func TestDBQueryMapsTheErrorsOfTheDatabaseLayer(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"not read only": {dbexec.ErrNotReadOnly, "not_read_only"},
		"empty":         {dbexec.ErrEmptyStatement, "invalid_argument"},
		"timeout":       {dbexec.ErrTimeout, "statement_timeout"},
		"sql error":     {errors.New("syntax error at or near \"SELEC\""), "sql_error"},
	} {
		e := withDB(t, "dev-pg")
		e.fake.queryErr = tc.err
		out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "x"})
		if !isErr || out["code"] != tc.code {
			t.Errorf("%s: want %s, got %v", name, tc.code, out)
		}
	}
}

func TestAnErrorFromTheDatabaseNeverShowsThePassword(t *testing.T) {
	e := withDB(t, "dev-pg")
	e.fake.queryErr = errors.New("FATAL: password authentication failed for user alice; password " + dbPass + " rejected")
	out, _ := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT 1"})
	if strings.Contains(raw(out), dbPass) {
		t.Errorf("the error carries the password: %v", out)
	}
}

func TestAQueryResultThatEchoesThePasswordIsScrubbed(t *testing.T) {
	e := withDB(t, "dev-pg")
	e.fake.rows = [][]any{{"the password is " + dbPass}, {"user alice"}}
	out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT current_setting('x')"})
	if isErr {
		t.Fatalf("%v", out)
	}
	if strings.Contains(raw(out), dbPass) {
		t.Errorf("the rows carry the password: %v", out)
	}
	if n, _ := out["redactions"].(float64); n < 1 {
		t.Errorf("the answer says how many values were removed: %v", out)
	}
}

func TestDBQueryAudits(t *testing.T) {
	e := withDB(t, "dev-pg")
	e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT secret_looking_text FROM t"})
	b := readFile(t, e.cfg.Audit.File)
	if !strings.Contains(b, `"db_query"`) || !strings.Contains(b, "dev-pg") || !strings.Contains(b, "sql_sha256") {
		t.Errorf("%s", b)
	}
	if strings.Contains(b, "secret_looking_text") || strings.Contains(b, dbPass) {
		t.Errorf("the audit log must not hold the SQL text or the password: %s", b)
	}
}

func TestDBExecIsRefusedOnAReadOnlyTargetBeforeAnythingIsOpened(t *testing.T) {
	e := withDB(t, "dev-pg")
	out, isErr := e.call(t, toolDBExec, map[string]any{"target": "dev-pg", "sql": "DELETE FROM t", "reason": "cleanup"})
	if !isErr || out["code"] != "target_read_only" {
		t.Errorf("%v", out)
	}
	if len(e.fake.opens()) != 0 || len(e.fake.execs) != 0 {
		t.Error("nothing is opened or run")
	}
	if len(e.rec.all()) != 0 {
		t.Error("nobody is told about a refused call")
	}
}

func TestDBExecRunsChangesAndTellsTheTeamAfterwards(t *testing.T) {
	e := withDB(t, "dev-my")
	out, isErr := e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": "UPDATE t SET a = 1", "reason": "fix the fixture"})
	if isErr {
		t.Fatalf("%v", out)
	}
	if out["rows_affected"] != float64(3) || len(e.fake.execs) != 1 {
		t.Errorf("%v %v", out, e.fake.execs)
	}
	msgs := e.rec.all()
	if len(msgs) != 1 {
		t.Fatalf("one DingTalk message after a change, got %d", len(msgs))
	}
	for _, want := range []string{"dev-my", "appdb", "UPDATE t SET a = 1", "fix the fixture", "3"} {
		if !strings.Contains(msgs[0], want) {
			t.Errorf("the message should say %q: %s", want, msgs[0])
		}
	}
	if strings.Contains(msgs[0], dbPass) || strings.Contains(msgs[0], "alice") {
		t.Errorf("the message carries the account: %s", msgs[0])
	}
}

func TestDBExecMessageEscapesWhatTheAgentWrote(t *testing.T) {
	e := withDB(t, "dev-my")
	e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": "UPDATE t SET a = 1",
		"reason": "[click here](http://evil.example) **now**"})
	msgs := e.rec.all()
	if len(msgs) != 1 || strings.Contains(msgs[0], "](http://evil.example)") {
		t.Errorf("the reason must be escaped: %v", msgs)
	}
}

func TestDBExecTellsTheTeamWhenAChangeWasRolledBack(t *testing.T) {
	e := withDB(t, "dev-my")
	e.fake.execErr, e.fake.affected = dbexec.ErrTooManyRows, 5000
	out, isErr := e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": "UPDATE t SET a = 1", "reason": "x"})
	if !isErr || out["code"] != "too_many_rows" {
		t.Errorf("%v", out)
	}
	msgs := e.rec.all()
	if len(msgs) != 1 || !strings.Contains(strings.ToLower(msgs[0]), "rolled back") {
		t.Errorf("%v", msgs)
	}
}

func TestDBExecAnnouncesBeforeItRunsWhenTheTeamCannotBeReached(t *testing.T) {
	e := withDB(t, "dev-my")
	e.s.notify = failingNotifier{}
	out, isErr := e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": "UPDATE t SET a = 1", "reason": "x"})
	if isErr {
		t.Fatalf("a notification that fails afterwards must not undo a change that was made: %v", out)
	}
	if out["notified"] != false {
		t.Errorf("the answer says the team was not told: %v", out)
	}
}

type failingNotifier struct{}

func (failingNotifier) Markdown(context.Context, string, string) error {
	return errors.New("webhook down")
}

func TestDBExecDDLNeedsTheTargetToAllowIt(t *testing.T) {
	e := withDB(t, "dev-my", "dev-my-ddl")
	e.fake.execErr = dbexec.ErrDDLRefused
	out, isErr := e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": "DROP TABLE t", "reason": "x"})
	if !isErr || out["code"] != "ddl_disabled" {
		t.Errorf("%v", out)
	}
	if len(e.rec.all()) != 0 {
		t.Error("a refused change is not announced as a change")
	}
}

func TestDBExecRequiresAReason(t *testing.T) {
	e := withDB(t, "dev-my")
	out, isErr := e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": "UPDATE t SET a = 1"})
	if !isErr || out["code"] != "invalid_argument" || !strings.Contains(raw(out), "reason") {
		t.Errorf("%v", out)
	}
	if len(e.fake.execs) != 0 {
		t.Error("nothing runs without a reason the team can read")
	}
}

func TestDBToolsNeedTheVaultOpen(t *testing.T) {
	g := gateServer(t, "locked", func(c *config.Config) { c.Databases = dbTargets() })
	for tool, args := range map[string]map[string]any{
		toolDBQuery: {"target": "dev-pg", "sql": "SELECT 1"},
		toolDBExec:  {"target": "dev-pg", "sql": "SELECT 1", "reason": "x"},
	} {
		out, isErr := g.call(t, tool, args)
		if !isErr || out["code"] != "vault_locked" {
			t.Errorf("%s: %v", tool, out)
		}
	}
	if out, isErr := g.call(t, toolDBTargets, map[string]any{}); isErr {
		t.Errorf("db_targets needs no secret and works while the vault is locked: %v", out)
	}
}

func TestADatabaseSessionIsInvisibleToTheWebTools(t *testing.T) {
	e := withDB(t, "dev-pg")
	out, isErr := e.call(t, toolRequest, map[string]any{"url": "https://dev-pg", "method": "GET", "path": "/"})
	if !isErr {
		t.Errorf("request must not reach a database: %v", out)
	}
	list, _ := e.call(t, toolSessionList, map[string]any{})
	if strings.Contains(raw(list), dbPass) || strings.Contains(raw(list), "alice") {
		t.Errorf("session_list shows the account: %v", list)
	}
}

func TestDBSessionOpenOnlyForAConfiguredTarget(t *testing.T) {
	e := withDB(t)
	out, isErr := e.call(t, toolSessionOpen, map[string]any{"url": "db://not-configured"})
	if !isErr || (out["code"] != "unknown_target" && out["code"] != "invalid_argument") {
		t.Errorf("%v", out)
	}
	for _, bad := range []string{"db://", "db://a b", "db://dev-pg/extra", "db://user:pw@dev-pg", "DB://dev-pg"} {
		if out, isErr := e.call(t, toolSessionOpen, map[string]any{"url": bad}); !isErr {
			t.Errorf("%q: %v", bad, out)
		}
	}
}

func TestSiteListMentionsDatabasesWithoutListingHosts(t *testing.T) {
	e := withDB(t)
	out, _ := e.call(t, toolSiteList, map[string]any{})
	if strings.Contains(raw(out), "pg.dev.corp.example") {
		t.Errorf("%v", out)
	}
}

func TestThePolicyShowsWhichTargetsExistWithoutHosts(t *testing.T) {
	e := withDB(t)
	p := e.s.policy()
	if len(p.DatabaseTargets) != 3 {
		t.Fatalf("%+v", p.DatabaseTargets)
	}
	if strings.Contains(raw(p), "corp.example") {
		t.Errorf("the policy must not carry hosts: %s", raw(p))
	}
}

func TestSessionCloseForgetsADatabaseAccount(t *testing.T) {
	e := withDB(t, "dev-pg", "dev-my")
	out, isErr := e.call(t, toolSessionClose, map[string]any{"url": "db://dev-pg"})
	if isErr || out["removed"] != float64(1) {
		t.Fatalf("%v", out)
	}
	if out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT 1"}); !isErr || out["code"] != "no_session" {
		t.Errorf("the account must be gone: %v", out)
	}
	if out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-my", "database": "appdb", "sql": "SELECT 1"}); isErr {
		t.Errorf("the other target's account is untouched: %v", out)
	}
	all, _ := e.call(t, toolSessionClose, map[string]any{"all": true})
	if all["removed"] != float64(1) {
		t.Errorf("all removes the rest: %v", all)
	}
}

func TestSessionCloseRefusesABadDatabaseURL(t *testing.T) {
	e := withDB(t, "dev-pg")
	for _, bad := range []string{"db://dev-pg/x", "db://", "db://user@dev-pg"} {
		if out, isErr := e.call(t, toolSessionClose, map[string]any{"url": bad}); !isErr {
			t.Errorf("%q: %v", bad, out)
		}
	}
	if _, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT 1"}); isErr {
		t.Error("a refused close must not have removed the account")
	}
}

// What the agent wrote must not be able to close the code block of the message and add text outside it.
func TestDBExecMessageKeepsTheSQLInsideItsCodeBlock(t *testing.T) {
	e := withDB(t, "dev-my")
	sql := "UPDATE t SET a = 1 -- ```\n\n**Approved by the security team** [verify](http://evil.example)"
	e.call(t, toolDBExec, map[string]any{"target": "dev-my", "database": "appdb", "sql": sql, "reason": "x"})
	msgs := e.rec.all()
	if len(msgs) != 1 {
		t.Fatalf("%v", msgs)
	}
	if n := strings.Count(msgs[0], "```"); n != 2 {
		t.Errorf("the statement must sit in one code block, found %d fences: %s", n, msgs[0])
	}
}

// A password the database no longer accepts ends the session, so the next call asks a person instead of trying again with
// a dead password.
func TestARefusedPasswordEndsTheSession(t *testing.T) {
	e := withDB(t, "dev-pg")
	e.fake.loginErr = dbexec.ErrBadCredentials
	out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT 1"})
	if !isErr || out["code"] != "session_expired" || !strings.Contains(raw(out), "force_refresh") {
		t.Fatalf("%v", out)
	}
	e.fake.loginErr = nil
	out, isErr = e.call(t, toolDBQuery, map[string]any{"target": "dev-pg", "sql": "SELECT 1"})
	if !isErr || out["code"] != "no_session" {
		t.Errorf("the dead session must be gone: %v", out)
	}
	if n := len(e.fake.opens()); n != 1 {
		t.Errorf("a dead password must not be tried again: %d attempts", n)
	}
}

// Target names are exact: "DEV-PG" is not "dev-pg", so a lookalike cannot reach a session by another spelling.
func TestTargetNamesAreExact(t *testing.T) {
	e := withDB(t, "dev-pg")
	for _, name := range []string{"DEV-PG", "Dev-Pg", " dev-pg", "dev-pg ", "dev-pg\n"} {
		out, isErr := e.call(t, toolDBQuery, map[string]any{"target": name, "sql": "SELECT 1"})
		if !isErr || out["code"] != "unknown_target" {
			t.Errorf("%q: %v", name, out)
		}
	}
	if len(e.fake.opens()) != 0 {
		t.Error("nothing is opened for a lookalike")
	}
}

// A target the owner gave no list of databases has nothing to choose from: the call needs no database, and the account
// decides what it can open. (It was refused as "database is required", so such a target could be logged in to but never
// used.)
func TestATargetWithoutADatabaseListNeedsNoDatabaseInTheCall(t *testing.T) {
	e := withDB(t, "dev-my-ddl")
	out, isErr := e.call(t, toolDBQuery, map[string]any{"target": "dev-my-ddl", "sql": "SELECT 1"})
	if isErr {
		t.Fatalf("%v", out)
	}
	if o := e.fake.opens(); len(o) != 1 || o[0].db != "" {
		t.Errorf("no database was named, so none is asked for: %+v", o)
	}
	out, isErr = e.call(t, toolDBQuery, map[string]any{"target": "dev-my-ddl", "database": "anything", "sql": "SELECT 1"})
	if isErr {
		t.Fatalf("a target that lists none accepts a name the account can open: %v", out)
	}
	if o := e.fake.opens(); len(o) != 2 || o[1].db != "anything" {
		t.Errorf("%+v", o)
	}
}
