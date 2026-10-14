package configcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guided questions, in order: name, engine, host, port, environment, databases, mode, tls. A read-only target stops
// there; a read_write one is asked for its limits and for DDL as well.
const guidedReadOnly = "gm-dev-pg\n1\npg.dev.corp.example\n\n1\nappdb\n1\n1\n"

func TestDBAddGuidedWritesAReadOnlyPostgresTarget(t *testing.T) {
	r := run(t, "", guidedReadOnly, "db", "add")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	if len(c.Databases) != 1 {
		t.Fatalf("%+v", c.Databases)
	}
	d := c.Databases[0]
	if d.Name != "gm-dev-pg" || d.Driver != "postgres" || d.Host != "pg.dev.corp.example" || d.Port != 5432 ||
		d.Environment != "dev" || d.Mode != "read_only" || len(d.Databases) != 1 || d.Databases[0] != "appdb" || d.TLSMode() != "verify" {
		t.Errorf("%+v", d)
	}
	raw, _ := os.ReadFile(r.path)
	if strings.Contains(string(raw), "port:") || strings.Contains(string(raw), "tls:") || strings.Contains(string(raw), "allow_ddl") || strings.Contains(string(raw), "mode:") {
		t.Errorf("defaults are not written, so the program can change them later:\n%s", raw)
	}
	if !strings.Contains(r.out, "session_open") || !strings.Contains(r.out, "db://gm-dev-pg") {
		t.Errorf("the output says how the account is given:\n%s", r.out)
	}
}

func TestDBAddNeverAsksForAnAccount(t *testing.T) {
	for name, tc := range map[string]struct {
		answers string
		args    []string
	}{
		"read only":  {guidedReadOnly, []string{"db", "add"}},
		"read write": {"m\n2\nmy.dev.corp.example\n\n2\nappdb\n2\ny\nn\n\n1\n", []string{"db", "add"}},
	} {
		r := run(t, "", tc.answers, tc.args...)
		if r.code != 0 {
			t.Fatalf("%s: %s\n%s", name, r.err, r.out)
		}
		// A question is a line that ends where the answer is typed: "label: " or "label [default]: ".
		for _, line := range strings.Split(r.out, "\n") {
			for _, q := range strings.Split(line, ": ") {
				l := strings.ToLower(q)
				if strings.Contains(l, "password") || strings.Contains(l, "username") || strings.Contains(l, "user name") || strings.Contains(l, "passphrase") {
					if !strings.Contains(l, "no account is needed") && !strings.Contains(l, "a person types") {
						t.Errorf("%s: a question asks for an account: %q", name, line)
					}
				}
			}
		}
	}
}

func TestDBAddEnvironmentOffersNoProduction(t *testing.T) {
	r := run(t, "", guidedReadOnly, "db", "add")
	if strings.Contains(strings.ToLower(r.out), "prod") && !strings.Contains(strings.ToLower(r.out), "not") {
		t.Errorf("production must not be offered:\n%s", r.out)
	}
	for _, env := range []string{"dev", "test", "staging"} {
		if !strings.Contains(r.out, env) {
			t.Errorf("%s should be offered:\n%s", env, r.out)
		}
	}
	// A typed "prod" is refused and the question asked again.
	r = run(t, "", "gm-dev-pg\n1\npg.dev.corp.example\n\nprod\n1\nappdb\n1\n1\n", "db", "add")
	if r.code != 0 {
		t.Fatalf("%s %s", r.err, r.out)
	}
	if d := load(t, r.path).Databases[0]; d.Environment != "dev" {
		t.Errorf("after a refused answer the default applies: %+v", d)
	}
}

func TestDBAddAsksAgainOnABadAnswer(t *testing.T) {
	// host with a port, then a good one; name with a space, then a good one
	r := run(t, "", "bad name\ngm-dev-pg\n1\npg.dev:5432\npg.dev.corp.example\n\n1\n\n1\n1\n", "db", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	if !strings.Contains(r.out, "!") {
		t.Errorf("a refused answer is explained:\n%s", r.out)
	}
	d := load(t, r.path).Databases[0]
	if d.Name != "gm-dev-pg" || d.Host != "pg.dev.corp.example" {
		t.Errorf("%+v", d)
	}
}

func TestDBAddReadWriteAsksForLimitsAndDDL(t *testing.T) {
	// name, engine mysql(2), host, port, env test(2), databases, mode read_write(2), confirm the write grant, ddl y,
	// max changed rows 25, tls
	r := run(t, "", "gm-dev-my\n2\nmy.dev.corp.example\n3307\n2\nappdb,other\n2\ny\ny\n25\n1\n", "db", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	d := load(t, r.path).Databases[0]
	if d.Driver != "mysql" || d.Port != 3307 || d.Environment != "test" || !d.Writable() || !d.AllowsDDL() || d.ChangedRowsLimit() != 25 ||
		len(d.Databases) != 2 || d.Databases[1] != "other" {
		t.Errorf("%+v", d)
	}
}

func TestDBAddReadWriteNeedsAnExplicitYes(t *testing.T) {
	r := run(t, "", "gm-dev-my\n2\nmy.dev.corp.example\n\n2\nappdb\n2\nn\n", "db", "add")
	if r.code == 0 {
		t.Fatalf("declining the write grant must stop the command:\n%s", r.out)
	}
	if _, err := os.Stat(r.path); err == nil {
		t.Error("nothing may be saved after a refusal")
	}
	if !strings.Contains(r.err, "nothing was changed") {
		t.Errorf("%s", r.err)
	}
}

func TestDBAddWithFlagsAsksNothingWhenEverythingIsGiven(t *testing.T) {
	r := run(t, "", "", "db", "add", "--name", "gm-dev-pg", "--driver", "postgres", "--host", "pg.dev.corp.example",
		"--environment", "dev", "--databases", "appdb,reports")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	d := load(t, r.path).Databases[0]
	if d.Name != "gm-dev-pg" || d.Mode != "read_only" || len(d.Databases) != 2 || d.Port != 5432 {
		t.Errorf("%+v", d)
	}
	if strings.Contains(r.out, "choice") || strings.Contains(r.out, "[y/N]") {
		t.Errorf("nothing was left to ask:\n%s", r.out)
	}
}

func TestDBAddWithFlagsReadWriteNeedsTheConfirmationFlag(t *testing.T) {
	args := []string{"db", "add", "--name", "m", "--driver", "mysql", "--host", "my.dev.corp.example", "--environment", "test", "--databases", "appdb", "--mode", "read_write"}
	r := run(t, "", "", args...)
	if r.code == 0 {
		t.Fatalf("a write grant without --yes-allow-writes must be refused:\n%s", r.out)
	}
	if !strings.Contains(r.err, "--yes-allow-writes") {
		t.Errorf("%s", r.err)
	}
	r = run(t, "", "", append(args, "--yes-allow-writes", "--allow-ddl", "--max-changed-rows", "40")...)
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	d := load(t, r.path).Databases[0]
	if !d.Writable() || !d.AllowsDDL() || d.ChangedRowsLimit() != 40 {
		t.Errorf("%+v", d)
	}
}

func TestDBAddWithFlagsRefusesWhatTheConfigurationRefuses(t *testing.T) {
	base := []string{"db", "add", "--name", "a", "--driver", "postgres", "--host", "db.corp.example", "--environment", "dev"}
	swap := func(flag, val string) []string {
		out := append([]string{}, base...)
		for i := range out {
			if out[i] == flag && i+1 < len(out) {
				out[i+1] = val
			}
		}
		return out
	}
	for name, args := range map[string][]string{
		"production":     swap("--environment", "prod"),
		"host and port":  swap("--host", "db.corp.example:5432"),
		"unknown engine": swap("--driver", "oracle"),
		"bad name":       swap("--name", "a b"),
		"ddl read only":  append(append([]string{}, base...), "--allow-ddl"),
		"bad mode":       append(append([]string{}, base...), "--mode", "admin"),
		"unknown flag":   append(append([]string{}, base...), "--password", "x"),
	} {
		r := run(t, "", "", args...)
		if r.code == 0 {
			t.Errorf("%s: must be refused", name)
		}
		if r.path != "" {
			if _, err := os.Stat(r.path); err == nil {
				t.Errorf("%s: nothing may be saved", name)
			}
		}
	}
}

func TestDBAddRefusesAnAccountOnTheCommandLine(t *testing.T) {
	for _, flag := range []string{"--password", "--user", "--username", "--passwd", "--dsn", "--url", "--connection-string"} {
		r := run(t, "", "", "db", "add", "--name", "a", "--driver", "postgres", "--host", "db.corp.example", "--environment", "dev", "--databases", "x", flag, "v")
		if r.code == 0 {
			t.Errorf("%s: an account must never be given here", flag)
		}
		if strings.Contains(r.err+r.out, "=v") {
			t.Errorf("%s: the value is echoed", flag)
		}
	}
}

func TestDBAddReplacesATargetWithTheSameNameAfterAsking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	if r := run(t, path, guidedReadOnly, "db", "add"); r.code != 0 {
		t.Fatal(r.err)
	}
	r := run(t, path, "y\n", "db", "add", "--name", "gm-dev-pg", "--driver", "postgres", "--host", "pg2.dev.corp.example", "--environment", "staging", "--databases", "appdb")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	c := load(t, path)
	if len(c.Databases) != 1 || c.Databases[0].Host != "pg2.dev.corp.example" || c.Databases[0].Environment != "staging" {
		t.Errorf("%+v", c.Databases)
	}
	// declining leaves the first one alone
	r = run(t, path, "n\n", "db", "add", "--name", "gm-dev-pg", "--driver", "postgres", "--host", "other.dev.corp.example", "--environment", "dev", "--databases", "appdb")
	if r.code == 0 {
		t.Errorf("declining must stop the command")
	}
	if c := load(t, path); c.Databases[0].Host != "pg2.dev.corp.example" {
		t.Errorf("a declined replacement changed the file: %+v", c.Databases)
	}
}

func TestDBListShowsTargetsWithoutAnythingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	run(t, path, guidedReadOnly, "db", "add")
	run(t, path, "", "db", "add", "--name", "m", "--driver", "mysql", "--host", "my.dev.corp.example", "--environment", "test", "--databases", "appdb", "--mode", "read_write", "--yes-allow-writes")
	r := run(t, path, "", "db", "list")
	if r.code != 0 {
		t.Fatalf("%s", r.err)
	}
	for _, want := range []string{"gm-dev-pg", "postgres", "dev", "read_only", "m", "mysql", "test", "read_write", "pg.dev.corp.example"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("list should show %q:\n%s", want, r.out)
		}
	}
	if r := run(t, filepath.Join(t.TempDir(), "x", "c.yaml"), "", "db", "list"); r.code != 0 || !strings.Contains(r.out, "no database") {
		t.Errorf("an empty list says so: %d %q", r.code, r.out)
	}
}

func TestDBRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	run(t, path, guidedReadOnly, "db", "add")
	r := run(t, path, "", "db", "remove", "gm-dev-pg")
	if r.code != 0 {
		t.Fatalf("%s", r.err)
	}
	if len(load(t, path).Databases) != 0 {
		t.Error("not removed")
	}
	if !strings.Contains(r.out, "session_close") {
		t.Errorf("the output says what to do about the saved account:\n%s", r.out)
	}
	if r := run(t, path, "", "db", "remove", "gm-dev-pg"); r.code == 0 {
		t.Error("removing a target that is not there is an error")
	}
	if r := run(t, path, "", "db", "remove"); r.code == 0 {
		t.Error("a name is required")
	}
}

func TestDBSubcommandsAreListedInTheHelp(t *testing.T) {
	r := run(t, "", "", "help")
	for _, want := range []string{"db add", "db list", "db remove"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("help should mention %q:\n%s", want, r.out)
		}
	}
	if r := run(t, "", "", "db"); r.code == 0 {
		t.Error("db needs a subcommand")
	}
	if r := run(t, "", "", "db", "nonsense"); r.code == 0 {
		t.Error("an unknown subcommand is an error")
	}
}

func TestDBAddKeepsOtherSettingsAndMakesABackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# mine\nmcp: {max_block_seconds: 30}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(t, path, guidedReadOnly, "db", "add"); r.code != 0 {
		t.Fatal(r.err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "# mine") || load(t, path).MCP.MaxBlockSeconds != 30 {
		t.Errorf("%s", raw)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("the previous file is kept: %v", err)
	}
}

// The port shown as the default must be the engine's own, and choosing it writes nothing.
func TestDBAddOffersTheEnginesOwnDefaultPort(t *testing.T) {
	for driver, tc := range map[string]struct{ choice, port string }{"postgres": {"1", "5432"}, "mysql": {"2", "3306"}} {
		r := run(t, "", "d\n"+tc.choice+"\ndb.dev.corp.example\n\n1\n\n1\n1\n", "db", "add")
		if r.code != 0 {
			t.Fatalf("%s: %s\n%s", driver, r.err, r.out)
		}
		if !strings.Contains(r.out, "Port ["+tc.port+"]") {
			t.Errorf("%s: the question should offer %s:\n%s", driver, tc.port, r.out)
		}
		d := load(t, r.path).Databases[0]
		if d.Driver != driver || d.Port != mustPort(driver) {
			t.Errorf("%s: %+v", driver, d)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "port:") {
			t.Errorf("%s: the default port is not written:\n%s", driver, raw)
		}
	}
}

func mustPort(driver string) int {
	if driver == "mysql" {
		return 3306
	}
	return 5432
}

// A host with a port in it is refused with the reason, whether it is typed or given as a flag.
func TestDBAddExplainsAHostThatCarriesAPort(t *testing.T) {
	r := run(t, "", "", "db", "add", "--name", "a", "--driver", "postgres", "--host", "db.corp.example:5432", "--environment", "dev")
	if r.code == 0 || !strings.Contains(r.err, "host") || !strings.Contains(r.err, "port") {
		t.Errorf("the refusal should say what is wrong with the host: %d %q", r.code, r.err)
	}
	if strings.Contains(r.err, "refusing to save") {
		t.Errorf("a flag the person typed is checked where it is read, so the message names it and not the file: %q", r.err)
	}
	r = run(t, "", "", "db", "add", "--name", "a", "--driver", "postgres", "--host", "db.corp.example", "--port", "70000", "--environment", "dev")
	if r.code == 0 || !strings.Contains(r.err, "port 70000") || strings.Contains(r.err, "refusing to save") {
		t.Errorf("a port out of range is reported where it is read: %d %q", r.code, r.err)
	}
}
