package configcli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/configedit"
)

const dbUsage = "usage: securl config db add [flags] | list | remove <name>"

func cmdDB(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New(dbUsage)
	}
	switch args[0] {
	case "add":
		return dbAdd(env, args[1:])
	case "list":
		return dbList(env)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: securl config db remove <name>")
		}
		return dbRemove(env, args[1])
	}
	return fmt.Errorf("unknown db command %q (add, list, remove)", args[0])
}

// dbFlags are the answers that can be given instead of asked. There is no flag for an account of any kind: a database
// account is typed by a person on the login page and kept in the vault, never in a file or in a shell history.
type dbFlags struct {
	scripted                                              bool // any flag was given: what is missing and optional takes its default
	name, driver, host, environment, databases, mode, tls string
	port, maxRows, maxChanged                             int
	timeout                                               time.Duration
	allowDDL, yesWrites                                   bool
}

func parseDBFlags(args []string) (dbFlags, error) {
	var f dbFlags
	fs := flag.NewFlagSet("db add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.name, "name", "", "")
	fs.StringVar(&f.driver, "driver", "", "")
	fs.StringVar(&f.host, "host", "", "")
	fs.IntVar(&f.port, "port", 0, "")
	fs.StringVar(&f.environment, "environment", "", "")
	fs.StringVar(&f.databases, "databases", "", "")
	fs.StringVar(&f.mode, "mode", "", "")
	fs.StringVar(&f.tls, "tls", "", "")
	fs.IntVar(&f.maxRows, "max-rows", 0, "")
	fs.IntVar(&f.maxChanged, "max-changed-rows", 0, "")
	fs.DurationVar(&f.timeout, "statement-timeout", 0, "")
	fs.BoolVar(&f.allowDDL, "allow-ddl", false, "")
	fs.BoolVar(&f.yesWrites, "yes-allow-writes", false, "")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("%s (flags: --name --driver --host --port --environment --databases --mode --tls --max-rows --max-changed-rows --statement-timeout --allow-ddl --yes-allow-writes; a database account is never given here: a person types it when an agent opens a session)", flagProblem(err))
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(*flag.Flag) { f.scripted = true })
	return f, nil
}

// flagProblem names the flag without echoing the value that came with it.
func flagProblem(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "flag provided but not defined: "); i >= 0 {
		return "unknown flag " + strings.TrimSpace(msg[i+len("flag provided but not defined: "):])
	}
	return msg
}

func dbAdd(env Env, args []string) error {
	f, err := parseDBFlags(args)
	if err != nil {
		return err
	}
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	d, err := collectDatabase(p, f)
	if err != nil {
		return err
	}
	if err := confirmReplace(p, ed, d.Name); err != nil {
		return err
	}
	if err := ed.SetDatabase(d); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo account is needed here: a person types the database username and password when an agent asks.")
	p.Say("The agent opens it with session_open and url db://%s; session_close with that url forgets the account.", d.Name)
	if d.Writable() {
		p.Say("This target takes changes: give the account only the rights an agent should have there.")
	}
	return nil
}

// collectDatabase builds a target from the flags and asks for what is missing. Every answer is checked as it is given, with
// the check the configuration applies when it loads, so a mistake is found here and not when an agent runs.
func collectDatabase(p *Prompter, f dbFlags) (config.Database, error) {
	var d config.Database
	var err error
	if d.Name, err = textOr(p, f.name, "Name an agent will call it (letters, digits, . _ -)", "", true, checkName); err != nil {
		return d, err
	}
	if d.Driver, err = choiceOr(p, f.driver, "Which database?", []string{config.DriverPostgres, config.DriverMySQL}, config.DriverPostgres); err != nil {
		return d, err
	}
	if d.Host, err = textOr(p, f.host, "Host name or address (no port, no scheme)", "", true, checkHost); err != nil {
		return d, err
	}
	def := "5432"
	if d.Driver == config.DriverMySQL {
		def = "3306"
	}
	if d.Port, err = portOr(p, f.port, def, f.scripted); err != nil {
		return d, err
	}
	p.Say("Production databases are not offered: they stay on Archery, where a person approves each change.")
	if d.Environment, err = choiceOr(p, f.environment, "Which environment is it?", []string{"dev", "test", "staging"}, "dev"); err != nil {
		return d, err
	}
	dbs := f.databases
	if !f.scripted || dbs != "" {
		if dbs, err = textOr(p, f.databases, "Databases an agent may use, comma separated (Enter: any the account can open)", "", false, checkDatabases); err != nil {
			return d, err
		}
	}
	d.Databases = splitList(dbs)
	if f.scripted && f.mode == "" {
		d.Mode = config.ModeReadOnly
	} else if d.Mode, err = choiceOr(p, f.mode, "May the agent change data?", []string{config.ModeReadOnly, config.ModeReadWrite}, config.ModeReadOnly); err != nil {
		return d, err
	}
	if d.Mode == config.ModeReadWrite {
		if err := askWriteSettings(p, f, &d); err != nil {
			return d, err
		}
	} else if f.allowDDL || f.maxChanged != 0 {
		// A setting that cannot take effect is a mistake to report, not to drop in silence.
		return d, errors.New("--allow-ddl and --max-changed-rows belong to a read_write target: add --mode read_write --yes-allow-writes, or leave them out")
	}
	if f.scripted && f.tls == "" {
		d.TLS = ""
	} else if d.TLS, err = tlsOr(p, f.tls); err != nil {
		return d, err
	}
	d.MaxRows, d.StatementTimeout = f.maxRows, f.timeout
	return d, nil
}

// askWriteSettings is the part that only a read_write target has. Giving an agent the right to write is the one answer
// here that is a decision about risk, so it is confirmed, and a script has to say so with --yes-allow-writes.
func askWriteSettings(p *Prompter, f dbFlags, d *config.Database) error {
	if !f.yesWrites {
		if f.scripted {
			return errors.New("mode read_write lets an agent change data on this database: add --yes-allow-writes to say that is intended")
		}
		ok, err := p.Confirm("An agent will be able to change data on this database (the team is told afterwards, and a change touching too many rows is rolled back). Allow it?", false)
		if err != nil {
			return err
		}
		if !ok {
			return errCancelled
		}
	}
	d.AllowDDL = f.allowDDL
	if !f.allowDDL && !f.scripted {
		ok, err := p.Confirm("Also allow schema changes (CREATE, ALTER, DROP, TRUNCATE)?", false)
		if err != nil {
			return err
		}
		d.AllowDDL = ok
	}
	d.MaxChangedRows = f.maxChanged
	if f.maxChanged == 0 && !f.scripted {
		v, err := p.Ask("Most rows one change may touch before it is rolled back", "1000", positiveInt)
		if err != nil {
			return err
		}
		n, _ := strconv.Atoi(v)
		if n != 1000 {
			d.MaxChangedRows = n
		}
	}
	return nil
}

func checkName(v string) error {
	d := config.Database{Name: v, Driver: config.DriverPostgres, Host: "h.example", Port: 5432, Environment: "dev", Mode: config.ModeReadOnly}
	if err := validateOne(d); err != nil {
		return errors.New("use 1-64 letters, digits, '.', '_' or '-'")
	}
	return nil
}

func checkHost(v string) error {
	d := config.Database{Name: "x", Driver: config.DriverPostgres, Host: v, Port: 5432, Environment: "dev", Mode: config.ModeReadOnly}
	if err := validateOne(d); err != nil {
		return errors.New("give a host name or an address only, with no port, scheme or user")
	}
	return nil
}

func checkDatabases(v string) error {
	d := config.Database{Name: "x", Driver: config.DriverPostgres, Host: "h.example", Port: 5432, Environment: "dev", Mode: config.ModeReadOnly, Databases: splitList(v)}
	if err := validateOne(d); err != nil {
		return errors.New("plain database names, separated by commas")
	}
	return nil
}

// validateOne runs the configuration's own check on one target, so the questions and the file can never disagree.
func validateOne(d config.Database) error {
	c := &config.Config{Databases: []config.Database{d}}
	return c.Validate()
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func positiveInt(v string) error {
	if n, err := strconv.Atoi(v); err != nil || n < 1 {
		return errors.New("a whole number, 1 or more")
	}
	return nil
}

// textOr uses the flag's value when it was given (checked the same way), and asks otherwise.
func textOr(p *Prompter, given, label, def string, required bool, validate func(string) error) (string, error) {
	if given != "" {
		if validate != nil {
			if err := validate(given); err != nil {
				return "", fmt.Errorf("%s: %w", firstWord(label), err)
			}
		}
		return given, nil
	}
	if required {
		return p.Require(label, def, validate)
	}
	return p.Ask(label, def, validate)
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " ("); i > 0 {
		return strings.ToLower(s[:i])
	}
	return strings.ToLower(s)
}

func choiceOr(p *Prompter, given, label string, choices []string, def string) (string, error) {
	if given != "" {
		for _, c := range choices {
			if c == given {
				return c, nil
			}
		}
		return "", fmt.Errorf("%q is not one of %s", given, strings.Join(choices, ", "))
	}
	return p.Choose(label, choices, def)
}

func portOr(p *Prompter, given int, def string, scripted bool) (int, error) {
	if given != 0 {
		if given < 1 || given > 65535 {
			return 0, fmt.Errorf("port %d: use 1-65535", given)
		}
		return explicitPort(given, def), nil
	}
	if scripted {
		return 0, nil
	}
	v, err := p.Ask("Port", def, func(v string) error {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			return errors.New("a port between 1 and 65535")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(v)
	return explicitPort(n, def), nil
}

// explicitPort is 0 (not written) when the port is the driver's own, so the file says only what the owner chose.
func explicitPort(n int, def string) int {
	if strconv.Itoa(n) == def {
		return 0
	}
	return n
}

func tlsOr(p *Prompter, given string) (string, error) {
	choices := []string{config.TLSVerify, config.TLSSkipVerify, config.TLSDisable}
	if given == "" {
		p.Say("verify checks the server's certificate (recommended); skip-verify encrypts without checking who answers; disable sends everything in the clear.")
	}
	v, err := choiceOr(p, given, "How should the connection be protected?", choices, config.TLSVerify)
	if err != nil || v == config.TLSVerify {
		return "", err
	}
	return v, nil
}

// confirmReplace asks before a target with the same name is overwritten.
func confirmReplace(p *Prompter, ed *configedit.Editor, name string) error {
	have, err := ed.Databases()
	if err != nil {
		return err
	}
	for _, h := range have {
		if h.Name == name {
			ok, err := p.Confirm(fmt.Sprintf("A database named %q already exists. Replace it?", name), false)
			if err != nil {
				return err
			}
			if !ok {
				return errCancelled
			}
			return nil
		}
	}
	return nil
}

func dbList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	have, err := ed.Databases()
	if err != nil {
		return err
	}
	if len(have) == 0 {
		fmt.Fprintln(env.Out, "no database targets configured (add one with: securl config db add)")
		return nil
	}
	tw := tabwriter.NewWriter(env.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tENGINE\tENV\tMODE\tHOST\tDATABASES")
	for _, d := range have {
		mode := d.Mode
		if mode == "" {
			mode = config.ModeReadOnly
		}
		host := d.Host
		if d.Port != 0 {
			host += ":" + strconv.Itoa(d.Port)
		}
		dbs := strings.Join(d.Databases, ",")
		if dbs == "" {
			dbs = "(any)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.Name, d.Driver, d.Environment, mode, host, dbs)
	}
	return tw.Flush()
}

func dbRemove(env Env, name string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.RemoveDatabase(name) {
		return fmt.Errorf("no database target named %q (see: securl config db list)", name)
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "An account saved for it stays in the vault until it is closed: ask the agent to call session_close with url db://%s.\n", name)
	return nil
}
