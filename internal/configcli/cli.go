package configcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/configedit"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/generic"
	"github.com/LeafAI/securl/internal/vault"
)

// Env is everything `securl config` needs from its surroundings (injected so it can be tested).
type Env struct {
	Path       string // config file
	In         io.Reader
	Out, Err   io.Writer
	ReadSecret func() (string, error) // no-echo reader for secrets; nil reads a plain line
	// SendTest posts a test message through the DingTalk robot (nil: the wizard does not offer it).
	SendTest func(webhook, secret, keyword string, mobiles []string) error
	// Now is the clock (nil: the real one); tests fix it so that codes are predictable.
	Now func() time.Time
	// Vault holds the secrets (the TOTP secrets). Commands that need a secret refuse, with the command that cures it,
	// while it is not initialized or locked.
	Vault *vault.Vault

	passReader *bufio.Reader // a plain-line passphrase reader, shared by the prompts of one command
}

const usage = `usage: securl config <command> [-config file]

  init                       guided setup: DingTalk robot, then optional advanced settings
  site add [url]             guided setup of one website (driver, path prefix, driver-specific options)
  site custom                describe any other website's login form step by step (no YAML needed)
  site list                  show configured websites and the drivers that are available
  site remove <host|name>    forget a website's settings, or a custom site
  show                       print the configuration (secrets are masked)
  get <key>                  print one setting         (-reveal shows secrets)
  set [key [value]]          change one setting; without arguments lists every setting
  unset <key>                remove a setting (the default applies again)
  totp init|code|status|on|off  the two TOTP factors that protect the link and the credential (see: securl config totp)
  path                       print the config file location

Every change is checked before it is saved. The previous file is kept as config.yaml.bak and comments are preserved.`

// Run executes `securl config args...` and returns the process exit code.
func Run(args []string, env Env) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(env.Out, usage)
		return 0
	}
	args = extractConfigFlag(args, &env)
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "path":
		fmt.Fprintln(env.Out, env.Path)
	case "show":
		err = cmdShow(env)
	case "get":
		err = cmdGet(env, rest)
	case "set":
		err = cmdSet(env, rest)
	case "unset":
		err = cmdUnset(env, rest)
	case "init":
		err = cmdInit(env)
	case "site":
		err = cmdSite(env, rest)
	case "totp":
		err = cmdTOTP(env, rest)
	default:
		fmt.Fprintf(env.Err, "securl config: unknown command %q\n\n%s\n", cmd, usage)
		return 2
	}
	return report(env, err)
}

func report(env Env, err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrNoInput):
		fmt.Fprintln(env.Err, "securl config: input ended before all questions were answered; run it in a terminal, or use `securl config set <key> <value>`")
	case errors.Is(err, errCancelled):
		fmt.Fprintln(env.Err, "securl config: cancelled, nothing was changed")
	default:
		fmt.Fprintf(env.Err, "securl config: %v\n", err)
	}
	return 1
}

var errCancelled = errors.New("cancelled")

// extractConfigFlag lets -config appear anywhere, so `securl config set a b -config x` works.
func extractConfigFlag(args []string, env *Env) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "-config" || args[i] == "--config") && i+1 < len(args):
			env.Path = args[i+1]
			i++
		case strings.HasPrefix(args[i], "-config="):
			env.Path = strings.TrimPrefix(args[i], "-config=")
		default:
			out = append(out, args[i])
		}
	}
	if len(out) == 0 {
		return []string{"help"}
	}
	return out
}

func prompter(env Env) *Prompter { return NewPrompter(env.In, env.Out, env.ReadSecret) }

// commit checks the edited configuration the way the server will use it, then saves it.
func commit(env Env, ed *configedit.Editor) error {
	if err := semanticCheck(ed); err != nil {
		return err
	}
	if err := ed.Save(); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "saved %s\n", ed.Path())
	return nil
}

// semanticCheck reuses the server's own start-up validation so mistakes surface now, not when an agent runs.
func semanticCheck(ed *configedit.Editor) error {
	cfg, err := parseEditor(ed)
	if err != nil {
		return err
	}
	if err := registerSites(cfg); err != nil {
		return err
	}
	if _, err := mcpserver.Providers(cfg); err != nil {
		return err
	}
	if err := mcpserver.ApplySiteOptions(cfg); err != nil {
		return err
	}
	for driver, opts := range cfg.SiteOptions {
		for k, v := range opts {
			o, ok := site.OptionOf(driver, k)
			if !ok {
				return fmt.Errorf("site_options.%s.%s: unknown option (known: %s)", driver, k, optionKeys(driver))
			}
			if err := o.Validate(v); err != nil {
				return fmt.Errorf("site_options.%s: %w", driver, err)
			}
		}
	}
	known := map[string]bool{}
	for _, n := range site.Names() {
		known[n] = true
	}
	for host, name := range cfg.Aliases {
		if !known[name] {
			return fmt.Errorf("aliases.%s: unknown driver %q (available: %s)", host, name, strings.Join(site.Names(), ", "))
		}
	}
	return nil
}

func optionKeys(driver string) string {
	var keys []string
	for _, o := range site.OptionsOf(driver) {
		keys = append(keys, o.Key)
	}
	if len(keys) == 0 {
		return "none; this driver takes no options"
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func parseEditor(ed *configedit.Editor) (*config.Config, error) {
	b, err := ed.Bytes()
	if err != nil {
		return nil, err
	}
	dir := ed.Path()
	if i := strings.LastIndexAny(dir, `/\`); i >= 0 {
		dir = dir[:i]
	} else {
		dir = "."
	}
	return config.Parse(b, dir)
}

// registerSites makes the configured custom sites resolvable (as the server does at start-up).
func registerSites(cfg *config.Config) error {
	for _, spec := range cfg.Sites {
		d, err := generic.New(spec)
		if err != nil {
			return err
		}
		site.Replace(d)
	}
	return nil
}

func openEditor(env Env) (*configedit.Editor, error) { return configedit.Open(env.Path) }

func cmdShow(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if !ed.Exists() {
		fmt.Fprintf(env.Out, "# no config file at %s yet (defaults and environment variables are in effect)\n# run `securl config init` to create one\n", env.Path)
		return nil
	}
	b, err := ed.Redacted()
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "# %s (secrets masked)\n%s", env.Path, b)
	return nil
}

func cmdGet(env Env, args []string) error {
	reveal := false
	var keys []string
	for _, a := range args {
		if a == "-reveal" || a == "--reveal" {
			reveal = true
		} else {
			keys = append(keys, a)
		}
	}
	if len(keys) != 1 {
		return errors.New("usage: securl config get [-reveal] <key>")
	}
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	v, ok, err := ed.Get(keys[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s is not set", keys[0])
	}
	if configedit.IsSecret(keys[0]) && !reveal {
		v = configedit.Mask(v)
	}
	fmt.Fprintln(env.Out, v)
	return nil
}

func cmdSet(env Env, args []string) error {
	if len(args) == 0 {
		listSettings(env)
		return nil
	}
	key := args[0]
	value := strings.Join(args[1:], " ")
	if len(args) > 1 && configedit.IsSecret(key) {
		fmt.Fprintf(env.Err, "note: a secret typed on the command line stays in your shell history; next time run `securl config set %s` and it is asked without echo\n", key)
	}
	if len(args) == 1 {
		if !configedit.IsSecret(key) {
			return fmt.Errorf("usage: securl config set %s <value>", key)
		}
		var err error // secrets are asked for, so they never land in shell history
		if value, err = prompter(env).Secret(key, false); err != nil {
			return err
		}
		if value == "" {
			return errors.New("no value given")
		}
	}
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if err := ed.Set(key, value); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "%s updated\n", key)
	return nil
}

func cmdUnset(env Env, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: securl config unset <key>")
	}
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	ok, err := ed.Unset(args[0])
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(env.Out, "%s was not set; nothing to do\n", args[0])
		return nil
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "%s removed\n", args[0])
	return nil
}

func listSettings(env Env) {
	fmt.Fprintln(env.Out, "settings (securl config set <key> <value>); lists take comma-separated values, durations look like 30s / 10m / 24h:")
	for _, s := range configedit.Settings() {
		fmt.Fprintf(env.Out, "  %-44s %s\n", s.Path, s.Type)
	}
	fmt.Fprintln(env.Out, "\nwebsites are easier with `securl config site add` and `securl config site custom`.")
}
