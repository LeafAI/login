package configcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/configedit"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

// A factor as the command line knows it: its name in the config, what people call it, and its key in the file.
type factor struct {
	key   string // "link" | "seal" (the argument people type)
	cfg   string // "link_totp" | "seal_totp" (the section of security:)
	label string // "unlock" | "sealing"
	use   string // what the code is for, for the output
}

var factors = []factor{
	{"link", "link_totp", "unlock", "opens the encrypted details of a login link in the page"},
	{"seal", "seal_totp", "sealing", "seals what you type in the page before it leaves the browser"},
}

func factorByKey(k string) (factor, bool) {
	for _, f := range factors {
		if f.key == k {
			return f, true
		}
	}
	return factor{}, false
}

// pick returns the factors named by args, or both when none is named.
func pick(args []string) ([]factor, error) {
	if len(args) == 0 {
		return factors, nil
	}
	var out []factor
	for _, a := range args {
		f, ok := factorByKey(a)
		if !ok {
			return nil, fmt.Errorf("unknown factor %q (link = the unlock code, seal = the sealing code)", a)
		}
		out = append(out, f)
	}
	return out, nil
}

func (env Env) now() time.Time {
	if env.Now != nil {
		return env.Now()
	}
	return time.Now()
}

const totpUsage = `usage: securl config totp <command>

  init [link|seal]    make the secret(s), show them to register in an authenticator, and switch the factor on
  code [link|seal]    print the current code(s), for an authenticator that cannot do the period
  status              show which factors are on and their settings (never a secret or a code)
  on  <link|seal>     switch a factor on again (its secret must exist)
  off <link|seal>     switch a factor off; its secret is kept, so your authenticator entry stays valid

link = the unlock factor: a long-period code (10 minutes by default, the longest 1Password supports) that opens the
encrypted details of a login link in the page. seal = the sealing factor: a 30 second code that seals what you type.`

func cmdTOTP(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New(totpUsage)
	}
	switch args[0] {
	case "init":
		return totpInit(env, args[1:])
	case "code":
		return totpCode(env, args[1:])
	case "status":
		return totpStatus(env)
	case "on":
		return totpSwitch(env, args[1:], true)
	case "off":
		return totpSwitch(env, args[1:], false)
	}
	return fmt.Errorf("unknown totp command %q\n\n%s", args[0], totpUsage)
}

func settingsOf(c *config.Config, f factor) config.TOTP {
	if f.key == "link" {
		return c.Security.LinkTOTP
	}
	return c.Security.SealTOTP
}

func loadConfig(env Env) (*configedit.Editor, *config.Config, error) {
	ed, err := openEditor(env)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := parseEditor(ed)
	if err != nil {
		return nil, nil, err
	}
	return ed, cfg, nil
}

// openVault returns the vault ready for use and a function that shuts it again. A vault that is locked is opened here:
// the key of a running server exists only in that process's memory, so a command line process opens its own copy by
// asking for the passphrase, and shuts it as soon as it is done. A vault that was never made is a different matter,
// with a different remedy, and is not prompted for.
func openVault(env Env) (*vault.Vault, func(), error) {
	noop := func() {}
	if env.Vault == nil {
		return nil, noop, errors.New("no vault is available")
	}
	switch env.Vault.State() {
	case vault.NotInitialized:
		return nil, noop, errors.New("the vault is not initialized: run `securl vault init` first; the TOTP secrets are kept in it")
	case vault.Locked:
		pass, err := askPassphrase(env)
		if err != nil {
			return nil, noop, err
		}
		if err := env.Vault.Unlock(pass); err != nil {
			return nil, noop, err
		}
		return env.Vault, env.Vault.Lock, nil
	}
	return env.Vault, noop, nil
}

// askPassphrase reads the vault passphrase exactly as typed (spaces may belong to it), without echo on a terminal.
func askPassphrase(env Env) (string, error) { return askPassphraseOn(&env) }

func askPassphraseOn(env *Env) (string, error) {
	fmt.Fprint(env.Out, "Vault passphrase: ")
	if env.ReadSecret != nil {
		s, err := env.ReadSecret()
		fmt.Fprintln(env.Out)
		return s, err
	}
	if env.passReader == nil {
		env.passReader = bufio.NewReader(env.In)
	}
	line, err := env.passReader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("the vault is locked and no passphrase could be read: run this in a terminal")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func entryOf(f factor) string { return "totp/" + f.key }

func hasEntry(v *vault.Vault, f factor) bool {
	_, err := v.Get(entryOf(f))
	return err == nil
}

func secretFrom(v *vault.Vault, f factor) ([]byte, error) {
	raw, err := v.Get(entryOf(f))
	if err != nil {
		return nil, err
	}
	return totp.ParseSecret(string(raw))
}

func totpInit(env Env, args []string) error {
	fs, err := pick(args)
	if err != nil {
		return err
	}
	v, shut, err := openVault(env)
	if err != nil {
		return err
	}
	defer shut()
	ed, cfg, err := loadConfig(env)
	if err != nil {
		return err
	}
	// Check everything first: a half-done init (one secret made, the other refused) would leave a state that is hard to
	// explain. Refuse before touching anything.
	for _, f := range fs {
		if hasEntry(v, f) {
			return fmt.Errorf("the %s secret already exists in the vault; refusing to replace a secret that may be registered in an authenticator (remove the entry from the vault yourself if you really want a new one)", f.label)
		}
	}
	account := accountName()
	for _, f := range fs {
		t := settingsOf(cfg, f)
		secret, err := totp.NewSecret()
		if err != nil {
			return err
		}
		// PutNew refuses to replace: another process could have made the secret since the check above.
		if err := v.PutNew(entryOf(f), []byte(totp.FormatSecret(secret))); err != nil {
			if errors.Is(err, vault.ErrExists) {
				return fmt.Errorf("the %s secret was made by someone else a moment ago; nothing was replaced", f.label)
			}
			return err
		}
		printSecret(env, f, t, secret, account)
		if err := ed.Set("security."+f.cfg+".enabled", "true"); err != nil {
			return err
		}
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintln(env.Out, "\nRegister each secret in your authenticator now (the secret is not shown again). Restart the securl process to apply.")
	return nil
}

func printSecret(env Env, f factor, t config.TOTP, secret []byte, account string) {
	fmt.Fprintf(env.Out, "\n== %s code (%s)\n", f.label, f.use)
	fmt.Fprintf(env.Out, "   period %s, %d digits, SHA-1\n", t.Period, t.Digits)
	fmt.Fprintf(env.Out, "   secret: %s\n", totp.FormatSecret(secret))
	fmt.Fprintf(env.Out, "   URI:    %s\n", totp.URI(secret, "login "+f.label, account, t.Period, t.Digits))
	if t.Period > 10*time.Minute {
		fmt.Fprintf(env.Out, "   note: many authenticators (1Password: at most 600 s) cannot do a period of %s; use `securl config totp code %s` instead\n", t.Period, f.key)
	}
}

func accountName() string {
	h, _ := os.Hostname()
	if u := os.Getenv("USER"); u != "" && h != "" {
		return u + "@" + h
	}
	if h != "" {
		return h
	}
	return "login"
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func totpCode(env Env, args []string) error {
	fs, err := pick(args)
	if err != nil {
		return err
	}
	v, shut, err := openVault(env)
	if err != nil {
		return err
	}
	defer shut()
	_, cfg, err := loadConfig(env)
	if err != nil {
		return err
	}
	now := env.now()
	shown := 0
	for _, f := range fs {
		t := settingsOf(cfg, f)
		if !t.Enabled && len(args) == 0 {
			continue // asked for everything: skip the factors that are off
		}
		secret, err := secretFrom(v, f)
		if err != nil {
			return fmt.Errorf("the %s factor: %w (run `securl config totp init %s`)", f.label, err, f.key)
		}
		secs := int64(t.Period / time.Second)
		left := time.Duration(secs-now.Unix()%secs) * time.Second
		fmt.Fprintf(env.Out, "%-8s %s   (valid for %s)\n", f.label, totp.Code(secret, now, t.Period, t.Digits), left.Round(time.Second))
		shown++
	}
	if shown == 0 {
		return errors.New("no factor is on; run `securl config totp init`")
	}
	return nil
}

func totpStatus(env Env) error {
	_, cfg, err := loadConfig(env)
	if err != nil {
		return err
	}
	state := vault.NotInitialized
	if env.Vault != nil {
		state = env.Vault.State()
	}
	for _, f := range factors {
		t := settingsOf(cfg, f)
		if !t.Enabled {
			fmt.Fprintf(env.Out, "%-8s off\n", f.label)
			continue
		}
		var note string
		switch state {
		case vault.Unlocked:
			note = "secret present"
			if _, err := secretFrom(env.Vault, f); err != nil {
				note = "SECRET MISSING IN THE VAULT: the server will not start (" + firstLine(err.Error()) + ")"
			}
		case vault.Locked:
			note = "the vault is locked, so the secret cannot be checked"
		default:
			note = "the vault is not initialized, so there is no secret: the server will not start"
		}
		fmt.Fprintf(env.Out, "%-8s on, period %s, %d digits, %s\n", f.label, t.Period, t.Digits, note)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func totpSwitch(env Env, args []string, on bool) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: securl config totp %s <link|seal>", map[bool]string{true: "on", false: "off"}[on])
	}
	f, ok := factorByKey(args[0])
	if !ok {
		return fmt.Errorf("unknown factor %q (link or seal)", args[0])
	}
	ed, _, err := loadConfig(env)
	if err != nil {
		return err
	}
	if on {
		v, shut, err := openVault(env)
		if err != nil {
			return fmt.Errorf("cannot switch the %s factor on: %w", f.label, err)
		}
		defer shut()
		if _, err := secretFrom(v, f); err != nil {
			return fmt.Errorf("cannot switch the %s factor on: %w (run `securl config totp init %s` first)", f.label, err, f.key)
		}
	}
	if err := ed.Set("security."+f.cfg+".enabled", fmt.Sprint(on)); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "the %s factor is %s\n", f.label, map[bool]string{true: "on", false: "off"}[on])
	return nil
}
