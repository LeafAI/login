// Package vaultcli implements `securl vault`: making the vault, looking at its state and changing its passphrase.
//
// There is deliberately no `unlock` or `lock` here. The vault's key lives only in the memory of the process that
// opened it, so a command-line process can only ever open its own copy; a running server is opened remotely, by the
// person typing the passphrase on the page that a DingTalk link leads to (the vault_unlock tool).
package vaultcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/migrate"
	"github.com/LeafAI/securl/internal/vault"
)

// Env is everything the commands need from their surroundings.
type Env struct {
	Config     *config.Config
	ConfigPath string
	Vault      *vault.Vault
	In         io.Reader
	Out, Err   io.Writer
	// ReadSecret reads one line without echo (a terminal). Nil reads a plain line from In, which is what scripts and
	// tests do.
	ReadSecret func() (string, error)

	reader *bufio.Reader
}

const maxAttempts = 3

const usage = `usage: securl vault <command>

  init      make the vault: choose a passphrase of at least 16 characters; anything an earlier version kept in files
            (TOTP secrets, stored logins) is moved into it
  status    say whether the vault exists and is open (never asks for the passphrase)
  passwd    change the passphrase
  migrate   move anything an earlier version left in files into the vault (init does this once; run it again if more turns up)

A running securl server starts locked. It is opened from your chat: the agent calls vault_unlock, you get a DingTalk
link, and you type the passphrase on that page. There is no command that opens a running server.`

// Run executes one command and returns the exit code.
func Run(args []string, env Env) int {
	if len(args) == 0 {
		fmt.Fprintln(env.Err, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "init":
		err = cmdInit(&env)
	case "status":
		err = cmdStatus(&env)
	case "passwd":
		err = cmdPasswd(&env)
	case "migrate":
		err = cmdMigrate(&env)
	case "unlock", "lock":
		err = fmt.Errorf("there is no `securl vault %s`: the key of the vault exists only in the memory of the process that opened it, so this command could not open a running server.\nA running server is opened remotely: the agent calls vault_unlock, you receive a DingTalk link and type the passphrase on its page", args[0])
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
	if err != nil {
		fmt.Fprintf(env.Err, "securl vault: %v\n", err)
		return 1
	}
	return 0
}

// passphrase reads one passphrase exactly as typed: only the line ending is removed, because spaces may be part of it.
func (e *Env) passphrase(label string) (string, error) {
	fmt.Fprintf(e.Out, "%s: ", label)
	if e.ReadSecret != nil {
		s, err := e.ReadSecret()
		fmt.Fprintln(e.Out)
		return s, err
	}
	if e.reader == nil {
		e.reader = bufio.NewReader(e.In)
	}
	line, err := e.reader.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("no more input: run this in a terminal")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// newPassphrase asks for a passphrase and its confirmation until they agree and pass the rules.
func (e *Env) newPassphrase(label string) (string, error) {
	var last error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		first, err := e.passphrase(label)
		if err != nil {
			return "", err
		}
		if err := vault.CheckPassphrase(first); err != nil {
			fmt.Fprintf(e.Err, "  ! %v\n", err)
			last = err
			continue
		}
		again, err := e.passphrase("Repeat it")
		if err != nil {
			return "", err
		}
		if again != first {
			fmt.Fprintln(e.Err, "  ! the two entries differ")
			last = errors.New("the two entries differ")
			continue
		}
		return first, nil
	}
	return "", fmt.Errorf("giving up after %d attempts: %w", maxAttempts, last)
}

func cmdInit(e *Env) error {
	if e.Vault.State() != vault.NotInitialized {
		return errors.New("the vault is already initialized: `securl vault passwd` changes its passphrase; a vault is never replaced")
	}
	fmt.Fprintf(e.Out, "The vault holds every secret login keeps. Its passphrase is asked for again whenever the server starts, so choose one\nyou can type; it cannot be recovered. At least %d characters; a sentence of several words is a good choice.\n\n", vault.MinPassphraseRunes)
	pass, err := e.newPassphrase("New vault passphrase")
	if err != nil {
		return err
	}
	if err := e.Vault.Init(pass); err != nil {
		return err
	}
	defer e.Vault.Lock() // this process ends here; a server has to be opened by its own passphrase
	rep, err := migrate.Run(e.Vault, e.migratePaths())
	if err != nil {
		return fmt.Errorf("the vault was made, but moving the old files into it failed: %w", err)
	}
	fmt.Fprintf(e.Out, "\nthe vault is ready at %s\n", e.Config.Vault.Dir)
	if rep.Total() > 0 || len(rep.Conflicts)+len(rep.Skipped)+len(rep.Exposed) > 0 {
		fmt.Fprint(e.Out, rep.String())
	}
	return nil
}

func cmdMigrate(e *Env) error {
	if e.Vault.State() == vault.NotInitialized {
		return errors.New("there is no vault yet: run `securl vault init`, which also moves the old files in")
	}
	pass, err := e.passphrase("Vault passphrase")
	if err != nil {
		return err
	}
	if err := e.Vault.Unlock(pass); err != nil {
		return err
	}
	defer e.Vault.Lock()
	rep, err := migrate.Run(e.Vault, e.migratePaths())
	if err != nil {
		return err
	}
	if rep.Total() == 0 && len(rep.Conflicts)+len(rep.Skipped)+len(rep.Exposed) == 0 {
		fmt.Fprintln(e.Out, "nothing to move: no secrets are left in files")
		return nil
	}
	fmt.Fprint(e.Out, rep.String())
	return nil
}

func (e *Env) migratePaths() migrate.Paths {
	return migrate.Paths{
		LinkSecret:  e.Config.Security.LinkTOTP.SecretFile,
		SealSecret:  e.Config.Security.SealTOTP.SecretFile,
		SessionsDir: e.Config.Sessions.Dir,
		KeysDir:     e.Config.Keys.Dir,
	}
}

func cmdStatus(e *Env) error {
	switch e.Vault.State() {
	case vault.NotInitialized:
		fmt.Fprintln(e.Out, "vault: not initialized (run `securl vault init`)")
	case vault.Locked:
		fmt.Fprintln(e.Out, "vault: locked (a running server is opened with the vault_unlock tool)")
	case vault.Unlocked:
		fmt.Fprintln(e.Out, "vault: unlocked")
	}
	fmt.Fprintf(e.Out, "location: %s\n", e.Config.Vault.Dir)
	return nil
}

func cmdPasswd(e *Env) error {
	if e.Vault.State() == vault.NotInitialized {
		return errors.New("there is no vault yet: run `securl vault init`")
	}
	old, err := e.passphrase("Current vault passphrase")
	if err != nil {
		return err
	}
	if err := e.Vault.Unlock(old); err != nil {
		return err
	}
	defer e.Vault.Lock()
	next, err := e.newPassphrase("New vault passphrase")
	if err != nil {
		return err
	}
	if err := e.Vault.Change(old, next); err != nil {
		return err
	}
	fmt.Fprintln(e.Out, "the passphrase was changed; running servers keep working until they restart, then need the new one")
	return nil
}
