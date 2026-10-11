package main

import (
	"os"

	"golang.org/x/term"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/vaultcli"
)

// runVault runs `securl vault ...`: making the vault, looking at it and changing its passphrase.
func runVault(args []string) int {
	path := config.DefaultPath()
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if (args[i] == "-config" || args[i] == "--config") && i+1 < len(args) {
			path = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	cfg, err := config.Load(path)
	if err != nil {
		os.Stderr.WriteString("securl vault: " + err.Error() + "\n")
		return 1
	}
	env := vaultcli.Env{Config: cfg, ConfigPath: path, Vault: vault.New(cfg.Vault.Dir), In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	env.ReadSecret = terminalSecret()
	return vaultcli.Run(rest, env)
}

// terminalSecret reads a line without echo when stdin is a terminal (nil otherwise: scripts pipe the passphrase in).
func terminalSecret() func() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	return func() (string, error) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		return string(b), err
	}
}
