package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/configcli"
	"github.com/LeafAI/securl/internal/notify"
	"github.com/LeafAI/securl/internal/vault"
)

// runConfig runs `securl config ...`: guided, validated editing of the config file.
func runConfig(args []string) int {
	env := configcli.Env{
		Path: config.DefaultPath(),
		In:   os.Stdin, Out: os.Stdout, Err: os.Stderr,
		SendTest: sendTestMessage,
	}
	env.Vault = vaultFor(args, env.Path)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		env.ReadSecret = func() (string, error) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			return string(b), err
		}
	}
	return configcli.Run(args, env)
}

func sendTestMessage(webhook, secret, keyword string, mobiles []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d := &notify.DingTalk{Webhook: webhook, Secret: secret, Keyword: keyword, Mobiles: mobiles}
	return d.Markdown(ctx, "securl setup", "### securl setup\n\nThis is a test message from `securl config init`. No action needed.")
}

// vaultFor opens the handle on the vault that sits where the config file (given by -config, or the default) says.
func vaultFor(args []string, defaultPath string) *vault.Vault {
	path := defaultPath
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-config" || args[i] == "--config" {
			path = args[i+1]
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		cfg = &config.Config{}
		cfg.Vault.Dir = filepath.Join(filepath.Dir(path), "vault")
	}
	return vault.New(cfg.Vault.Dir)
}
