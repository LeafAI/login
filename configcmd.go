package main

import (
	"context"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/configcli"
	"github.com/LeafAI/securl/internal/notify"
)

// runConfig runs `login config ...`: guided, validated editing of the config file.
func runConfig(args []string) int {
	env := configcli.Env{
		Path: config.DefaultPath(),
		In:   os.Stdin, Out: os.Stdout, Err: os.Stderr,
		SendTest: sendTestMessage,
	}
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
	return d.Markdown(ctx, "login setup", "### login setup\n\nThis is a test message from `login config init`. No action needed.")
}
