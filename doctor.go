package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/netguard"
	"github.com/LeafAI/securl/internal/notify"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/tunnel"
	"github.com/LeafAI/securl/internal/vault"
)

// runDoctor checks the local setup. Flags: -config, -tunnel (really start each tunnel provider),
// -send (post a test message to DingTalk).
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file")
	doTunnel := fs.Bool("tunnel", false, "start each configured tunnel provider and fetch a page through it")
	doSend := fs.Bool("send", false, "send a test message through the DingTalk robot")
	siteURL := fs.String("site", "", "inspect a site (no credentials): picks the driver like the tools do and reports what it will do")
	siteName := fs.String("site-name", "", "driver to use with -site (default: from aliases / the host name)")
	fs.Parse(args)

	bad := 0
	report := func(ok bool, what, detail string) {
		mark := "ok  "
		if !ok {
			mark, bad = "FAIL", bad+1
		}
		fmt.Printf("[%s] %s", mark, what)
		if detail != "" {
			fmt.Printf(": %s", detail)
		}
		fmt.Println()
	}

	_, statErr := os.Stat(*cfgPath)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		report(false, "config", err.Error())
		return 1
	}
	if statErr != nil {
		fmt.Printf("[note] no config file at %s (defaults + environment are used)\n", *cfgPath)
	} else {
		report(true, "config", *cfgPath)
	}

	report(cfg.DingTalk.Webhook != "", "dingtalk webhook", map[bool]string{true: "configured", false: "missing: run `securl config init` (or set dingtalk.webhook / SECURL_DINGTALK_WEBHOOK)"}[cfg.DingTalk.Webhook != ""])
	if _, err := url.Parse(cfg.Web.PageURL); err != nil {
		report(false, "web.page_url", err.Error())
	} else {
		fmt.Printf("[note] login links point at %s\n", cfg.Web.PageURL)
	}
	vstate := doctorVault(cfg, report)
	doctorLegacyFiles(cfg, report)
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		report(false, "ssh client", "not found in PATH; tunnels cannot start")
	} else {
		report(true, "ssh client", ssh)
	}
	providers, err := mcpserver.Providers(cfg)
	if err != nil {
		report(false, "tunnel providers", err.Error())
	} else {
		var names []string
		for _, p := range providers {
			names = append(names, p.Name)
		}
		report(true, "tunnel providers", strings.Join(names, ", "))
	}
	doctorGuards(cfg, vstate, report)
	if !cfg.Archery.DDLAllowed() {
		fmt.Println("[note] archery.allow_ddl is false: DDL will be refused")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if *doTunnel && providers != nil && ssh != "" {
		doctorTunnels(ctx, cfg, providers, report)
	}
	if *siteURL != "" {
		doctorSite(ctx, cfg, *siteURL, *siteName, report)
	}
	if *doSend {
		d := &notify.DingTalk{Webhook: cfg.DingTalk.Webhook, Secret: cfg.DingTalk.Secret, Keyword: cfg.DingTalk.Keyword, Mobiles: cfg.DingTalk.Mobiles}
		err := d.Markdown(ctx, "securl doctor", "### securl doctor\n\nThis is a test message from `securl doctor`. No action needed.")
		if err != nil {
			report(false, "dingtalk test message", err.Error())
		} else {
			report(true, "dingtalk test message", "sent; check the chat")
		}
	}
	if !*doTunnel || !*doSend || *siteURL == "" {
		fmt.Println("[note] add -tunnel to test the tunnel providers, -send to test DingTalk, -site <url> to inspect a site")
	}
	if bad > 0 {
		return 1
	}
	return 0
}

func doctorTunnels(ctx context.Context, cfg *config.Config, providers []*tunnel.Provider, report func(bool, string, string)) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "login-doctor") }))
	defer local.Close()
	u, _ := url.Parse(local.URL)
	var port int
	fmt.Sscanf(u.Port(), "%d", &port)
	r := &tunnel.Runner{Timeout: cfg.Tunnel.Timeout}
	for _, p := range providers {
		if p.Kind != tunnel.HTTP {
			fmt.Printf("[note] tunnel %s is TCP-only and is skipped\n", p.Name)
			continue
		}
		start := time.Now()
		tn, err := r.Start(ctx, []*tunnel.Provider{p}, port)
		if err != nil {
			report(false, "tunnel "+p.Name, err.Error())
			continue
		}
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(tn.URL)
		if err != nil {
			report(false, "tunnel "+p.Name, tn.URL+" came up but fetching it failed: "+err.Error())
		} else {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
			resp.Body.Close()
			report(strings.Contains(string(b), "login-doctor"), "tunnel "+p.Name, fmt.Sprintf("%s (%s)", tn.URL, time.Since(start).Round(100*time.Millisecond)))
		}
		tn.Close()
	}
}

// doctorSite resolves a site like the login tools do and asks its driver what it will do (no credentials).
func doctorSite(ctx context.Context, cfg *config.Config, rawURL, name string, report func(bool, string, string)) {
	if err := mcpserver.ApplySiteOptions(cfg); err != nil {
		report(false, "site_options", err.Error())
		return
	}
	d, base, err := mcpserver.Resolve(cfg, rawURL, name)
	if err != nil {
		report(false, "site "+rawURL, err.Error())
		return
	}
	report(true, "site "+rawURL, fmt.Sprintf("driver %q, base URL %s", d.Name(), base))
	if !d.NeedsLogin() {
		fmt.Println("[note] this driver needs no login; the tool only checks that the URL answers")
	}
	in, ok := d.(site.Inspector)
	if !ok {
		fmt.Printf("[note] driver %q cannot inspect a server without logging in\n", d.Name())
		return
	}
	findings, err := in.Inspect(ctx, base, netguard.New(netguard.Policy{AllowLocal: cfg.Security.AllowLocalAddresses, AllowedHosts: cfg.Security.AllowedHosts}))
	if err != nil {
		report(false, "inspect "+d.Name(), err.Error())
		return
	}
	for _, f := range findings {
		fmt.Println("[info] " + f)
	}
}

// doctorGuards reports the activity log and the limits that protect people from request floods.
func doctorGuards(cfg *config.Config, vstate vault.State, report func(bool, string, string)) {
	if cfg.Audit.On() {
		if l, err := audit.Open(cfg.Audit.File, nil); err != nil {
			report(false, "audit log", err.Error())
		} else if l != nil {
			report(true, "audit log", cfg.Audit.File)
		}
	} else {
		fmt.Println("[note] audit.enabled is false: nothing records who asked for which login")
	}
	doctorFactors(cfg, vstate, report)
	l := cfg.Limits
	fmt.Printf("[note] people are asked at most %d times per site and %d overall per %s; a rejected site is paused for %s\n",
		l.PerSite, l.Total, l.Window, l.RejectCooldown)
}

// doctorVault reports the vault. A shut vault is the normal state of a server that has not been opened, so it is not a
// failure; a vault that was never made is, because nothing that needs a secret can work. doctor never asks for the
// passphrase: it only reports.
func doctorVault(cfg *config.Config, report func(bool, string, string)) vault.State {
	state := vault.New(cfg.Vault.Dir).State()
	switch state {
	case vault.NotInitialized:
		report(false, "vault", "not initialized: run `securl vault init` (every secret login keeps lives in the vault, and a server cannot log in to anything without it)")
	case vault.Locked:
		report(true, "vault", "locked at "+cfg.Vault.Dir+" (normal: a running server is opened with the vault_unlock tool)")
	default:
		report(true, "vault", "unlocked at "+cfg.Vault.Dir)
	}
	return state
}

// doctorLegacyFiles warns about secrets that an earlier version left in plain files. They are what the vault replaces,
// so finding them is a failure with one remedy. Nothing about their content is shown.
func doctorLegacyFiles(cfg *config.Config, report func(bool, string, string)) {
	var found []string
	for _, p := range []string{cfg.Security.LinkTOTP.SecretFile, cfg.Security.SealTOTP.SecretFile} {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	for _, name := range []string{"sessions.enc", "sessions.key"} {
		if p := filepath.Join(cfg.Sessions.Dir, name); fileThere(p) {
			found = append(found, p)
		}
	}
	if ents, err := os.ReadDir(cfg.Keys.Dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".asc")) {
				found = append(found, filepath.Join(cfg.Keys.Dir, e.Name()))
			}
		}
	}
	if len(found) > 0 {
		report(false, "plaintext secrets", fmt.Sprintf("%d file(s) from an earlier version hold secrets outside the vault (%s ...): run `securl vault init` (or `securl vault migrate` on an existing vault) to move them in and remove the files", len(found), found[0]))
	}
}

func fileThere(p string) bool { _, err := os.Stat(p); return err == nil }

// doctorFactors checks the two TOTP factors. A factor that is on can only start if the vault will hold its secret, so a
// vault that does not exist is a failure here. With the vault shut the secret cannot be checked, which says nothing
// against the setup, and is reported as a note.
func doctorFactors(cfg *config.Config, state vault.State, report func(bool, string, string)) {
	if err := cfg.Validate(); err != nil {
		report(false, "security factors", err.Error())
		return
	}
	for _, f := range []struct {
		name string
		t    config.TOTP
		hint string
	}{
		{"unlock factor", cfg.Security.LinkTOTP, "link"},
		{"sealing factor", cfg.Security.SealTOTP, "seal"},
	} {
		if !f.t.Enabled {
			fmt.Printf("[note] %s: off (enable it with `securl config totp init %s`)\n", f.name, f.hint)
			continue
		}
		switch state {
		case vault.NotInitialized:
			report(false, f.name, "on, but there is no vault to hold its secret, so the server cannot start (run `securl vault init`, then `securl config totp init "+f.hint+"`)")
		case vault.Locked:
			fmt.Printf("[note] %s: on, period %s, %d digits; the vault is locked, so its secret was not checked\n", f.name, f.t.Period, f.t.Digits)
		default:
			report(true, f.name, fmt.Sprintf("on, period %s, %d digits", f.t.Period, f.t.Digits))
		}
	}
}
