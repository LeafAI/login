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
	"strings"
	"time"

	"github.com/LeafAI/login/internal/audit"
	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/mcpserver"
	"github.com/LeafAI/login/internal/notify"
	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/tunnel"
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

	report(cfg.DingTalk.Webhook != "", "dingtalk webhook", map[bool]string{true: "configured", false: "missing: run `login config init` (or set dingtalk.webhook / LOGIN_DINGTALK_WEBHOOK)"}[cfg.DingTalk.Webhook != ""])
	if _, err := url.Parse(cfg.Web.PageURL); err != nil {
		report(false, "web.page_url", err.Error())
	} else {
		fmt.Printf("[note] login links point at %s\n", cfg.Web.PageURL)
	}
	if err := os.MkdirAll(cfg.Keys.Dir, 0o700); err != nil {
		report(false, "key directory", err.Error())
	} else {
		report(true, "key directory", cfg.Keys.Dir)
	}
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
	doctorGuards(cfg, report)
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
		err := d.Markdown(ctx, "login doctor", "### login doctor\n\nThis is a test message from `login doctor`. No action needed.")
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
	findings, err := in.Inspect(ctx, base, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		report(false, "inspect "+d.Name(), err.Error())
		return
	}
	for _, f := range findings {
		fmt.Println("[info] " + f)
	}
}

// doctorGuards reports the activity log and the limits that protect people from request floods.
func doctorGuards(cfg *config.Config, report func(bool, string, string)) {
	if cfg.Audit.On() {
		if l, err := audit.Open(cfg.Audit.File, nil); err != nil {
			report(false, "audit log", err.Error())
		} else if l != nil {
			report(true, "audit log", cfg.Audit.File)
		}
	} else {
		fmt.Println("[note] audit.enabled is false: nothing records who asked for which login")
	}
	l := cfg.Limits
	fmt.Printf("[note] people are asked at most %d times per site and %d overall per %s; a rejected site is paused for %s\n",
		l.PerSite, l.Total, l.Window, l.RejectCooldown)
}
