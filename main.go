// Command securl is an MCP server that sends authenticated HTTP requests to internal websites on behalf of an AI agent.
// A person types the credential once, through a DingTalk-delivered link; the credentials stay in an encrypted vault, are
// put into each request here, and are removed from the answer, so the agent never holds a cookie, a token or a password.
//
// Usage:
//
//	securl [-config file]        serve MCP over stdio
//	securl version               print the version
//	securl page [dir]            write the static login page (to open locally instead of GitHub Pages)
//	securl doctor [-tunnel] [-send]  check the setup, try the tunnel providers, send a test DingTalk message
//	securl config <command>      guided, validated editing of the config file (init, site add, set, show, ...)
//	securl vault <command>       make the vault that holds every secret (init), look at it (status), change its passphrase (passwd)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/web"

	_ "github.com/LeafAI/securl/internal/site/archery"
	_ "github.com/LeafAI/securl/internal/site/gitlab"
	_ "github.com/LeafAI/securl/internal/site/jenkins"
	_ "github.com/LeafAI/securl/internal/site/kibana"
	_ "github.com/LeafAI/securl/internal/site/kubesphere"
	_ "github.com/LeafAI/securl/internal/site/nightingale"
	_ "github.com/LeafAI/securl/internal/site/noauth"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "page" {
		dir := "securl-page"
		if len(os.Args) > 2 {
			dir = os.Args[2]
		}
		if err := web.WriteTo(dir); err != nil {
			log.Fatal(err)
		}
		abs, _ := filepath.Abs(dir)
		fmt.Println("SHA-256 of the page files (the hosted page publishes the same SHA256SUMS):")
		for _, line := range web.Checksums() {
			fmt.Println("  " + line)
		}
		fmt.Printf("wrote the login page to %s\nOpen %s/index.html in a browser, then paste the link from DingTalk\n"+
			"(or set web.page_url to file://%s/index.html so links point at this copy).\n", abs, abs, abs)
		return
	}

	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(versionLine())
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "config" {
		os.Exit(runConfig(os.Args[2:]))
	}

	if len(os.Args) > 1 && os.Args[1] == "vault" {
		os.Exit(runVault(os.Args[2:]))
	}

	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		os.Exit(runDoctor(os.Args[2:]))
	}

	cfgPath := flag.String("config", config.DefaultPath(), "config file")
	flag.Parse()
	log.SetOutput(os.Stderr) // stdout is the MCP transport

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{})
	if err != nil {
		log.Fatalf("setup: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = srv.Run(ctx, &mcp.StdioTransport{})
	app.Close() // tear down tunnels of pending logins
	if err != nil && ctx.Err() == nil {
		log.Fatalf("server: %v", err)
	}
}
