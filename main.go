// Command login is an MCP server that logs in to frequently used websites (with a human typing
// the credential through a DingTalk-delivered link) and returns their cookies/tokens to an AI agent.
//
// Usage:
//
//	login [-config file]        serve MCP over stdio
//	login page [dir]            write the static login page (to open locally instead of GitHub Pages)
//	login doctor [-tunnel] [-send]  check the setup, try the tunnel providers, send a test DingTalk message
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

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/mcpserver"
	"github.com/LeafAI/login/internal/web"

	_ "github.com/LeafAI/login/internal/site/archery"
	_ "github.com/LeafAI/login/internal/site/gitlab"
	_ "github.com/LeafAI/login/internal/site/jenkins"
	_ "github.com/LeafAI/login/internal/site/kibana"
	_ "github.com/LeafAI/login/internal/site/kubesphere"
	_ "github.com/LeafAI/login/internal/site/nightingale"
	_ "github.com/LeafAI/login/internal/site/noauth"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "page" {
		dir := "login-page"
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
