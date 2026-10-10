// Command login is an MCP server that logs in to frequently used websites
// (with a human typing the credential via DingTalk) and returns their cookies/tokens.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/mcpserver"
	_ "github.com/LeafAI/login/internal/site/noauth"
)

func main() {
	cfgPath := flag.String("config", config.DefaultPath(), "config file")
	flag.Parse()
	log.SetOutput(os.Stderr) // stdout is the MCP transport

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := mcpserver.New(cfg).Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}
