package mcpserver

// Version is the server's version as reported to MCP clients. The binary overrides it at build time:
//
//	go build -ldflags "-X github.com/LeafAI/securl/internal/mcpserver.Version=1.2.3"
var Version = "0.1.0"
