package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T, s *Server, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "proto-test", Version: "9"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func protoServer(t *testing.T) (*mcp.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	srv, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	return srv, s
}

func TestEveryToolHasTitleAndOutputSchema(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 12 {
		t.Fatalf("%d tools, want 12", len(res.Tools))
	}
	for _, tl := range res.Tools {
		if tl.Title == "" || tl.Title == tl.Name {
			t.Errorf("%s: needs a human-readable title, got %q", tl.Name, tl.Title)
		}
		m, ok := tl.OutputSchema.(map[string]any)
		if !ok || m["type"] != "object" || m["properties"] == nil {
			t.Errorf("%s: output schema = %v", tl.Name, tl.OutputSchema)
		}
		if tl.InputSchema == nil || tl.Description == "" {
			t.Errorf("%s: missing input schema or description", tl.Name)
		}
	}
}

// validate checks the tool's real structured answer against the schema the server advertised.
func validate(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any, wantErr bool) {
	t.Helper()
	ctx := context.Background()
	tools, _ := cs.ListTools(ctx, nil)
	var schemaRaw any
	for _, tl := range tools.Tools {
		if tl.Name == tool {
			schemaRaw = tl.OutputSchema
		}
	}
	b, _ := json.Marshal(schemaRaw)
	var sch jsonschema.Schema
	if err := json.Unmarshal(b, &sch); err != nil {
		t.Fatal(err)
	}
	resolved, err := sch.Resolve(nil)
	if err != nil {
		t.Fatalf("%s: schema does not resolve: %v", tool, err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError != wantErr {
		t.Fatalf("%s: isError=%v want %v: %v", tool, res.IsError, wantErr, res.Content)
	}
	if wantErr {
		return
	}
	var v any
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if err := resolved.Validate(v); err != nil {
		t.Errorf("%s: real result violates its advertised output schema: %v\n%s", tool, err, raw)
	}
}

func TestRealResultsMatchTheirOutputSchemas(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	validate(t, cs, "login_sites", map[string]any{}, false)
	validate(t, cs, "login_sessions", map[string]any{}, false)
	validate(t, cs, "login", map[string]any{"url": ts.URL, "site": "skywalking"}, false) // ok with headers/tokens maps
	validate(t, cs, "logout", map[string]any{"all": true}, false)
	// a pending login seen through an Archery tool, via the union types
	for _, v := range []any{
		ArcheryStatusOrPending{Phase: "login", LoginID: "lg_1", NextTool: "login_wait"},
		ArcheryCancelOrPending{CancelOutput: CancelOutput{Status: "aborted"}},
		pendingLogin(&LoginOutput{LoginID: "lg_1"}),
		QueryOutput{Login: &LoginOutput{Status: "pending", LoginID: "lg_2"}},
	} {
		sch, err := outputSchema(reflectTypeOf(v))
		if err != nil {
			t.Fatal(err)
		}
		res, _ := sch.Resolve(nil)
		raw, _ := json.Marshal(v)
		var anyV any
		json.Unmarshal(raw, &anyV)
		if err := res.Validate(anyV); err != nil {
			t.Errorf("%T: %v\n%s", v, err, raw)
		}
	}
}

func TestResourcesExposeSitesSessionsAndPolicyWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	cfg.DingTalk.Webhook = "https://oapi.dingtalk.com/robot/send?access_token=SUPERSECRETTOKEN"
	cfg.DingTalk.Secret = "SECshouldnotleak"
	cfg.Security.AllowedHosts = []string{"*.corp.example"}
	srv, s, err := New(cfg, Options{Notifier: quiet{}, Tunnels: noTunnels{}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	cs := connect(t, s, srv)
	ctx := context.Background()
	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range list.Resources {
		got[r.URI] = true
		if r.MIMEType != "application/json" || r.Description == "" || r.Title == "" {
			t.Errorf("resource %s lacks metadata: %+v", r.URI, r)
		}
	}
	for _, u := range []string{"login://sites", "login://sessions", "login://policy"} {
		if !got[u] {
			t.Errorf("resource %s not listed (have %v)", u, got)
		}
	}
	read := func(uri string) string {
		r, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		return r.Contents[0].Text
	}
	var pol Policy
	if err := json.Unmarshal([]byte(read("login://policy")), &pol); err != nil {
		t.Fatal(err)
	}
	if len(pol.AllowedHosts) != 1 || pol.AllowedHosts[0] != "*.corp.example" || pol.Limits.PerSite != 6 || !pol.DDLAllowed || !pol.AuditEnabled || pol.MaxBlockSeconds != 50 {
		t.Errorf("policy = %+v", pol)
	}
	for _, uri := range []string{"login://policy", "login://sites", "login://sessions"} {
		txt := read(uri)
		for _, leak := range []string{"SUPERSECRETTOKEN", "SECshouldnotleak", "access_token"} {
			if strings.Contains(txt, leak) {
				t.Errorf("%s leaks %q", uri, leak)
			}
		}
	}
	if !strings.Contains(read("login://sites"), "gitlab") {
		t.Error("sites resource should list gitlab")
	}
	if _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "login://nope"}); err == nil {
		t.Error("an unknown resource must be an error")
	}
}

func TestServerInstructionsGuideTheAgent(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	init := cs.InitializeResult()
	for _, want := range []string{"login_wait", "user_rejected", "rate_limited", "host_not_allowed", "session_expired", "login://policy", "never print"} {
		if !strings.Contains(init.Instructions, want) {
			t.Errorf("instructions do not mention %q", want)
		}
	}
	if init.ServerInfo.Title == "" || init.ServerInfo.Version != Version {
		t.Errorf("server info = %+v", init.ServerInfo)
	}
}
