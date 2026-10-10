package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/config"
	"github.com/LeafAI/login/internal/flow"
	"github.com/LeafAI/login/internal/mcpserver"
	"github.com/LeafAI/login/internal/web"

	_ "github.com/LeafAI/login/internal/site/archery"
	_ "github.com/LeafAI/login/internal/site/gitlab"
	_ "github.com/LeafAI/login/internal/site/noauth"
)

// fakeGitLab: sign-in form with TOTP 2FA.
func fakeGitLab() *httptest.Server {
	const form = `<form><input type="hidden" name="authenticity_token" value="T1"/></form>`
	const otp = `<form><input type="hidden" name="authenticity_token" value="T2"/><input name="user[otp_attempt]"/></form>`
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(form))
			return
		}
		r.ParseForm()
		if code := r.PostForm.Get("user[otp_attempt]"); code != "" {
			if code == "123456" {
				http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "sess", Path: "/"})
				http.Redirect(w, r, "/", 302)
				return
			}
			w.Write([]byte(otp))
			return
		}
		if r.PostForm.Get("user[login]") == "alice" && r.PostForm.Get("user[password]") == "pw" {
			w.Write([]byte(otp))
			return
		}
		w.Write([]byte(form))
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != "sess" {
			http.Error(w, "no", 401)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("home")) })
	return httptest.NewServer(mux)
}

// recorder is the fake DingTalk robot.
type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) Markdown(_ context.Context, title, text string) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, text)
	r.mu.Unlock()
	return nil
}

func (r *recorder) wait(t *testing.T, n int) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.msgs) >= n {
			m := r.msgs[n-1]
			r.mu.Unlock()
			return m
		}
		r.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no DingTalk message #%d", n)
	return ""
}

// localTunnel stands in for ssh: the "public" URL is just the local API address.
type localTunnel struct{ url string }

func (l localTunnel) PublicURL() string   { return l.url }
func (localTunnel) Done() <-chan struct{} { return nil }
func (localTunnel) Close()                {}

type localTunnels struct{}

func (localTunnels) Start(_ context.Context, port int) (flow.Tunnel, error) {
	return localTunnel{fmt.Sprintf("http://127.0.0.1:%d", port)}, nil
}

// human drives the real static page in headless Chromium for the link found in a DingTalk message.
func human(t *testing.T, msg, dir, action, values, reason string) string {
	t.Helper()
	i := strings.Index(msg, "](")
	j := strings.Index(msg[i:], ")")
	link := msg[i+2 : i+j]
	frag := link[strings.Index(link, "#")+1:]
	cmd := exec.Command("node", "../web/testdata/e2e.js", dir, frag, action, values, reason)
	cmd.Env = append(os.Environ(), "NODE_PATH=/opt/node22/lib/node_modules")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	return string(out)
}

// requireBrowser skips the test unless Node, Playwright and a Chromium are usable.
func requireBrowser(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}
	cmd := exec.Command("node", "-e", "require('playwright').chromium.executablePath()")
	cmd.Env = append(os.Environ(), "NODE_PATH=/opt/node22/lib/node_modules")
	if err := cmd.Run(); err != nil {
		t.Skip("playwright not available")
	}
}

type env struct {
	cs   *mcp.ClientSession
	rec  *recorder
	dir  string
	site *httptest.Server
}

func setup(t *testing.T) *env { return setupWith(t, nil) }

func setupWith(t *testing.T, tweak func(*config.Config)) *env {
	t.Helper()
	requireBrowser(t)
	dir := t.TempDir()
	if err := web.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir + "/nonexistent.yaml")
	cfg.Keys.Dir = dir + "/keys"
	cfg.Web.PageURL = "file://" + dir + "/index.html"
	cfg.Web.TTL = time.Minute
	cfg.MCP.MaxBlockSeconds = 1
	if tweak != nil {
		tweak(cfg)
	}
	rec := &recorder{}
	srv, _, err := mcpserver.New(cfg, mcpserver.Options{Notifier: rec, Tunnels: localTunnels{}, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	gl := fakeGitLab()
	t.Cleanup(gl.Close)
	return &env{cs, rec, dir, gl}
}

func (e *env) call(t *testing.T, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: bad structured content %s", tool, b)
	}
	return out, res.IsError
}

func TestLoginTwoRoundsViaBrowser(t *testing.T) {
	e := setup(t)
	url := e.site.URL + "/projects"

	// 1s block time < the human's time: expect a pending result first.
	out, isErr := e.call(t, "login", map[string]any{"url": url, "site": "gitlab", "reason": "list merge requests"})
	if isErr || out["status"] != "pending" || out["waiting_for"] != "login" {
		t.Fatalf("first call: %v", out)
	}
	id := out["login_id"].(string)
	if !strings.Contains(e.rec.wait(t, 1), "list merge requests") {
		t.Error("reason missing from DingTalk message")
	}

	// Round 1: username/password in the real page; round 2: TOTP from a new DingTalk message.
	r1 := human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw"}`, "")
	if !strings.Contains(r1, "Another step is needed") {
		t.Fatalf("round 1 page said: %s", r1)
	}
	if out, _ := e.call(t, "login_wait", map[string]any{"login_id": id, "max_block_seconds": 1}); out["status"] != "pending" || out["waiting_for"] != "totp" {
		// the second round may not be announced yet; wait for it explicitly below
		t.Logf("after round 1: %v", out)
	}
	r2 := human(t, e.rec.wait(t, 2), e.dir, "submit", `{"code":"123456"}`, "")
	if !strings.Contains(r2, "Done") {
		t.Fatalf("round 2 page said: %s", r2)
	}
	out, isErr = e.call(t, "login_wait", map[string]any{"login_id": id, "max_block_seconds": 20})
	if isErr || out["status"] != "ok" || !strings.Contains(out["cookie_header"].(string), "_gitlab_session=sess") || out["auth"] != "cookie" {
		t.Fatalf("final: %v", out)
	}

	// Second call reuses the validated session without bothering the human.
	out, _ = e.call(t, "login", map[string]any{"url": e.site.URL, "site": "gitlab"})
	if out["status"] != "ok" || out["cached"] != true {
		t.Fatalf("cached: %v", out)
	}
	if s, _ := e.call(t, "login_sessions", nil); len(s["sessions"].([]any)) != 1 || strings.Contains(fmt.Sprint(s), "_gitlab_session") {
		t.Errorf("sessions: %v", s)
	}
	if o, _ := e.call(t, "logout", map[string]any{"url": e.site.URL}); o["removed"] != float64(1) {
		t.Errorf("logout: %v", o)
	}
}

func TestRejectWithReason(t *testing.T) {
	e := setup(t)
	out, _ := e.call(t, "login", map[string]any{"url": e.site.URL, "site": "gitlab", "max_block_seconds": 1})
	id := out["login_id"].(string)
	page := human(t, e.rec.wait(t, 1), e.dir, "reject", "", "I did not request this")
	if !strings.Contains(page, "Rejected") {
		t.Fatalf("page said: %s", page)
	}
	out, isErr := e.call(t, "login_wait", map[string]any{"login_id": id, "max_block_seconds": 20})
	if !isErr || out["code"] != "user_rejected" || !strings.Contains(out["message"].(string), "I did not request this") {
		t.Fatalf("got %v (isErr=%v)", out, isErr)
	}
}

func TestToolsListAndNoAuthSite(t *testing.T) {
	e := setup(t)
	tools, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "login login_wait login_sites login_sessions logout archery_instances archery_query archery_run_sql archery_wait archery_workflow_status archery_cancel"
	var got []string
	for _, tl := range tools.Tools {
		got = append(got, tl.Name)
	}
	for _, n := range strings.Fields(want) {
		if !strings.Contains(" "+strings.Join(got, " ")+" ", " "+n+" ") {
			t.Errorf("tool %s missing (have %v)", n, got)
		}
	}
	out, isErr := e.call(t, "login", map[string]any{"url": e.site.URL, "site": "skywalking"})
	if isErr || out["status"] != "ok" || out["auth"] != "none" {
		t.Errorf("skywalking: %v", out)
	}
	if out, isErr := e.call(t, "login", map[string]any{"url": "nope"}); !isErr || out["code"] != "invalid_argument" {
		t.Errorf("bad url: %v", out)
	}
	if out, isErr := e.call(t, "login", map[string]any{"url": "https://unknown.example"}); !isErr || out["code"] != "unsupported_site" {
		t.Errorf("unsupported: %v", out)
	}
}
