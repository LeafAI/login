package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/notify"
	"github.com/LeafAI/securl/internal/sshtest"
	"github.com/LeafAI/securl/internal/web"
)

// TestFullStack runs everything except the real internet: a config-defined SSH tunnel through a real
// sshd, a real (signed) DingTalk webhook call received by a local HTTP server, the real login page in
// headless Chromium, and a fake GitLab.
func TestFullStack(t *testing.T) {
	browsertest.Require(t)
	srv := sshtest.Start(t)
	remotePort := sshtest.FreePort(t)

	// DingTalk: the robot webhook, verifying the signature like the real one would.
	var mu sync.Mutex
	var texts []string
	const secret = "SECtest"
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var ts int64
		fmt.Sscanf(q.Get("timestamp"), "%d", &ts)
		if q.Get("access_token") != "TOKEN" || q.Get("sign") != notify.Sign(secret, ts) {
			w.Write([]byte(`{"errcode":310000,"errmsg":"sign not match"}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m struct {
			Markdown struct{ Text string } `json:"markdown"`
		}
		json.Unmarshal(body, &m)
		mu.Lock()
		texts = append(texts, m.Markdown.Text)
		mu.Unlock()
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer hook.Close()
	waitText := func(n int) string {
		for i := 0; i < 300; i++ {
			mu.Lock()
			if len(texts) >= n {
				s := texts[n-1]
				mu.Unlock()
				return s
			}
			mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no DingTalk message #%d", n)
		return ""
	}

	dir := t.TempDir()
	web.WriteTo(dir)
	cfg, _ := config.Load(dir + "/none.yaml")
	cfg.Keys.Dir = dir + "/keys"
	cfg.Web.PageURL = "file://" + dir + "/index.html"
	cfg.MCP.MaxBlockSeconds = 60
	cfg.DingTalk = config.DingTalk{Webhook: hook.URL + "/robot/send?access_token=TOKEN", Secret: secret}
	cfg.Tunnel.Order = []string{"mycorp"}
	cfg.Tunnel.Custom = []config.CustomProvider{{Name: "mycorp", Command: srv.ReverseCommand(remotePort), URL: fmt.Sprintf("http://127.0.0.1:%d", remotePort)}}
	m, app, err := mcpserver.New(cfg, mcpserver.Options{Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	// The tunnel of a finished login is closed a moment after the page has read the outcome. The test ends sooner,
	// so close the server explicitly: otherwise the real ssh process outlives the test as an orphan.
	t.Cleanup(app.Close)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := m.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	gl := fakeGitLab()
	defer gl.Close()

	type result struct {
		out map[string]any
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "login", Arguments: map[string]any{"url": gl.URL, "site": "gitlab", "reason": "full stack"}})
		if err != nil {
			done <- result{nil, err}
			return
		}
		b, _ := json.Marshal(res.StructuredContent)
		var out map[string]any
		json.Unmarshal(b, &out)
		done <- result{out, nil}
	}()

	drive := func(msg, action, values string) string {
		i := strings.Index(msg, "](")
		link := msg[i+2 : i+strings.Index(msg[i:], ")")]
		u, _ := url.Parse(link)
		_ = u
		return browsertest.Drive(t, dir, browsertest.Fragment(link), action, values, "").Msg
	}
	m1 := waitText(1)
	if !strings.Contains(m1, "full stack") || !strings.Contains(m1, "Step 1") {
		t.Errorf("first message:\n%s", m1)
	}
	if got := drive(m1, "submit", `{"username":"alice","password":"pw"}`); !strings.Contains(got, "Another step") {
		t.Fatalf("round 1 page: %q", got)
	}
	if got := drive(waitText(2), "submit", `{"code":"123456"}`); !strings.Contains(got, "Done") {
		t.Fatalf("round 2 page: %q", got)
	}
	select {
	case r := <-done:
		if r.err != nil || r.out["status"] != "ok" || !strings.Contains(fmt.Sprint(r.out["cookie_header"]), "_gitlab_session=sess") {
			t.Fatalf("login result: %+v %v", r.out, r.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("login did not finish")
	}
}
