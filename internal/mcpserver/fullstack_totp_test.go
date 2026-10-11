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
	"github.com/LeafAI/securl/internal/sshtest"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/web"
)

// TestFullStackWithBothTOTPFactors runs the whole thing with both factors on: a real sshd tunnel, a DingTalk webhook, the
// real page in a real browser, and an authenticator played by the test. The person (the test) reads the codes from the
// secrets exactly like an authenticator would, unlocks the link with the long-period code, and seals what they type
// with the short-period one, in BOTH rounds of the login (password, then the site's own TOTP).
func TestFullStackWithBothTOTPFactors(t *testing.T) {
	browsertest.Require(t)
	srv := sshtest.Start(t)
	remotePort := sshtest.FreePort(t)

	var mu sync.Mutex
	var texts []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	cfg.Security.AllowLocalAddresses = true // the fake site runs on this machine
	cfg.Web.PageURL = "file://" + dir + "/index.html"
	cfg.MCP.MaxBlockSeconds = 60
	cfg.DingTalk = config.DingTalk{Webhook: hook.URL + "/robot/send?access_token=TOKEN"}
	cfg.Tunnel.Order = []string{"mycorp"}
	cfg.Tunnel.Custom = []config.CustomProvider{{Name: "mycorp", Command: srv.ReverseCommand(remotePort), URL: fmt.Sprintf("http://127.0.0.1:%d", remotePort)}}
	cfg.Security.LinkTOTP.Enabled, cfg.Security.SealTOTP.Enabled = true, true
	linkSecret, _ := totp.NewSecret()
	sealSecret, _ := totp.NewSecret()
	v := testVault(t, cfg)
	if err := v.Put(config.LinkSecretName, []byte(totp.FormatSecret(linkSecret))); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(config.SealSecretName, []byte(totp.FormatSecret(sealSecret))); err != nil {
		t.Fatal(err)
	}
	m, app, err := mcpserver.New(cfg, mcpserver.Options{Log: func(string, ...any) {}, Vault: v})
	if err != nil {
		t.Fatal(err)
	}
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
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "session_open", Arguments: map[string]any{"url": gl.URL, "site": "gitlab", "reason": "two factors"}})
		if err != nil {
			done <- result{nil, err}
			return
		}
		b, _ := json.Marshal(res.StructuredContent)
		var out map[string]any
		json.Unmarshal(b, &out)
		done <- result{out, nil}
	}()

	// What the person reads from the authenticator right now.
	unlockCode := func() string {
		return totp.Code(linkSecret, time.Now(), cfg.Security.LinkTOTP.Period, cfg.Security.LinkTOTP.Digits)
	}
	sealCode := func() string {
		return totp.Code(sealSecret, time.Now(), cfg.Security.SealTOTP.Period, cfg.Security.SealTOTP.Digits)
	}

	round := func(msg, fields string) string {
		i := strings.Index(msg, "](")
		link := msg[i+2 : i+strings.Index(msg[i:], ")")]
		frag, _ := url.ParseQuery(browsertest.Fragment(link))
		// the link the person clicked hides the site, the tunnel and the one-shot password
		for _, k := range []string{"site", "u", "s"} {
			if frag.Get(k) != "" {
				t.Errorf("the DingTalk link carries %q in the clear", k)
			}
		}
		for _, leak := range []string{"127.0.0.1", gl.URL, fmt.Sprint(remotePort)} {
			if strings.Contains(link, leak) {
				t.Errorf("the DingTalk link carries %q", leak)
			}
		}
		for _, want := range []string{"Unlock code", "Sealing code"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the message does not say %q is needed:\n%s", want, msg)
			}
		}
		var vals map[string]string
		json.Unmarshal([]byte(fields), &vals)
		vals["unlock"], vals["factor"] = unlockCode(), sealCode()
		b, _ := json.Marshal(vals)
		return browsertest.Drive(t, dir, browsertest.Fragment(link), "unlock-submit", string(b), "").Msg
	}

	m1 := waitText(1)
	if got := round(m1, `{"username":"alice","password":"pw"}`); !strings.Contains(got, "Another step") {
		t.Fatalf("round 1 page: %q", got)
	}
	if got := round(waitText(2), `{"code":"123456"}`); !strings.Contains(got, "Done") {
		t.Fatalf("round 2 page: %q", got)
	}
	select {
	case r := <-done:
		if r.err != nil || r.out["status"] != "ok" || strings.Contains(fmt.Sprint(r.out), "_gitlab_session") {
			t.Fatalf("login result: %+v %v", r.out, r.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("login did not finish")
	}
}
