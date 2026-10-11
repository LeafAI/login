package mcpserver_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
)

// The promise of securl, tested as a whole: a person logs in through the real page in a real browser, the agent uses the
// session through the request tool, and NOTHING the agent receives, at any step, contains the password, the cookie the
// site issued, or anything derived from them. The check is on the wire: every result the agent got is collected and
// searched.

type wire struct {
	mu  sync.Mutex
	log []string
}

func (w *wire) add(tool string, res *mcp.CallToolResult) {
	b, _ := json.Marshal(res)
	w.mu.Lock()
	w.log = append(w.log, tool+" => "+string(b))
	w.mu.Unlock()
}

func (w *wire) all() string { w.mu.Lock(); defer w.mu.Unlock(); return strings.Join(w.log, "\n") }

// sessionSite is a GitLab-shaped fake that issues a session cookie and has a debug endpoint that repeats what it was sent,
// the worst case for a scrubber.
func sessionSite() *httptest.Server {
	const issued = "ISSUED-SESSION-COOKIE-8f3a91c2d4e5b6a7"
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`<form><input type="hidden" name="authenticity_token" value="T1"/></form>`))
			return
		}
		r.ParseForm()
		if r.PostForm.Get("user[login]") == "alice" && r.PostForm.Get("user[password]") == "S3cret-Passw0rd-XYZ" {
			http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: issued, Path: "/"})
			http.Redirect(w, r, "/", 302)
			return
		}
		w.Write([]byte("bad"))
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != issued {
			http.Error(w, "no", 401)
		}
	})
	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("_gitlab_session")
		v := ""
		if c != nil {
			v = c.Value
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<pre>Cookie: %s</pre><a href="/x?sid=%s">link</a><script>var s=%q;</script><!-- %x -->`, r.Header.Get("Cookie"), v, v, v)
	})
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != issued {
			http.Error(w, "sign in", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":1,"name":"payments"},{"id":2,"name":"ledger"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("home")) })
	return httptest.NewServer(mux)
}

func TestTheAgentNeverHoldsACredentialFromLoginToRequest(t *testing.T) {
	const password = "S3cret-Passw0rd-XYZ"
	const issued = "ISSUED-SESSION-COOKIE-8f3a91c2d4e5b6a7"
	site := sessionSite()
	defer site.Close()
	e := setupWith(t, func(c *config.Config) { c.MCP.MaxBlockSeconds = 1 })
	w := &wire{}
	call := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		w.add(tool, res)
		b, _ := json.Marshal(res.StructuredContent)
		var out map[string]any
		json.Unmarshal(b, &out)
		return out
	}

	// 1. the agent asks for a session; a person types the password into the real page
	out := call("session_open", map[string]any{"url": site.URL, "site": "gitlab", "reason": "list projects"})
	if out["status"] != "pending" {
		t.Fatalf("%v", out)
	}
	id := out["login_id"]
	page := human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"`+password+`"}`, "")
	if !strings.Contains(page, "Done") {
		t.Fatalf("the page said: %s", page)
	}
	out = call("session_wait", map[string]any{"login_id": id, "max_block_seconds": 20})
	if out["status"] != "ok" {
		t.Fatalf("%v", out)
	}

	// 2. the agent uses the session
	got := call("request", map[string]any{"url": site.URL, "method": "GET", "path": "/projects"})
	if got["status"] != float64(200) || !strings.Contains(fmt.Sprint(got["body"]), "payments") {
		t.Fatalf("the request must work with the session the person opened: %v", got)
	}

	// 3. the worst case: a page that repeats the cookie in six encodings
	dbg := call("request", map[string]any{"url": site.URL, "method": "GET", "path": "/debug"})
	if !strings.Contains(fmt.Sprint(dbg["body"]), "[REDACTED]") {
		t.Fatalf("the debug page repeats the cookie, so something must have been removed: %v", dbg)
	}

	// 4. and the session list
	call("session_list", map[string]any{})

	// Everything the agent received, from the first call to the last.
	all := w.all()
	// What the agent must never have is a VALUE: the password, the session id the site issued, and any slice of either. The
	// NAME of the cookie is public (it is in the site's own pages and documentation) and an echo page repeating
	// "_gitlab_session=[REDACTED]" tells the agent nothing it can use, so it is not counted.
	for _, secret := range []string{password, issued, "8f3a91c2d4e5b6a7", "ISSUED-SESSION", "S3cret", "Passw0rd"} {
		if strings.Contains(all, secret) {
			i := strings.Index(all, secret)
			t.Errorf("the agent was handed %q:\n...%s...", secret, all[max0(i-150):min2(i+150, len(all))])
		}
	}
	if strings.Contains(all, "_gitlab_session=") && !strings.Contains(all, "_gitlab_session=[REDACTED]") {
		t.Errorf("a cookie name followed by anything but the placeholder: the value was not removed")
	}
	for _, field := range []string{"cookie_header", "Set-Cookie", "set-cookie"} {
		if strings.Contains(all, field) {
			t.Errorf("a result mentions %q", field)
		}
	}
	// the DingTalk messages are not the agent's channel, but they must not carry the password either
	for _, m := range e.rec.all() {
		if strings.Contains(m, password) {
			t.Errorf("a DingTalk message carries the password")
		}
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A session id made only of letters, digits and dashes is its own URL form and its own JavaScript form, so a scrubber that
// knew nothing about those encodings would still pass the test above. Real session cookies often hold "+", "/", "=" and
// quotes. This site issues one that does, and repeats it as a browser, a framework and a JSON API each would.
func TestACookieWithSpecialCharactersIsRemovedInEveryEncodingTheSiteRepeatsItIn(t *testing.T) {
	const issued = `Ab/Cd+Ef=gh"ij\kl&mn 9z`
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`<form><input type="hidden" name="authenticity_token" value="T1"/></form>`))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: url.QueryEscape(issued), Path: "/"})
		http.Redirect(w, r, "/", 302)
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("_gitlab_session")
		raw, _ := url.QueryUnescape(c.Value)
		j, _ := json.Marshal(raw)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "raw=%s\nurl=%s\njson=%s\nhtml=%s\nb64=%s\nhex=%x\nheader=%s\n", raw, url.QueryEscape(raw), j, html.EscapeString(raw),
			base64.StdEncoding.EncodeToString([]byte(raw)), raw, r.Header.Get("Cookie"))
	})
	site := httptest.NewServer(mux)
	defer site.Close()
	e := setupWith(t, func(c *config.Config) { c.MCP.MaxBlockSeconds = 1 })
	out, _ := e.call(t, "session_open", map[string]any{"url": site.URL, "site": "gitlab"})
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw"}`, "")
	e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	got, isErr := e.call(t, "request", map[string]any{"url": site.URL, "method": "GET", "path": "/echo"})
	if isErr {
		t.Fatalf("%v", got)
	}
	body := fmt.Sprint(got["body"])
	for name, leak := range map[string]string{
		"raw": issued, "url-escaped": url.QueryEscape(issued), "json-escaped": strings.Trim(mustJSON(issued), `"`), "html-escaped": html.EscapeString(issued),
		"base64": base64.StdEncoding.EncodeToString([]byte(issued)), "hex": fmt.Sprintf("%x", issued),
	} {
		if strings.Contains(body, leak) {
			t.Errorf("the %s form of the session cookie reached the agent:\n%s", name, body)
		}
	}
	if n, _ := got["redactions"].(float64); n < 6 {
		t.Errorf("six encodings were repeated, so at least six removals are expected, the count says %v", got["redactions"])
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
