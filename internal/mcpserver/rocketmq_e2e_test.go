package mcpserver_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
)

// The full path against a real RocketMQ Dashboard (the 2.0.x image the production one resembles): the page asks for the
// account, securl logs in with it, and the request tool reads. SECURL_TEST_ROCKETMQ names the Dashboard (host:port); the
// test is skipped when it is not set. scripts/mqtest/up.sh starts one. Accounts: viewer (a normal user) and admin.
func dashboard(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("SECURL_TEST_ROCKETMQ")
	if addr == "" {
		t.Skip("SECURL_TEST_ROCKETMQ is not set")
	}
	return "http://" + addr
}

func loginSite(t *testing.T, e *env, base, name, user, pass string) map[string]any {
	t.Helper()
	out, _ := e.call(t, "session_open", map[string]any{"url": base, "site": name, "reason": "read the topics", "max_block_seconds": 1})
	if out["status"] != "pending" {
		t.Fatalf("expected a pending login: %v", out)
	}
	human(t, e.rec.wait(t, len(e.rec.all())), e.dir, "submit", fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass), "")
	res, _ := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	return res
}

// adminCall asks the Dashboard directly, as the administrator, what is really there: the test's own eyes, not securl's.
func adminCall(t *testing.T, base, method, path string, body string) (int, string) {
	t.Helper()
	jar := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	login, _ := http.NewRequest("POST", base+"/login/login.do?"+url.Values{"username": {"admin"}, "password": {"admin-pass-1"}}.Encode(), nil)
	resp, err := jar.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	r2, err := jar.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	b, _ := io.ReadAll(r2.Body)
	return r2.StatusCode, string(b)
}

func TestRocketMQDashboardEndToEnd(t *testing.T) {
	base := dashboard(t)
	e := setupWith(t, nil)
	res := loginSite(t, e, base, "rocketmq", "viewer", "viewer-pass-1")
	if res["status"] != "ok" || res["site"] != "rocketmq" {
		t.Fatalf("login: %v", res)
	}
	assertNoCredentials(t, res, "viewer-pass-1", "JSESSIONID")

	// A read goes through, with the session's cookie put in by securl, and the answer is the Dashboard's.
	out, isErr := e.call(t, "request", map[string]any{"url": base, "method": "GET", "path": "/topic/list.query"})
	if isErr || out["status"] != float64(200) {
		t.Fatalf("%v", out)
	}
	body, _ := out["body"].(string)
	var r struct {
		Status int `json:"status"`
		Data   struct {
			TopicList []string `json:"topicList"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil || r.Status != 0 || len(r.Data.TopicList) == 0 {
		t.Fatalf("the Dashboard's answer was read as a logged-in one: %v %s", err, body)
	}
	// The answer of the request tool has headers and a body, which assertNoCredentials (made for the result of a login) forbids;
	// what it must not hold is the session and the password.
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), "viewer-pass-1") || strings.Contains(string(raw), "SESSION-") {
		t.Errorf("the answer holds the password or the session: %s", raw)
	}
	if hdr, _ := json.Marshal(out["headers"]); strings.Contains(strings.ToLower(string(hdr)), "set-cookie") {
		t.Errorf("a Set-Cookie header reached the agent: %s", hdr)
	}

	// Writes are refused in securl. The strongest proof that nothing was sent: make one, as admin, that WOULD have changed
	// something, ask for it through the tool, and look at the Dashboard afterwards.
	topic := "securl_e2e_probe_topic"
	status, ans := adminCall(t, base, "POST", "/topic/createOrUpdate.do", fmt.Sprintf(`{"topicName":%q,"brokerNameList":["broker-a"],"clusterNameList":[],"writeQueueNums":2,"readQueueNums":2,"perm":6,"order":false}`, topic))
	if status != 200 || !strings.Contains(ans, `"status":0`) {
		t.Skipf("could not set up the topic the test wants to see survive: %d %s", status, ans)
	}
	defer adminCall(t, base, "POST", "/topic/deleteTopic.do?clusterName=DefaultCluster&topic="+topic, "")
	for name, args := range map[string]map[string]any{
		"delete through a write path":  {"method": "POST", "path": "/topic/deleteTopic.do", "query": map[string]any{"clusterName": "DefaultCluster", "topic": topic}},
		"delete through GET":           {"method": "GET", "path": "/topic/deleteTopic.do", "query": map[string]any{"clusterName": "DefaultCluster", "topic": topic}},
		"reset offsets":                {"method": "POST", "path": "/consumer/resetOffset.do", "json": map[string]any{"topic": topic}},
		"change the name server":       {"method": "POST", "path": "/ops/updateNameSvrAddr.do", "query": map[string]any{"nameSvrAddrList": "evil:9876"}},
		"read a message body":          {"method": "GET", "path": "/message/queryMessageByTopic.query", "query": map[string]any{"topic": topic, "begin": "0", "end": "9999999999999"}},
		"read a message body, in case": {"method": "GET", "path": "/MESSAGE/queryMessageByTopic.query", "query": map[string]any{"topic": topic}},
	} {
		args["url"] = base
		out, isErr := e.call(t, "request", args)
		if !isErr || out["code"] != "request_not_allowed" {
			t.Errorf("%s: %v", name, out)
		}
	}
	status, list := adminCall(t, base, "GET", "/topic/list.query", "")
	if status != 200 || !strings.Contains(list, topic) {
		t.Errorf("the topic is gone: a refused write must not have reached the Dashboard (%d)", status)
	}
	if _, home := adminCall(t, base, "GET", "/ops/homePage.query", ""); strings.Contains(home, "evil:9876") {
		t.Error("the name server was changed")
	}
}

func TestRocketMQMessageBodiesOpenOnlyWhenTheOwnerOpensThem(t *testing.T) {
	base := dashboard(t)
	for _, open := range []bool{false, true} {
		e := setupWith(t, func(c *config.Config) {
			if open {
				c.SiteOptions = map[string]map[string]string{"rocketmq": {"allow_message_body": "yes"}}
			}
		})
		if res := loginSite(t, e, base, "rocketmq", "viewer", "viewer-pass-1"); res["status"] != "ok" {
			t.Fatalf("%v", res)
		}
		out, isErr := e.call(t, "request", map[string]any{"url": base, "method": "GET", "path": "/message/queryMessageByTopic.query",
			"query": map[string]any{"topic": "BenchmarkTest", "begin": "0", "end": "9999999999999"}})
		switch {
		case !open && (!isErr || out["code"] != "request_not_allowed"):
			t.Errorf("closed by default: %v", out)
		case open && (isErr || out["status"] != float64(200)):
			t.Errorf("opened by the owner: %v", out)
		}
	}
}

func TestRocketMQWrongPasswordIsBadCredentialsAndLeavesNoSession(t *testing.T) {
	base := dashboard(t)
	e := setupWith(t, nil)
	res := loginSite(t, e, base, "rocketmq", "viewer", "WRONG-PASSWORD-1")
	if res["code"] != "bad_credentials" {
		t.Errorf("%v", res)
	}
	if strings.Contains(fmt.Sprint(res), "WRONG-PASSWORD-1") {
		t.Errorf("%v", res)
	}
	if out, isErr := e.call(t, "request", map[string]any{"url": base, "method": "GET", "path": "/topic/list.query"}); !isErr || out["code"] != "no_session" {
		t.Errorf("%v", out)
	}
}
