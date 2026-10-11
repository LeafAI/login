package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignVector(t *testing.T) {
	// Computed independently with Python hmac/hashlib: base64(HMAC-SHA256(key="SEC", msg="1700000000000\nSEC")).
	if got := Sign("SEC", 1700000000000); got != "r+2we0q01lkZqz38LA5IPNbHN81U1leRf3Au4PSQb6Q=" {
		t.Fatalf("unexpected signature %q", got)
	}
}

func TestMarkdown(t *testing.T) {
	var gotQuery string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()
	d := &DingTalk{Webhook: srv.URL + "/robot/send?access_token=T", Secret: "SEC", Keyword: "login", Mobiles: []string{"1380000"},
		Now: func() time.Time { return time.UnixMilli(1700000000000) }}
	if err := d.Markdown(context.Background(), "hello", "**x**"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "access_token=T") || !strings.Contains(gotQuery, "timestamp=1700000000000") || !strings.Contains(gotQuery, "sign=") {
		t.Errorf("query %q", gotQuery)
	}
	md := gotBody["markdown"].(map[string]any)
	if md["title"] != "login hello" {
		t.Errorf("title %v", md["title"])
	}
}

func TestErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errcode":310000,"errmsg":"keywords not in content"}`))
	}))
	defer srv.Close()
	if err := (&DingTalk{Webhook: srv.URL}).Markdown(context.Background(), "t", "x"); err == nil || !strings.Contains(err.Error(), "310000") {
		t.Errorf("want errcode error, got %v", err)
	}
	if err := (&DingTalk{}).Markdown(context.Background(), "t", "x"); err == nil {
		t.Error("want unconfigured error")
	}
}

const leakToken = "ACCESSTOKEN_SECRET_VALUE"

func assertNoWebhookSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, bad := range []string{leakToken, "access_token", "sign=", "timestamp="} {
		if strings.Contains(s, bad) {
			t.Errorf("%s leaks %q: %s", what, bad, s)
		}
	}
}

func TestTransportErrorDoesNotLeakWebhook(t *testing.T) {
	d := &DingTalk{Webhook: "https://127.0.0.1:1/robot/send?access_token=" + leakToken, Secret: "SEC"}
	err := d.Markdown(context.Background(), "t", "x")
	if err == nil {
		t.Fatal("want a transport error")
	}
	assertNoWebhookSecrets(t, "transport error", err.Error())
	if !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "dial") {
		t.Errorf("the cause must stay visible: %v", err)
	}
}

func TestMalformedWebhookErrorDoesNotLeak(t *testing.T) {
	d := &DingTalk{Webhook: "https://exa mple.com/robot/send?access_token=" + leakToken}
	err := d.Markdown(context.Background(), "t", "x")
	if err == nil {
		t.Fatal("want a parse error")
	}
	assertNoWebhookSecrets(t, "parse error", err.Error())
}

func TestTimeoutErrorDoesNotLeakAndKeepsCause(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	d := &DingTalk{Webhook: srv.URL + "/robot/send?access_token=" + leakToken, Secret: "SEC", HTTP: &http.Client{Timeout: 50 * time.Millisecond}}
	err := d.Markdown(context.Background(), "t", "x")
	if err == nil {
		t.Fatal("want a timeout")
	}
	assertNoWebhookSecrets(t, "timeout error", err.Error())
}

func TestRedactStripsCredentialParameters(t *testing.T) {
	in := `Post "https://oapi.dingtalk.com/robot/send?access_token=AAA&sign=B%2Bc%3D&timestamp=1700000000000": dial tcp: refused; again access_token=ZZZ`
	got := Redact(in)
	assertNoWebhookSecrets(t, "Redact", got)
	for _, bad := range []string{"AAA", "B%2Bc", "ZZZ", "1700000000000"} {
		if strings.Contains(got, bad) {
			t.Errorf("Redact kept %q: %s", bad, got)
		}
	}
	if !strings.Contains(got, "dial tcp: refused") {
		t.Errorf("Redact must keep the cause: %s", got)
	}
	if Redact("plain text") != "plain text" {
		t.Error("Redact must not touch text without credentials")
	}
}

func TestRedactCutsQueryStringOfAnyURL(t *testing.T) {
	got := Redact(`Get "https://hook.example/robot?key=OTHERSECRET&x=1": refused`)
	if strings.Contains(got, "OTHERSECRET") || strings.Contains(got, "?") {
		t.Errorf("a URL query string must be cut even with unknown parameter names: %s", got)
	}
	if !strings.Contains(got, "https://hook.example/robot") || !strings.Contains(got, "refused") {
		t.Errorf("host, path and cause must stay: %s", got)
	}
}
