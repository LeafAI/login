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

// DingTalk @-mentions a person only when the phone number is in the message's `at.atMobiles` list AND the same number
// is written as "@number" in the text (its documented examples all start the markdown text with "@number"). The robot
// used to send the list alone, so nobody was ever mentioned: the message arrived, but no phone rang.

func sendCapturing(t *testing.T, d *DingTalk, title, text string) map[string]any {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()
	d.Webhook = srv.URL + "/robot/send?access_token=T"
	if err := d.Markdown(context.Background(), title, text); err != nil {
		t.Fatal(err)
	}
	return body
}

func mdText(t *testing.T, body map[string]any) string {
	t.Helper()
	md, ok := body["markdown"].(map[string]any)
	if !ok {
		t.Fatalf("no markdown in %v", body)
	}
	s, _ := md["text"].(string)
	return s
}

func atMobiles(t *testing.T, body map[string]any) []string {
	t.Helper()
	at, _ := body["at"].(map[string]any)
	var out []string
	for _, v := range at["atMobiles"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestEachMentionedNumberIsWrittenInTheTextAndListed(t *testing.T) {
	body := sendCapturing(t, &DingTalk{Mobiles: []string{"13800000001", "13900000002"}}, "t", "### hello\n\nbody")
	text := mdText(t, body)
	if !strings.HasPrefix(text, "@13800000001 @13900000002\n\n") {
		t.Errorf("the text must start with the @numbers, then a blank line: %q", text)
	}
	if !strings.HasSuffix(text, "### hello\n\nbody") {
		t.Errorf("the message itself must follow unchanged: %q", text)
	}
	if got := strings.Join(atMobiles(t, body), ","); got != "13800000001,13900000002" {
		t.Errorf("atMobiles = %q, the same numbers must be listed", got)
	}
}

func TestNobodyIsMentionedWhenNoNumberIsConfigured(t *testing.T) {
	body := sendCapturing(t, &DingTalk{}, "t", "### hello")
	if text := mdText(t, body); text != "### hello" {
		t.Errorf("without numbers the text is the message alone: %q", text)
	}
	if got := atMobiles(t, body); len(got) != 0 {
		t.Errorf("atMobiles = %v, want none", got)
	}
	if at, _ := body["at"].(map[string]any); at["isAtAll"] != false {
		t.Errorf("isAtAll must stay false: everyone in the group is never mentioned: %v", at["isAtAll"])
	}
}

// The numbers come from the configuration, a file a person edits. A stray space, an empty entry, a repeat or a character
// that is not a digit must not end up in a message as something that looks like another mention.
func TestMentionedNumbersAreCleaned(t *testing.T) {
	body := sendCapturing(t, &DingTalk{Mobiles: []string{" 13800000001 ", "", "13800000001", "1380000x002", "+8613900000003", "13900000004\n@all", "13700000005", "\t13600000006 "}}, "t", "m")
	text := mdText(t, body)
	if !strings.HasPrefix(text, "@13800000001 @13700000005 @13600000006\n\n") {
		t.Errorf("want only the clean, distinct numbers, in order (spaces ignored, an entry with any other character refused, not repaired): %q", text)
	}
	for _, leaked := range []string{"@all", "x002", "13900000004", "8613900000003", "+"} {
		if strings.Contains(text, leaked) {
			t.Errorf("a malformed entry reached the text (%q): %q", leaked, text)
		}
	}
	if got := strings.Join(atMobiles(t, body), ","); got != "13800000001,13700000005,13600000006" {
		t.Errorf("atMobiles = %q", got)
	}
}

// Text that an agent supplies (the reason for a login, the title of a SQL change) is escaped before it is put in a message.
// It may contain "@13800000009": that must stay plain text. Only the numbers in the configuration are mentioned.
func TestAnAgentCannotMentionAnyoneByWhatItWrites(t *testing.T) {
	body := sendCapturing(t, &DingTalk{Mobiles: []string{"13800000001"}}, "t", "reason: "+Escape("please call @13800000009 @all now", 100))
	if got := strings.Join(atMobiles(t, body), ","); got != "13800000001" {
		t.Errorf("atMobiles = %q: only the configured number may be listed", got)
	}
	if at, _ := body["at"].(map[string]any); at["isAtAll"] != false {
		t.Error("isAtAll must stay false")
	}
}
