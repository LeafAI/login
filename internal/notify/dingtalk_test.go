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
