package site_test

import (
	"net/url"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	_ "github.com/LeafAI/securl/internal/site/noauth"
)

func TestResolve(t *testing.T) {
	u, _ := url.Parse("https://skywalking.corp.example/")
	d, err := site.Resolve("", u)
	if err != nil || d.Name() != "skywalking" || d.NeedsLogin() {
		t.Fatalf("got %v %v", d, err)
	}
	if _, err := site.Resolve("nope", u); err == nil {
		t.Error("expected unknown-site error")
	}
	other, _ := url.Parse("https://other.example/")
	if _, err := site.Resolve("", other); err == nil {
		t.Error("expected no-match error")
	}
}
