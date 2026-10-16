package site_test

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
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

func TestUnreachableMarksATransportFailureAndKeepsItsText(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.1:443: connect: connection refused")
	got := site.Unreachable(cause)
	if !errors.Is(got, site.ErrUnreachable) || !strings.Contains(got.Error(), "connection refused") {
		t.Errorf("%v", got)
	}
	if site.Unreachable(nil) != nil {
		t.Error("nothing to mark")
	}
	already := fmt.Errorf("%w: x", site.ErrUnreachable)
	if site.Unreachable(already) != already {
		t.Error("an error that is already marked is not wrapped twice")
	}
}
