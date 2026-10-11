package main

import (
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/mcpserver"
)

func TestVersionLine(t *testing.T) {
	got := versionLine()
	for _, want := range []string{"login ", mcpserver.Version, "go1", "/"} {
		if !strings.Contains(got, want) {
			t.Errorf("version line %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "\n") {
		t.Errorf("must be a single line: %q", got)
	}
}
