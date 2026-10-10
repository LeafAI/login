package notify

import (
	"strings"
	"testing"
)

func TestEscapeNeutralisesMarkdown(t *testing.T) {
	got := Escape("see [login here](https://evil.example)\n# big **bold** `x` <b>", 200)
	for _, bad := range []string{"](", "\n", "<b>"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q still contains %q", got, bad)
		}
	}
	if strings.Contains(strings.ReplaceAll(got, "\\[", ""), "[") {
		t.Errorf("unescaped [ in %q", got)
	}
	if got := Escape(strings.Repeat("a", 500), 10); len([]rune(got)) != 13 {
		t.Errorf("not truncated: %d", len(got))
	}
}

func TestCodeBlockCannotCloseFence(t *testing.T) {
	if got := CodeBlock("select 1\n```\n[x](http://evil)", 100); strings.Contains(got, "```") {
		t.Errorf("fence survived: %q", got)
	}
}
