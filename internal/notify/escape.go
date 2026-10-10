package notify

import "strings"

var mdReplacer = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)",
	"<", "&lt;", ">", "&gt;", "#", "\\#", "|", "\\|", "!", "\\!",
)

// Escape makes agent-supplied text safe to embed in a DingTalk markdown message: it is flattened to
// one line, truncated to max runes and stripped of markdown syntax so it cannot add links or formatting.
func Escape(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); max > 0 && len(r) > max {
		s = string(r[:max]) + "..."
	}
	return mdReplacer.Replace(s)
}

// CodeBlock makes agent-supplied text safe inside a fenced code block (no early fence close).
func CodeBlock(s string, max int) string {
	if r := []rune(s); max > 0 && len(r) > max {
		s = string(r[:max]) + "..."
	}
	return strings.ReplaceAll(s, "```", "'''")
}
