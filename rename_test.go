package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The program is called securl. The word "login" still names what one tool does (log in to a site), so it stays in tool
// names, in the "login" step of a page and in prose about logging in. What must not stay is "login" as the NAME OF THE
// PROGRAM: in a command a person is told to type, in a message that says who is speaking, or in a path.

var programNameAsCommand = regexp.MustCompile("`login (config|vault|doctor|page|version)|run login |: login (config|vault|doctor)|\"login (config|vault|doctor)")

func goFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") && !strings.HasPrefix(p, ".git") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestNoUserFacingTextTellsAPersonToTypeLoginAsTheCommand(t *testing.T) {
	for _, f := range goFiles(t) {
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			if programNameAsCommand.MatchString(line) {
				t.Errorf("%s:%d still names the program 'login': %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// A message that says what the program does names it as the subject of the sentence: "login does not connect ...".
// "log in", "login page", "login step", "the login" (the act) stay; "login" followed by a verb that only a program can do
// is the old name.
var programNameAsSubject = regexp.MustCompile(`\blogin (does|do|will|would|never|cannot|can|keeps|keep|stores|sends|asks|needs|is|has|runs|opens|reads|writes|refuses|only|always)\b`)

func TestNoUserFacingTextUsesLoginAsTheNameOfTheProgram(t *testing.T) {
	for _, f := range goFiles(t) {
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			if t := strings.TrimSpace(line); strings.HasPrefix(t, "//") {
				continue
			}
			if programNameAsSubject.MatchString(line) {
				t.Errorf("%s:%d names the program 'login': %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestTheProgramSpeaksUnderItsNewName(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"main.go", "Command securl"},
		{"vaultcmd.go", `"securl vault: "`},
		{"internal/mcpserver/server.go", `Name: "securl"`},
		{"internal/mcpserver/server.go", `"securl: "+f`},
	} {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), c.want) {
			t.Errorf("%s must contain %q", c.file, c.want)
		}
	}
}

// The old name is gone everywhere, not kept for compatibility: tools, resources, the module path, labels, files.
func TestNothingIsLeftOfTheOldNameInTheSource(t *testing.T) {
	bad := regexp.MustCompile(`LeafAI/login\b|login://|"login_wait"|"login_sites"|"login_sessions"|"logout"|login/seal|login/link|login-vault|login\.js|login\.css|LOGIN_[A-Z]|"login", ""|login@localhost`)
	for _, f := range goFiles(t) {
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			if bad.MatchString(line) {
				t.Errorf("%s:%d: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	for _, f := range []string{"go.mod", "Dockerfile", ".github/workflows/ci.yml", ".github/workflows/pages.yml", "scripts/build-pages.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bad.Match(b) {
			t.Errorf("%s still carries the old name", f)
		}
	}
}
