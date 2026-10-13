package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The binary links the Go standard library of the toolchain that built it, and securl's http.Client talks to sites that
// are not trusted. govulncheck found 19 reachable vulnerabilities in net/http, crypto/tls, crypto/x509, net/url, net and
// others with Go 1.25.9; the last of them is fixed only in Go 1.26.9. Every place that picks a Go version has to say at
// least that, or a build quietly goes back to a standard library with those holes.

// minGo is the oldest Go whose standard library has none of the vulnerabilities govulncheck reported as reachable.
const minGo = "1.26.9"

func goVersionParts(t *testing.T, v string) []int {
	t.Helper()
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("not a version number: %q", v)
		}
		out = append(out, n)
	}
	for len(out) < 3 {
		out = append(out, 0)
	}
	return out
}

func atLeast(t *testing.T, got, want string) bool {
	t.Helper()
	g, w := goVersionParts(t, got), goVersionParts(t, want)
	for i := 0; i < 3; i++ {
		if g[i] != w[i] {
			return g[i] > w[i]
		}
	}
	return true
}

// checkGoMod returns what is wrong with the text of a go.mod. It is a function of the text so that the check can be
// tried on go.mod files that the go tool itself would refuse to load: the dependencies need Go 1.26, so an edit back to
// 1.25 stops `go test` before any test runs. The check does not depend on that.
func checkGoMod(t *testing.T, mod string) []string {
	t.Helper()
	var problems []string
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+(?:\.\d+)?)$`).FindStringSubmatch(mod)
	if m == nil {
		return []string{"go.mod has no go directive"}
	}
	if !atLeast(t, m[1], minGo) {
		problems = append(problems, "go "+m[1]+" links a standard library with reachable vulnerabilities, want "+minGo+" or newer")
	}
	// With `go 1.26` (no patch) the toolchain that is picked is the first 1.26 there was, which has them all.
	if !regexp.MustCompile(`(?m)^go \d+\.\d+\.\d+$`).MatchString(mod) {
		problems = append(problems, "the go directive must name the patch version: `go 1.26` accepts the first 1.26 release")
	}
	for _, l := range regexp.MustCompile(`(?m)^toolchain go(\S+)`).FindAllStringSubmatch(mod, -1) {
		if !atLeast(t, l[1], minGo) {
			problems = append(problems, "the toolchain line says go"+l[1]+", older than "+minGo)
		}
	}
	return problems
}

func TestGoModRequiresAStandardLibraryWithoutTheKnownHoles(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range checkGoMod(t, string(b)) {
		t.Error(p)
	}
}

func TestTheGoModCheckRefusesEveryOlderOrVagueDirective(t *testing.T) {
	bad := map[string]string{
		"1.25.0 (before the fixes)":          "module m\n\ngo 1.25.0\n",
		"1.25.14 (the last 1.25)":            "module m\n\ngo 1.25.14\n",
		"1.26.0 (the first 1.26)":            "module m\n\ngo 1.26.0\n",
		"1.26.8 (one short)":                 "module m\n\ngo 1.26.8\n",
		"1.26 (no patch: accepts the first)": "module m\n\ngo 1.26\n",
		// Newer than the minimum, but without a patch it accepts the first release of that minor version, which carries
		// whatever was found in it afterwards. Only the rule that asks for the patch refuses this one.
		"1.27 (newer, but no patch)":     "module m\n\ngo 1.27\n",
		"a toolchain line that is older": "module m\n\ngo 1.26.9\n\ntoolchain go1.26.2\n",
		"no go directive":                "module m\n",
	}
	for name, mod := range bad {
		if len(checkGoMod(t, mod)) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	good := map[string]string{
		"exactly the minimum":     "module m\n\ngo 1.26.9\n",
		"a later patch":           "module m\n\ngo 1.26.10\n",
		"a later minor":           "module m\n\ngo 1.27.0\n",
		"a newer toolchain line":  "module m\n\ngo 1.26.9\n\ntoolchain go1.27.2\n",
		"the same toolchain line": "module m\n\ngo 1.26.9\n\ntoolchain go1.26.9\n",
	}
	for name, mod := range good {
		if p := checkGoMod(t, mod); len(p) != 0 {
			t.Errorf("%s was refused: %v", name, p)
		}
	}
}

// The Docker image is built from a Go image. A tag such as golang:1.26-alpine moves with the newest 1.26 and golang:1.25
// never gets this far, so the tag has to be one that is exactly a version that is new enough.
func TestDockerfileBuildsWithAGoThatIsNewEnough(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^FROM golang:(\d+\.\d+\.\d+)(?:-\S+)? AS build`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("the build stage must be `FROM golang:<major.minor.patch>... AS build`: a tag without the patch moves under you")
	}
	if !atLeast(t, m[1], minGo) {
		t.Errorf("the image builds with Go %s, older than %s", m[1], minGo)
	}
	gm := regexp.MustCompile(`(?m)^go (\S+)$`)
	mod, _ := os.ReadFile("go.mod")
	if g := gm.FindStringSubmatch(string(mod)); g != nil && !atLeast(t, m[1], g[1]) {
		t.Errorf("the image uses Go %s but go.mod asks for %s: the build would fetch another toolchain at build time", m[1], g[1])
	}
}

// The workflows take the Go version from go.mod, so one edit moves CI, the nightly build and the tests together. A
// hard-coded version in a workflow could fall behind it.
func TestWorkflowsTakeTheirGoFromGoMod(t *testing.T) {
	for _, f := range []string{".github/workflows/ci.yml", ".github/workflows/nightly.yml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if !strings.Contains(s, "go-version-file: go.mod") {
			t.Errorf("%s must set up Go with go-version-file: go.mod", f)
		}
		if regexp.MustCompile(`(?m)^\s*go-version:`).MatchString(s) {
			t.Errorf("%s pins a Go version by hand: it can fall behind go.mod", f)
		}
	}
}

// The documents say which Go a developer needs. Saying 1.25 when go.mod needs 1.26.9 sends a person to a toolchain that
// cannot build it, so the documents state the version go.mod asks for, and the one from which Go fetches it by itself.
func TestDocumentsSayWhichGoIsNeeded(t *testing.T) {
	mod, _ := os.ReadFile("go.mod")
	g := regexp.MustCompile(`(?m)^go (\S+)$`).FindStringSubmatch(string(mod))
	if g == nil {
		t.Fatal("no go directive")
	}
	for _, f := range []string{"README.md", "docs/OPERATING.md", "skills/securl/SKILL.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		flat := strings.Join(strings.Fields(string(b)), " ")
		if !strings.Contains(flat, "Go "+g[1]) {
			t.Errorf("%s must say that securl needs Go %s", f, g[1])
		}
		if !strings.Contains(flat, "GOTOOLCHAIN=local") {
			t.Errorf("%s must say that GOTOOLCHAIN=local turns the automatic download off", f)
		}
		if strings.Contains(flat, "Go 1.25 or newer") {
			t.Errorf("%s still says Go 1.25 is enough", f)
		}
	}
}
