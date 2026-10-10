// Package browsertest drives the static login page in headless Chromium (Playwright via Node).
// It is for tests only; every helper skips the test when the tooling is not installed.
package browsertest

import (
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

//go:embed e2e.js
var script []byte

var (
	once     sync.Once
	nodePath string
	skip     string
)

func detect() {
	if _, err := exec.LookPath("node"); err != nil {
		skip = "node not available"
		return
	}
	candidates := []string{os.Getenv("NODE_PATH"), "/opt/node22/lib/node_modules"}
	if out, err := exec.Command("npm", "root", "-g").Output(); err == nil {
		candidates = append(candidates, strings.TrimSpace(string(out)))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		cmd := exec.Command("node", "-e", "require('playwright').chromium.executablePath()")
		cmd.Env = append(os.Environ(), "NODE_PATH="+c)
		if cmd.Run() == nil {
			nodePath = c
			return
		}
	}
	skip = "playwright not available"
}

// Require skips the test unless Node, Playwright and Chromium are usable.
func Require(t *testing.T) {
	t.Helper()
	once.Do(detect)
	if skip != "" {
		t.Skip(skip)
	}
}

// Result is what the page showed after the scripted interaction.
type Result struct {
	Fpr        string   `json:"fpr"`
	HashAfter  string   `json:"hashAfter"`
	Msg        string   `json:"msg"`
	MainHidden bool     `json:"mainHidden"`
	Errors     []string `json:"errors"`
	// Imgs describes the captcha images the page rendered (naturalWidth > 0 means the image loaded).
	Imgs []struct {
		Src string `json:"src"`
		W   int    `json:"w"`
	} `json:"imgs"`
}

// Drive opens pageDir/index.html with the given link fragment and acts as the human.
// action is "submit" (values = JSON of field values), "reject" (reason optional) or "mismatch"
// (expects the page to refuse the link).
func Drive(t *testing.T, pageDir, fragment, action, values, reason string) Result {
	t.Helper()
	Require(t)
	js := filepath.Join(t.TempDir(), "e2e.js")
	if err := os.WriteFile(js, script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", js, pageDir, fragment, action, values, reason)
	cmd.Env = append(os.Environ(), "NODE_PATH="+nodePath)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("browser run failed: %v\n%s", err, stderr)
	}
	var r Result
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("bad browser output %q: %v", out, err)
	}
	return r
}

// Fragment returns the part of a link after '#'.
func Fragment(link string) string { return link[strings.Index(link, "#")+1:] }
