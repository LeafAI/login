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
	Fpr         string   `json:"fpr"`
	Code        string   `json:"code"`  // the verification code shown to the human
	Title       string   `json:"title"` // document title
	HashAfter   string   `json:"hashAfter"`
	Msg         string   `json:"msg"`
	MainHidden  bool     `json:"mainHidden"`
	PasteHidden bool     `json:"pasteHidden"`
	Errors      []string `json:"errors"`
	// FactorShown says whether the page asked for a second-factor (sealing) code.
	FactorShown bool `json:"factorShown"`
	// UnlockShown / FormShown say which part of the page is visible (the unlock box, or the credential form).
	UnlockShown bool `json:"unlockShown"`
	FormShown   bool `json:"formShown"`
	// RequestsWhileLocked lists every network request the page made while it was locked (there must be none).
	RequestsWhileLocked []string `json:"requestsWhileLocked"`
	// UnlockLeft is what is still in the unlock box after the page has unlocked.
	UnlockLeft string `json:"unlockLeft"`
	// PageText is the visible text of the page, to check that nothing secret is shown while it is locked.
	PageText string `json:"pageText"`
	// Derived holds the keys the page derives from fixed inputs (action "derive"), as hex.
	Derived struct {
		Stretched string `json:"stretched"`
		PlainKey  string `json:"plainKey"`
		Key       string `json:"key"`
		// the link layer
		LinkStretched string `json:"linkStretched"`
		LinkSlotKey   string `json:"linkSlotKey"`
	} `json:"derived"`
	// RequestBody is what the page posted to /submit, as it went over the wire.
	RequestBody string `json:"requestBody"`
	// Imgs describes the captcha images the page rendered (naturalWidth > 0 means the image loaded).
	Imgs []struct {
		Src string `json:"src"`
		W   int    `json:"w"`
	} `json:"imgs"`
	Autocomplete           []string `json:"autocomplete"`
	SubmitDisabledBefore   bool     `json:"submitDisabledBefore"`    // before the verification box is ticked
	SubmitDisabledAfter    bool     `json:"submitDisabledAfter"`     // after ticking it
	SubmitDisabledUnticked bool     `json:"submitDisabledUnchecked"` // after unticking again
	FieldsDisabled         []bool   `json:"fieldsDisabled"`
	RejectBoxHidden        bool     `json:"reasonHiddenAfter"`
	Violated               bool     `json:"violated"`     // a securitypolicyviolation event fired
	OtherBlocked           bool     `json:"otherBlocked"` // fetch to a foreign origin was refused
}

// Drive opens pageDir/index.html with the given link fragment and acts as the human.
// action is "submit" (values = JSON of field values), "reject" (reason optional), "refuse" (the page must
// refuse the link), "probe" (inspect state and the verification gate), "csp" (check that connections are
// locked to the tunnel origin), "inert" (the page must stay dead, e.g. after an integrity failure) or "emptysubmit" (press Submit with empty fields after opening the reject box).
func Drive(t *testing.T, pageDir, fragment, action, values, reason string) Result {
	t.Helper()
	return drive(t, pageDir, fragment, action, values, reason, "")
}

func drive(t *testing.T, pageDir, fragment, action, values, reason, openAs string) Result {
	t.Helper()
	Require(t)
	js := filepath.Join(t.TempDir(), "e2e.js")
	if err := os.WriteFile(js, script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", js, pageDir, fragment, action, values, reason, openAs)
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

// DriveAt is like Drive but opens a page served over HTTP (pageURL, e.g. http://127.0.0.1:8080/) instead of a
// local file, which exercises the cross-origin calls a hosted page makes.
func DriveAt(t *testing.T, pageURL, fragment, action, values, reason string) Result {
	t.Helper()
	t.Setenv("PAGE_HTTP_URL", pageURL)
	return drive(t, "", fragment, action, values, reason, "http")
}

// Fragment returns the part of a link after '#'.
func Fragment(link string) string { return link[strings.Index(link, "#")+1:] }
