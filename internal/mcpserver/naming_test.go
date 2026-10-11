package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Tools are named for what they act on: session_*, site_list, vault_*, archery_*. Nothing is named after the program's
// old name, and the verbs a person says ("log in") appear in descriptions, not in names.
func TestNoToolOrResourceIsNamedAfterTheOldProgram(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if tl.Name == "login" || strings.HasPrefix(tl.Name, "login_") || tl.Name == "logout" {
			t.Errorf("tool %q still carries the old name", tl.Name)
		}
	}
	rr, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rr.Resources {
		if !strings.HasPrefix(r.URI, "securl://") {
			t.Errorf("resource %q must live under securl://", r.URI)
		}
	}
	if len(rr.Resources) != 3 {
		t.Errorf("%d resources, want 3 (sites, sessions, policy)", len(rr.Resources))
	}
}

func TestEveryNextToolPointsAtAToolThatExists(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	have := map[string]bool{}
	for _, tl := range res.Tools {
		have[tl.Name] = true
	}
	for _, n := range []string{nextSessionWait, nextArcheryWait, nextVaultUnlock} {
		if !have[n] {
			t.Errorf("a result tells the agent to call %q, which is not a tool", n)
		}
	}
}

// What the model is told is as much part of the interface as the tool names. Every tool the instructions mention must
// exist, and no tool, resource or program name from before the rename may be left in them.
func TestInstructionsOnlyNameToolsThatExist(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	have := map[string]bool{}
	for _, tl := range res.Tools {
		have[tl.Name] = true
	}
	for _, word := range strings.FieldsFunc(instructions, func(r rune) bool {
		return !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		looksLikeATool := strings.HasPrefix(word, "session_") || strings.HasPrefix(word, "vault_") || strings.HasPrefix(word, "archery_") || strings.HasPrefix(word, "site_") || word == "request"
		if looksLikeATool && !have[word] && !instructionsMayMention[word] {
			t.Errorf("the instructions mention %q, which is not a tool", word)
		}
	}
	for _, name := range []string{toolSessionOpen, toolSessionWait, toolSiteList, toolVaultUnlock, toolVaultStatus} {
		if !strings.Contains(instructions, name) {
			t.Errorf("the instructions must teach the agent %q", name)
		}
	}
}

// Words that start like a tool name but are other things the instructions legitimately say (fields and error codes).
var instructionsMayMention = map[string]bool{
	"session_expired": true, "session_id": true, // error code, field
	"vault_locked": true, "vault_not_initialized": true, // error codes
	"archery_": true, // the wildcard "archery_*"
}

func TestInstructionsHaveNoOldNames(t *testing.T) {
	for _, old := range []string{"login_wait", "login_sites", "login_sessions", "logout", "login://", "Call login", "call login", "login is a gateway", "login starts"} {
		if strings.Contains(instructions, old) {
			t.Errorf("the instructions still contain %q", old)
		}
	}
	if !strings.Contains(instructions, "securl") {
		t.Error("the instructions say whose they are")
	}
}

func TestEveryToolDescriptionNamesOnlyRealTools(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	have := map[string]bool{}
	for _, tl := range res.Tools {
		have[tl.Name] = true
	}
	for _, tl := range res.Tools {
		for _, word := range strings.FieldsFunc(tl.Description, func(r rune) bool {
			return !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
		}) {
			if (strings.HasPrefix(word, "session_") || strings.HasPrefix(word, "vault_") || strings.HasPrefix(word, "site_")) && !have[word] && !instructionsMayMention[word] {
				t.Errorf("the description of %s names %q, which is not a tool", tl.Name, word)
			}
			if word == "login_wait" || word == "login_sites" || word == "login_sessions" {
				t.Errorf("the description of %s uses the old tool name %q", tl.Name, word)
			}
		}
	}
}

func TestInputDescriptionsUseTheNewToolNames(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, _ := cs.ListTools(context.Background(), nil)
	for _, tl := range res.Tools {
		raw, _ := json.Marshal(tl.InputSchema)
		if strings.Contains(string(raw), "login_sites") || strings.Contains(string(raw), "login_wait") {
			t.Errorf("%s: an input description still names an old tool: %s", tl.Name, raw)
		}
	}
}

func TestHintsAndErrorsPointAtRealTools(t *testing.T) {
	hints := map[string]string{
		"archery session expired": archerySessionHint,
		"unlock":                  unlockHintLocked,
	}
	for name, h := range hints {
		for _, old := range []string{"login_wait", "call login", "Call login"} {
			if strings.Contains(h, old) {
				t.Errorf("%s: %q", name, h)
			}
		}
	}
	if !strings.Contains(archerySessionHint, toolSessionOpen) || !strings.Contains(unlockHintLocked, toolVaultUnlock) {
		t.Errorf("hints must name the tools to call: %q / %q", archerySessionHint, unlockHintLocked)
	}
}

// The exemption list must not become a way to hide a stale tool name: a name that really was a tool and no longer is
// stays an error.
func TestTheAllowanceListDoesNotHideStaleToolNames(t *testing.T) {
	for _, stale := range []string{"session_login", "session_logout", "vault_open", "site_sessions", "archery_runsql", "login_wait", "session_renew"} {
		if instructionsMayMention[stale] {
			t.Errorf("%q must not be excused", stale)
		}
	}
}
