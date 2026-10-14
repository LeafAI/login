package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// skills/securl/SKILL.md is what an agent reads to set securl up and to use it. A command, tool, setting or field that
// is wrong in it sends the agent (and the person behind it) down a dead end, so every one of them is held to the source.

const skillFile = "skills/securl/SKILL.md"

func readSkill(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(skillFile)
	if err != nil {
		t.Fatalf("%s must exist: %v", skillFile, err)
	}
	return string(b)
}

func TestSkillHasTheFrontMatterAClientNeeds(t *testing.T) {
	s := readSkill(t)
	m := regexp.MustCompile(`(?s)\A---\nname: ([a-z0-9-]+)\ndescription: (.+?)\n---\n`).FindStringSubmatch(s)
	if m == nil {
		t.Fatal("the file must start with a front matter holding `name` and `description` and nothing else")
	}
	if m[1] != "securl" {
		t.Errorf("name = %q, want securl (the directory it lives in)", m[1])
	}
	// The description is what decides whether the skill is loaded at all: it must say what it is for and when to use it.
	if n := len(m[2]); n < 80 || n > 1024 {
		t.Errorf("description is %d characters, want 80..1024", n)
	}
	if !strings.Contains(strings.ToLower(m[2]), "use when") && !strings.Contains(strings.ToLower(m[2]), "use this") {
		t.Errorf("description must say when to use the skill: %q", m[2])
	}
}

func TestEveryToolTheSkillNamesExists(t *testing.T) {
	have := realTools(t)
	s := readSkill(t)
	notTools := map[string]bool{
		"session_expired": true, "vault_locked": true, "vault_not_initialized": true, "site_unreachable": true, "archery_error": true,
		"site_options": true,
	}
	for _, m := range toolish.FindAllStringSubmatch(s, -1) {
		if !have[m[1]] && !notTools[m[1]] {
			t.Errorf("the skill names the tool %q, which does not exist", m[1])
		}
	}
	// `request` has no prefix to match on, so the tools a skill has to teach are checked by name.
	for _, must := range []string{"vault_unlock", "vault_status", "session_open", "session_wait", "request", "session_list", "site_list"} {
		if !strings.Contains(s, "`"+must+"`") {
			t.Errorf("the skill must teach `%s`", must)
		}
	}
}

// Every `securl <command>` the skill tells somebody to type must be one the program has.
func TestEverySecurlCommandInTheSkillExists(t *testing.T) {
	known := map[string]bool{
		"config": true, "vault": true, "doctor": true, "page": true, "version": true,
	}
	sub := map[string]map[string]bool{
		"config": {"init": true, "site": true, "show": true, "get": true, "set": true, "unset": true, "totp": true, "path": true, "db": true},
		"vault":  {"init": true, "status": true, "passwd": true, "migrate": true},
	}
	siteSub := map[string]bool{"add": true, "custom": true, "list": true, "remove": true}
	totpSub := map[string]bool{"init": true, "code": true, "status": true, "on": true, "off": true}
	dbSub := map[string]bool{"add": true, "list": true, "remove": true}
	cmd := regexp.MustCompile("(?m)(?:^|[`$] *|\\| )securl ((?:[a-z]+)(?: [a-z]+)?(?: [a-z]+)?)")
	for _, m := range cmd.FindAllStringSubmatch(readSkill(t), -1) {
		w := strings.Fields(m[1])
		if !known[w[0]] {
			continue // prose such as "securl is ...", flags, or the server started with no command
		}
		if s, ok := sub[w[0]]; ok && len(w) > 1 && !s[w[1]] {
			t.Errorf("`securl %s` is not a command (securl %s has: %v)", m[1], w[0], keys(s))
		}
		if w[0] == "config" && len(w) > 2 && w[1] == "site" && !siteSub[w[2]] {
			t.Errorf("`securl %s`: no such site command", m[1])
		}
		if w[0] == "config" && len(w) > 2 && w[1] == "totp" && !totpSub[w[2]] {
			t.Errorf("`securl %s`: no such totp command", m[1])
		}
		if w[0] == "config" && len(w) > 2 && w[1] == "db" && !dbSub[w[2]] {
			t.Errorf("`securl %s`: no such db command", m[1])
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A setting named in the skill with `securl config set <key>` must be one the program accepts, or the person gets an
// error on the first thing the skill told them to do.
func TestEverySettingTheSkillSetsExists(t *testing.T) {
	b, err := os.ReadFile("internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// The key is section.name; for aliases and roots the part after the section is a host name, which has dots of its
	// own, so only the first two segments are checked. For the maps (aliases, roots, site_options) the section is.
	set := regexp.MustCompile("securl config (?:set|get|unset) ([a-z_]+(?:\\.[a-z_<>]+)+)")
	maps := map[string]bool{"aliases": true, "roots": true, "site_options": true}
	for _, m := range set.FindAllStringSubmatch(readSkill(t), -1) {
		parts := strings.Split(m[1], ".")
		key := parts[len(parts)-1]
		if maps[parts[0]] {
			key = parts[0]
		} else {
			key = parts[1]
		}
		if !strings.Contains(src, "yaml:\""+key+"\"") {
			t.Errorf("`securl config set %s`: the setting %q is not in the configuration", m[1], key)
		}
	}
}

func TestSkillSaysWhatTheAgentMustNeverDo(t *testing.T) {
	s := strings.ToLower(readSkill(t))
	for _, must := range []string{
		"never ask the user for a password", // the one rule the whole design rests on
		"passphrase",                        // the vault passphrase is typed by a person, not passed through a tool
		"force_refresh",                     // how a dead session is renewed
		"cookie",                            // and that none may be supplied
		"securl vault init",                 // the first thing to do
	} {
		if !strings.Contains(s, must) {
			t.Errorf("the skill must say %q", must)
		}
	}
}

// The first thing a person does is install, and most of them have no Go toolchain, so the skill installs the nightly
// build. Every address and file name in it must be the one the nightly workflow publishes and the README documents, or the
// first command is a 404.
// section returns the text from the heading that starts with from up to the heading that starts with to. The install and
// the update teach the same commands, so a check that looked at the whole file would be satisfied by the one that was
// left right when the other was broken.
func section(t *testing.T, from, to string) string {
	t.Helper()
	s := readSkill(t)
	i := strings.Index(s, from)
	j := strings.Index(s, to)
	if i < 0 || j < i {
		t.Fatalf("the skill must have %q before %q", from, to)
	}
	return s[i:j]
}

// The two ways to get securl are told apart by the machine, not ranked: a person without Go (or with one older than 1.21, which cannot fetch the toolchain it needs)
// downloads the nightly build, a developer who already builds Go programs runs `go install`. The skill has to say how to
// tell which one applies, and give each its own complete instructions.
func installText(t *testing.T) (all, nightly, goInstall string) {
	t.Helper()
	all = section(t, "## 1. Install", "## 2. Update")
	n := strings.Index(all, "### 1a.")
	g := strings.Index(all, "### 1b.")
	b := strings.Index(all, "### Both ways")
	if n < 0 || g < n || b < g {
		t.Fatal("the Install section must have 1a (the nightly), then 1b (go install), then a Both ways part")
	}
	return all, all[n:g], all[g:b]
}

// The commands a person types to get the nightly, in the order they type them. The install and the update each carry the
// whole list.
var nightlyCommands = []string{
	"curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz",
	"curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS",
	"shasum -a 256 --ignore-missing -c SHA256SUMS",
	"tar -xzf securl_<os>_<arch>.tar.gz",
	"install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl",
	"securl version",
}

func TestInstallTellsYouHowToChooseAndGivesEachWayInFull(t *testing.T) {
	all, nightly, goInstall := installText(t)
	flat := strings.Join(strings.Fields(all), " ")
	// The choice is made by what is on the machine, and `go version` is how to find out.
	for _, want := range []string{"go version", "No Go", "Go 1.21 or newer", "download the nightly build", "go install"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the choice between the two ways must mention %q", want)
		}
	}
	// Each way is complete on its own.
	last := -1
	for _, cmd := range nightlyCommands {
		at := strings.Index(nightly, cmd)
		if at < 0 {
			t.Errorf("1a must contain the command %q", cmd)
			continue
		}
		if at < last {
			t.Errorf("1a: %q is out of order", cmd)
		}
		last = at
	}
	if !strings.Contains(goInstall, "go install github.com/LeafAI/securl@latest") {
		t.Error("1b must give the developer `go install github.com/LeafAI/securl@latest`: that is the whole install for them")
	}
	if strings.Contains(nightly, "go install ") && !strings.Contains(nightly, "go install` copy") {
		t.Error("1a is for a machine without Go: it must not tell the person to run go install")
	}
	// The way that needs Go says so; the way that does not, does not.
	if strings.Contains(strings.Join(strings.Fields(nightly), " "), "You need Go") {
		t.Error("the nightly needs no Go toolchain: do not say that it does")
	}
	if !strings.Contains(strings.Join(strings.Fields(goInstall), " "), "newest `master`") {
		t.Error("1b must say that @latest is the newest master, because the repository has no release tags")
	}
}

// The Go developer runs the one command on their own machine; it has to be the real module path (case sensitive), and the
// skill must not push a person without Go towards it.
func TestGoInstallUsesTheRealModuleAndIsNeverMistakenForTheNightly(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^module (\S+)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("go.mod has no module line")
	}
	s := readSkill(t)
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "go install ") && !strings.HasPrefix(line, "go install "+m[1]+"@") {
			t.Errorf("not this module: %s", line)
		}
	}
	if !strings.Contains(s, "go install "+m[1]+"@latest") {
		t.Errorf("the skill must show `go install %s@latest`", m[1])
	}
	_, _, goInstall := installText(t)
	flat := strings.Join(strings.Fields(goInstall), " ")
	// What it prints is not what the nightly prints, and a person who has both must be able to tell them apart.
	for _, want := range []string{"0.1.0", "@<commit>", "GOPROXY=direct"} {
		if !strings.Contains(flat, want) {
			t.Errorf("1b must mention %q", want)
		}
	}
}

// Two copies of securl on one machine is the usual reason an update "did not work": the other one comes first on PATH. The
// skill says how to see which one runs, once, for both ways, and what each way's version looks like.
func TestInstallSaysWhatToDoWhenAnotherCopyComesFirst(t *testing.T) {
	all, _, _ := installText(t)
	b := strings.Index(all, "### Both ways")
	both := strings.Join(strings.Fields(all[b:]), " ")
	for _, want := range []string{"command -v securl", "~/go/bin", "~/.local/bin", "nightly-<date>-<commit>", "0.1.0"} {
		if !strings.Contains(both, want) {
			t.Errorf("the part for both ways must mention %q", want)
		}
	}
}

func TestSkillInstallsTheNightlyBuildAndChecksIt(t *testing.T) {
	_, nightly, _ := installText(t)
	flat := strings.Join(strings.Fields(nightly), " ")
	base := "https://github.com/LeafAI/securl/releases/download/nightly/"
	for _, want := range []string{
		base + "securl_<os>_<arch>.tar.gz", // the name that never changes, so the command never goes stale
		base + "SHA256SUMS",
		"shasum -a 256 --ignore-missing -c SHA256SUMS", // the check, written so that one downloaded file is enough
		"install -m 0755",
		"nightly-<date>-<commit>", // what the version looks like, so a person can tell the install worked
		"certutil",                // Windows has no shasum
	} {
		if !strings.Contains(nightly, want) {
			t.Errorf("1a must contain %q", want)
		}
	}
	if strings.Contains(readSkill(t), "releases/latest") {
		t.Error("releases/latest never points at the nightly pre-release: use releases/download/nightly")
	}
	// Why the SHA-256 and not the SHA-1 is the one to run: the honest reason, stated where the check is.
	if !strings.Contains(flat, "SHA1SUMS") || !strings.Contains(flat, "SHA-1 collisions can be made") {
		t.Error("1a must say why SHA256SUMS is the one to rely on, and that SHA1SUMS only catches a damaged download")
	}
	if !strings.Contains(flat, "not a tested release") {
		t.Error("1a must say that the nightly is the newest master and not a tested release")
	}
	// The names must be the ones the workflow and the script produce.
	script, err := os.ReadFile(releaseScript)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"securl_${os}_${arch}.", "SHA256SUMS", "SHA1SUMS"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("the script no longer produces %q, which the skill tells people to download", want)
		}
	}
}

// An update follows the install: the same download again for the one who downloaded, `go install` again for the one who
// built, and for both a restart that locks the vault. The only release is the nightly, which has no release notes.
func TestUpdateHasTheSameTwoWaysAndWarnsAboutTheVault(t *testing.T) {
	update := section(t, "## 2. Update", "## 3. Set up")
	last := -1
	for _, cmd := range nightlyCommands {
		at := strings.Index(update, cmd)
		if at < 0 {
			t.Errorf("the Update section must contain the command %q", cmd)
			continue
		}
		if at < last {
			t.Errorf("Update: %q is out of order", cmd)
		}
		last = at
	}
	flat := strings.Join(strings.Fields(update), " ")
	for _, want := range []string{"go install github.com/LeafAI/securl@latest", "go version -m", "locks the vault", "passphrase", "the way you installed"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the Update section must mention %q", want)
		}
	}
	if strings.Contains(strings.ToLower(flat), "release notes") {
		t.Error("there are no release notes: the nightly is the only release")
	}
	if strings.Contains(update, "shasum -a 1 ") || strings.Contains(update, "releases/latest") {
		t.Error("the update must check with SHA-256 and use the nightly address")
	}
	if regexp.MustCompile(`securl_v?\d`).MatchString(update) {
		t.Error("the file name must not carry a version, or the command goes stale")
	}
}

// An argument the skill names for a tool must be a field that tool takes. The names are read from the input types, so
// a renamed or misspelt field in the skill fails here instead of being refused by the server in front of the user.
func TestEveryFieldTheSkillNamesIsOneTheToolsTake(t *testing.T) {
	b, err := os.ReadFile("internal/mcpserver/types.go")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, m := range regexp.MustCompile("`json:\"([a-z_]+)[,\"]").FindAllStringSubmatch(string(b), -1) {
		fields[m[1]] = true
	}
	cfg, err := os.ReadFile("internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	// Words in backticks that are not arguments: states, values, answers, and error codes.
	notArgs := map[string]bool{
		"not_initialized": true, "waiting_for": true, "next_tool": true, "total_bytes": true,
		"human_timeout": true, "user_rejected": true, "bad_credentials": true, "rate_limited": true, "host_not_allowed": true,
		"tunnel_unavailable": true, "notify_failed": true, "invalid_argument": true, "no_session": true, "vault_locked": true,
		"vault_not_initialized": true, "session_expired": true, "site_unreachable": true, "request_not_allowed": true,
		"unknown_target": true, "database_not_allowed": true, "target_read_only": true, "not_read_only": true, "too_many_rows": true,
		"statement_timeout": true, "ddl_disabled": true, "sql_error": true,
		// Values of a database target's mode.
		"read_only": true, "read_write": true,
		// Parameters of the sites' own APIs, used as examples of what goes into `query`.
		"per_page": true,
	}
	skill := readSkill(t)
	for _, m := range regexp.MustCompile("`([a-z]+(?:_[a-z]+)+)`").FindAllStringSubmatch(skill, -1) {
		name := m[1]
		switch {
		case fields[name], notArgs[name], toolish.MatchString(m[0]):
		case strings.Contains(string(cfg), "yaml:\""+name+"\""):
		case strings.HasSuffix(name, "_id"):
		default:
			t.Errorf("the skill names %q, which is neither an argument of a tool, a setting nor an error code", name)
		}
	}
	// What a dead session needs is taught twice; it must be the real field name both times.
	if n := strings.Count(skill, "force_refresh"); n < 2 {
		t.Errorf("force_refresh must be taught where a session dies and in the table of failures (found %d)", n)
	}
	for _, f := range []string{"force_refresh", "unlock_id", "follow_redirects", "max_response_bytes", "resource_group", "reason"} {
		if !fields[f] {
			t.Errorf("types.go no longer has the field %q the skill teaches", f)
		}
		if !strings.Contains(skill, f) {
			t.Errorf("the skill no longer teaches %q", f)
		}
	}
}

// The description decides whether a client loads the skill, so it has to keep saying what the skill covers.
func TestSkillDescriptionCoversTheFourJobs(t *testing.T) {
	m := regexp.MustCompile(`(?s)\A---\nname: [a-z0-9-]+\ndescription: (.+?)\n---\n`).FindStringSubmatch(readSkill(t))
	if m == nil {
		t.Fatal("no front matter")
	}
	d := strings.ToLower(m[1])
	for _, w := range []string{"install", "update", "set up", "use", "mcp", "vault_locked"} {
		if !strings.Contains(d, w) {
			t.Errorf("the description must mention %q: %q", w, m[1])
		}
	}
}

// The skill is read by an agent that does what it says. If it ever told the agent to ask for a secret in the chat, or
// to hand one to a tool, that would undo the design, so the sentences that could say so are held to what is true: a
// secret is typed by the person on the page, and no tool takes one.
func TestSkillNeverTeachesAnAgentToHandleASecret(t *testing.T) {
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(ask|tell|have|get)\b[^.\n]{0,40}\buser\b[^.\n]{0,40}\b(for|to (give|send|share|paste|type[^.\n]{0,20}(here|in the chat)))\b[^.\n]{0,30}\b(passphrase|password|totp|code|token|cookie)\b`),
		regexp.MustCompile(`(?i)\b(pass|send|give|supply|provide|put|hand)\b[^.\n]{0,40}\b(passphrase|password|totp code)\b[^.\n]{0,40}\b(to|in|into|as|with)\b[^.\n]{0,30}\b(tool|argument|parameter|vault_unlock|session_open|request)\b`),
		regexp.MustCompile(`(?i)\bwith the (passphrase|password)\b[^.\n]{0,40}\b(user|chat|gives|provides)\b`),
		regexp.MustCompile(`(?i)\bpassphrase argument\b`),
		regexp.MustCompile(`(?i)\b(passphrase|password)\b[^.\n]{0,30}\bin the chat\b`),
	}
	// A sentence that forbids it is the rule itself: "never ask the user for a password ... in the chat".
	allowed := regexp.MustCompile(`(?i)\b(never|not|no|cannot|does not|do not|don't|refused|must not)\b`)
	for i, line := range strings.Split(readSkill(t), "\n") {
		for _, re := range forbidden {
			if re.MatchString(line) && !allowed.MatchString(line) {
				t.Errorf("%s:%d teaches handling a secret: %s", skillFile, i+1, strings.TrimSpace(line))
			}
		}
	}
	// Line breaks in the Markdown are not part of the sentence.
	s := strings.ToLower(strings.Join(strings.Fields(readSkill(t)), " "))
	// The statements that make the rule checkable: who types a secret and where, the rule, and why it cannot be broken.
	for _, must := range []string{
		"types the passphrase on that page",
		"never ask the user for a password, a totp code or the vault passphrase in the chat",
		"a tool that takes a passphrase does not exist",
	} {
		if !strings.Contains(s, must) {
			t.Errorf("the skill must keep saying: %q", must)
		}
	}
}
