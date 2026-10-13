package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A person without a Go toolchain installs securl from the files the nightly build publishes. A build that is missing a
// platform, whose checksum file does not match its archives, or whose workflow can publish from a pull request or a
// stray branch, fails that person at the first step, so the workflow and the scripts it runs are held to what they
// promise. There is exactly one release, tagged `nightly`, and nothing here describes any other.

const (
	nightlyWorkflow = ".github/workflows/nightly.yml"
	releaseScript   = "scripts/release.sh"
	publishScript   = "scripts/publish-nightly.sh"
	nightlyVersion  = "nightly-20261012-1a2b3c4"
	nightlyCommit   = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
)

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		If          string            `yaml:"if"`
		Needs       any               `yaml:"needs"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Name string            `yaml:"name"`
			If   string            `yaml:"if"`
			Uses string            `yaml:"uses"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
			With map[string]any    `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) (workflow, string) {
	t.Helper()
	b, err := os.ReadFile(nightlyWorkflow)
	if err != nil {
		t.Fatalf("%s must exist: %v", nightlyWorkflow, err)
	}
	var w workflow
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("%s is not valid YAML: %v", nightlyWorkflow, err)
	}
	return w, string(b)
}

func TestThereIsNoReleaseWorkflowOtherThanTheNightlyOne(t *testing.T) {
	if _, err := os.Stat(".github/workflows/release.yml"); err == nil {
		t.Error("only the nightly build is published: .github/workflows/release.yml must not exist")
	}
	_, raw := loadWorkflow(t)
	if strings.Contains(raw, "tags:") {
		t.Error("the nightly workflow must not run on tags: no tag other than `nightly` is ever made")
	}
}

func TestNightlyRunsOnASchedulePullRequestsAndByHandOnly(t *testing.T) {
	w, _ := loadWorkflow(t)
	for _, trigger := range []string{"schedule", "pull_request", "workflow_dispatch"} {
		if _, ok := w.On[trigger]; !ok {
			t.Errorf("the workflow must run on %s", trigger)
		}
	}
	if _, ok := w.On["push"]; ok {
		t.Error("a push must not run a build that can publish")
	}
	sched, _ := w.On["schedule"].([]any)
	if len(sched) != 1 {
		t.Fatalf("one schedule expected, got %v", sched)
	}
	cron, _ := sched[0].(map[string]any)["cron"].(string)
	if !regexp.MustCompile(`^\d+ \d+ \* \* \*$`).MatchString(cron) {
		t.Errorf("cron %q must run once a day", cron)
	}
}

// Publishing is a separate job that only runs when the first job decided a master build should be published, so a pull
// request or another branch builds and checks but never touches the release.
func TestOnlyAMasterBuildThatTheFirstJobApprovedIsPublished(t *testing.T) {
	w, raw := loadWorkflow(t)
	pub, ok := w.Jobs["publish"]
	if !ok {
		t.Fatal("there must be a publish job")
	}
	if pub.If != "needs.build.outputs.publish == 'true'" {
		t.Errorf("publish must run only when build approved it, if: %q", pub.If)
	}
	if pub.Needs != "build" {
		t.Errorf("publish must wait for build, needs: %v", pub.Needs)
	}
	// What decides: master, and a scheduled or manual run. A pull request must never reach `publish=true`.
	for _, want := range []string{`"$REF" = "refs/heads/master"`, `"$EVENT" = "schedule"`, `"$EVENT" = "workflow_dispatch"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("the decision must test %s", want)
		}
	}
	if strings.Contains(raw, "pull_request\" ]") || strings.Contains(raw, "= \"pull_request\"") {
		t.Error("the decision must not let a pull request publish")
	}
}

// A night in which master did not move does not replace the release: the date in its name would change and nothing else.
// A manual run always publishes, so a person can refresh it.
func TestANightWithNoNewCommitBuildsNothing(t *testing.T) {
	w, raw := loadWorkflow(t)
	if !strings.Contains(raw, `git/ref/tags/nightly`) || !strings.Contains(raw, "publish=skip") {
		t.Error("the decision step must compare the nightly tag with the commit and set publish=skip when they are equal")
	}
	scheduleOnly := regexp.MustCompile(`"\$publish" = true \] && \[ "\$EVENT" = "schedule" \]`)
	if !scheduleOnly.MatchString(raw) {
		t.Error("only a scheduled run may skip; a manual run always publishes")
	}
	skipped := map[string]bool{"Test": false, "Build, package and checksum": false, "Verify the checksums the way a user will": false}
	for _, s := range w.Jobs["build"].Steps {
		if _, ok := skipped[s.Name]; ok {
			skipped[s.Name] = s.If == "steps.decide.outputs.publish != 'skip'"
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact") && s.If != "steps.decide.outputs.publish != 'skip'" {
			t.Errorf("the upload must be skipped too, if: %q", s.If)
		}
	}
	for name, ok := range skipped {
		if !ok {
			t.Errorf("step %q must not run when the night is skipped", name)
		}
	}
}

// The token is read-only everywhere except the one job that replaces the release, so a step that is compromised in a
// build cannot write to the repository.
func TestNightlyTokenIsReadOnlyExceptWhereTheReleaseIsReplaced(t *testing.T) {
	w, _ := loadWorkflow(t)
	if got := w.Permissions["contents"]; got != "read" {
		t.Errorf("workflow-level contents permission = %q, want read", got)
	}
	for name, p := range w.Permissions {
		if p == "write" {
			t.Errorf("workflow-level permission %s is write", name)
		}
	}
	if got := w.Jobs["build"].Permissions; len(got) != 0 {
		t.Errorf("the build job must not widen the token: %v", got)
	}
	if got := w.Jobs["publish"].Permissions["contents"]; got != "write" {
		t.Errorf("publish needs contents: write to replace the release, got %q", got)
	}
}

// Both checksum files are verified the way a user will do it, in the job that built them and again before publishing:
// what is published is what was checked.
func TestNightlyChecksBothChecksumFilesBeforeAndAfterTheHandOver(t *testing.T) {
	_, raw := loadWorkflow(t)
	if n := strings.Count(raw, "sha1sum --check --strict SHA1SUMS"); n != 2 {
		t.Errorf("SHA1SUMS must be checked in build and in publish, found %d checks", n)
	}
	if n := strings.Count(raw, "sha256sum --check --strict SHA256SUMS"); n != 2 {
		t.Errorf("SHA256SUMS must be checked in build and in publish, found %d checks", n)
	}
}

func TestNightlyTestsBeforeItBuildsAndPublishesWhatItBuilt(t *testing.T) {
	w, _ := loadWorkflow(t)
	var order []string
	for _, s := range w.Jobs["build"].Steps {
		switch {
		case strings.Contains(s.Run, "go test"):
			order = append(order, "test")
		case strings.Contains(s.Run, "scripts/release.sh"):
			order = append(order, "build")
		case strings.HasPrefix(s.Uses, "actions/upload-artifact"):
			order = append(order, "upload")
		}
	}
	if strings.Join(order, ",") != "test,build,upload" {
		t.Errorf("build job order = %v, want test, build, upload", order)
	}
	var download, publish, checkout bool
	for _, s := range w.Jobs["publish"].Steps {
		download = download || strings.HasPrefix(s.Uses, "actions/download-artifact")
		publish = publish || strings.Contains(s.Run, "scripts/publish-nightly.sh")
		checkout = checkout || strings.HasPrefix(s.Uses, "actions/checkout")
	}
	if !download || !publish || !checkout {
		t.Errorf("publish must fetch the scripts, download what build made and publish it, not build again (download=%v publish=%v checkout=%v)", download, publish, checkout)
	}
}

// Actions are pinned to a major version at least: a floating ref such as @main runs whatever is there on the night.
func TestNightlyActionsAreVersioned(t *testing.T) {
	w, _ := loadWorkflow(t)
	for job, j := range w.Jobs {
		for _, s := range j.Steps {
			if s.Uses == "" {
				continue
			}
			if !regexp.MustCompile(`@v\d+(\.\d+)*$|@[0-9a-f]{40}$`).MatchString(s.Uses) {
				t.Errorf("job %s uses %q without a version", job, s.Uses)
			}
		}
	}
}

// The version is made from the date and the commit, and a branch or tag name, which a person chooses, never reaches a
// script. A GitHub expression carrying such text may appear in `env:` but never inside a script.
func TestNightlyNeverSplicesGitHubExpressionsIntoAShellScript(t *testing.T) {
	w, _ := loadWorkflow(t)
	expr := regexp.MustCompile(`\$\{\{.*?\}\}`)
	for job, j := range w.Jobs {
		for _, s := range j.Steps {
			if m := expr.FindString(s.Run); m != "" {
				t.Errorf("job %s step %q splices %s into a script: pass it through env instead", job, s.Name, m)
			}
		}
	}
	_, raw := loadWorkflow(t)
	for _, name := range []string{"github.ref_name", "github.head_ref", "GITHUB_REF_NAME", "GITHUB_HEAD_REF", "github.event.pull_request.title",
		"github.event.head_commit.message"} {
		if strings.Contains(raw, name) {
			t.Errorf("the workflow must not use %s: a person chooses it, and the version is the date and the commit", name)
		}
	}
}

// The version is built from the date in UTC and the first seven characters of the commit, and nothing else.
func TestNightlyVersionIsTheDateAndTheCommit(t *testing.T) {
	_, raw := loadWorkflow(t)
	if !strings.Contains(raw, `version="nightly-$(date -u +%Y%m%d)-${SHA:0:7}"`) {
		t.Error("the version must be made from the UTC date and the first seven characters of the commit")
	}
	// Assignments only: `echo "version=$version"` passes the value on and does not make one.
	if n := len(regexp.MustCompile(`(?m)^\s*version=`).FindAllString(raw, -1)); n != 1 {
		t.Errorf("the version is made in one place, found %d assignments", n)
	}
}

func scriptTargets(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(releaseScript)
	if err != nil {
		t.Fatalf("%s must exist: %v", releaseScript, err)
	}
	m := regexp.MustCompile(`targets=\(([^)]*)\)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("the script has no targets list")
	}
	return strings.Fields(m[1])
}

func TestReleaseCoversTheSixPlatformsPeopleRunAnMCPServerOn(t *testing.T) {
	got := strings.Join(scriptTargets(t), " ")
	for _, want := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"} {
		if !strings.Contains(got, want) {
			t.Errorf("platform %s is missing from %q", want, got)
		}
	}
}

// Every platform in the list must be one the Go toolchain can build, or the build fails on the night.
func TestEveryReleaseTargetBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("cross compiles six binaries")
	}
	for _, target := range scriptTargets(t) {
		parts := strings.SplitN(target, "/", 2)
		out := filepath.Join(t.TempDir(), "securl")
		cmd := exec.Command("go", "build", "-trimpath", "-o", out, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+parts[0], "GOARCH="+parts[1])
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s does not build: %v\n%s", target, err, b)
		}
	}
}

func needTools(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds six binaries")
	}
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	for _, tool := range []string{"bash", "tar", "zip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// buildRelease runs the script for real into a fresh directory and returns it.
func buildRelease(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dist")
	if b, err := exec.Command("bash", releaseScript, dir, nightlyVersion).CombinedOutput(); err != nil {
		t.Fatalf("release.sh failed: %v\n%s", err, b)
	}
	return dir
}

// The script is run for real: it must produce one archive per platform, a checksum line for each, and files a user can
// verify with the tool they have.
func TestReleaseScriptProducesVerifiableFiles(t *testing.T) {
	needTools(t)
	sum := "sha1sum"
	sumArgs := []string{"--check", "--strict"}
	if _, err := exec.LookPath("sha1sum"); err != nil {
		if _, err := exec.LookPath("shasum"); err != nil {
			t.Skip("neither sha1sum nor shasum is installed")
		}
		sum, sumArgs = "shasum", []string{"-a", "1", "-c"}
	}
	dir := buildRelease(t)
	var archives []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "securl_"+nightlyVersion+"_") {
			archives = append(archives, e.Name())
		}
	}
	if len(archives) != len(scriptTargets(t)) {
		t.Fatalf("%d archives for %d targets: %v", len(archives), len(scriptTargets(t)), archives)
	}
	for _, a := range archives {
		isWin := strings.Contains(a, "_windows_")
		if isWin != strings.HasSuffix(a, ".zip") || !isWin && !strings.HasSuffix(a, ".tar.gz") {
			t.Errorf("%s: Windows gets a .zip, the others a .tar.gz", a)
		}
	}
	for _, name := range []string{"SHA1SUMS", "SHA256SUMS"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		// Each platform is published under a versioned and an unversioned name (see the test for the second).
		if len(lines) != 2*len(archives) {
			t.Errorf("%s has %d lines for %d archives, want a line for each of the two names", name, len(lines), len(archives))
		}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) != 2 || strings.Contains(f[1], "/") {
				t.Errorf("%s: %q must be `<digest>  <bare file name>`", name, l)
			}
			want := 40
			if name == "SHA256SUMS" {
				want = 64
			}
			if len(f) == 2 && len(f[0]) != want {
				t.Errorf("%s: digest %q is %d characters, want %d", name, f[0], len(f[0]), want)
			}
		}
	}
	// What the user installs says which build it is: `securl version` must print the version the files are named for.
	// Only the binary for this machine can be run here.
	own := "securl_" + nightlyVersion + "_" + runtime.GOOS + "_" + runtime.GOARCH
	var packed string
	for _, a := range archives {
		if strings.HasPrefix(a, own+".") {
			packed = a
		}
	}
	if packed == "" {
		t.Logf("no archive for %s/%s, so the version is not run", runtime.GOOS, runtime.GOARCH)
	} else if !strings.HasSuffix(packed, ".zip") {
		unpack := t.TempDir()
		if b, err := exec.Command("tar", "-xzf", filepath.Join(dir, packed), "-C", unpack).CombinedOutput(); err != nil {
			t.Fatalf("a user cannot unpack %s: %v\n%s", packed, err, b)
		}
		out, err := exec.Command(filepath.Join(unpack, own, "securl"), "version").CombinedOutput()
		if err != nil {
			t.Fatalf("the unpacked binary does not run: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "securl "+nightlyVersion+" ") {
			t.Errorf("`securl version` = %q, want it to say %s", strings.TrimSpace(string(out)), nightlyVersion)
		}
		for _, f := range []string{"README.md", "THIRD_PARTY_NOTICES.md"} {
			if _, err := os.Stat(filepath.Join(unpack, own, f)); err != nil {
				t.Errorf("the archive lacks %s: a user needs the licences of what is inside", f)
			}
		}
	}
	check := exec.Command(sum, append(sumArgs, "SHA1SUMS")...)
	check.Dir = dir
	if b, err := check.CombinedOutput(); err != nil {
		t.Errorf("a user's own `%s` rejects the files: %v\n%s", sum, err, b)
	}
	// Damage one archive: the check must fail, or it checks nothing.
	victim := filepath.Join(dir, archives[0])
	data, _ := os.ReadFile(victim)
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(victim, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := check.Run(); err == nil {
		t.Error("a damaged archive passed the checksum")
	}
}

// `releases/download/nightly/<name>` needs a name that does not change from night to night. The versioned archives are
// kept (they say which build they are), and each is published a second time under a name without the version, so that
// a person without Go can type one command that never goes stale.
func TestReleaseAlsoPublishesEachArchiveUnderAnUnversionedName(t *testing.T) {
	needTools(t)
	dir := buildRelease(t)
	sums := map[string]string{}
	for _, name := range []string{"SHA1SUMS", "SHA256SUMS"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Fields(l)
			sums[name+" "+f[1]] = f[0]
		}
	}
	for _, target := range scriptTargets(t) {
		parts := strings.SplitN(target, "/", 2)
		ext := ".tar.gz"
		if parts[0] == "windows" {
			ext = ".zip"
		}
		versioned := "securl_" + nightlyVersion + "_" + parts[0] + "_" + parts[1] + ext
		stable := "securl_" + parts[0] + "_" + parts[1] + ext
		a, errA := os.ReadFile(filepath.Join(dir, versioned))
		b, errB := os.ReadFile(filepath.Join(dir, stable))
		if errA != nil || errB != nil {
			t.Errorf("%s and %s must both exist: %v %v", versioned, stable, errA, errB)
			continue
		}
		if string(a) != string(b) {
			t.Errorf("%s is not the same file as %s", stable, versioned)
		}
		for _, sum := range []string{"SHA1SUMS", "SHA256SUMS"} {
			if sums[sum+" "+stable] == "" {
				t.Errorf("%s has no line for %s", sum, stable)
			}
			if sums[sum+" "+stable] != sums[sum+" "+versioned] {
				t.Errorf("%s: the two names of one archive must have one digest", sum)
			}
		}
	}
}

// The version goes into file names and into what `securl version` prints. Anything that is not date-and-commit is
// refused, so that no branch or tag name, and nothing a person types, can reach either.
func TestReleaseScriptOnlyAcceptsADateAndACommit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	for _, v := range []string{"main", "dev", "1.2.3", "v1.2.3", "v", "latest", "nightly", "nightly-20261012", "nightly-20261012-abc",
		"nightly-2026-1a2b3c4", "nightly-20261012-1A2B3C4", "nightly-20261012-1a2b3c4; id", "nightly-20261012-1a2b3c4 x",
		"nightly-20261012-../../x1234567", "nightly-20261012-1a2b3c4\n", ""} {
		cmd := exec.Command("bash", releaseScript, filepath.Join(t.TempDir(), "d"), v)
		if err := cmd.Run(); err == nil {
			t.Errorf("version %q was accepted", v)
		}
	}
}

// ---- publishing ------------------------------------------------------------------------------------------------

// fakeGH is a `gh` that records every call and answers from a small model of the repository: whether a nightly release
// and a nightly tag exist, and which call, if any, should fail.
type fakeGH struct {
	t        *testing.T
	log      string
	bin      string
	state    string
	release  bool
	tag      bool
	failOn   string
	released string
}

func newFakeGH(t *testing.T, release, tag bool, failOn string) *fakeGH {
	t.Helper()
	root := t.TempDir()
	g := &fakeGH{t: t, bin: filepath.Join(root, "bin"), log: filepath.Join(root, "calls.log"), state: filepath.Join(root, "state")}
	if err := os.MkdirAll(g.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(g.state, 0o755); err != nil {
		t.Fatal(err)
	}
	if release {
		os.WriteFile(filepath.Join(g.state, "release"), nil, 0o644)
	}
	if tag {
		os.WriteFile(filepath.Join(g.state, "tag"), nil, 0o644)
	}
	script := `#!/usr/bin/env bash
# One line per call; the multi-line release notes are not part of what is recorded.
args=(); skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; args+=("<text>"); continue; fi
  case "$a" in --notes|--title) skip=1; args+=("$a");; *) args+=("$a");; esac
done
echo "${args[*]}" >> "` + g.log + `"
state="` + g.state + `"
case "$1 $2" in
  "release view")   [ -e "$state/release" ] && exit 0 || exit 1 ;;
  "release delete") [ "` + failOn + `" = delete ] && exit 1; rm -f "$state/release" "$state/tag"; exit 0 ;;
  "release create") [ "` + failOn + `" = create ] && exit 1; : > "$state/release"; : > "$state/tag"; shift 2
                    shift # the tag name
                    : > "$state/uploaded"; for f in "$@"; do case "$f" in --*) break;; *) basename "$f" >> "$state/uploaded";; esac; done
                    exit 0 ;;
  "api -X")         [ "` + failOn + `" = deltag ] && exit 1; rm -f "$state/tag"; exit 0 ;;
  api\ repos/*)     [ -e "$state/tag" ] && exit 0 || exit 1 ;;
esac
echo "fake gh: unexpected call: $*" >&2
exit 99
`
	if err := os.WriteFile(filepath.Join(g.bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *fakeGH) calls() []string {
	b, _ := os.ReadFile(g.log)
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (g *fakeGH) has(name string) bool {
	_, err := os.Stat(filepath.Join(g.state, name))
	return err == nil
}

func publishDir(t *testing.T, withSums bool) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "securl_nightly-20261012-1a2b3c4_linux_amd64.tar.gz"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, "securl_linux_amd64.tar.gz"), []byte("a"), 0o644)
	if withSums {
		os.WriteFile(filepath.Join(dir, "SHA1SUMS"), []byte("x  y\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("x  y\n"), 0o644)
	}
	return dir
}

func (g *fakeGH) publish(dir, commit, version, repo string) ([]byte, error) {
	cmd := exec.Command("bash", publishScript, dir, commit, version, repo)
	cmd.Env = append(os.Environ(), "PATH="+g.bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return cmd.CombinedOutput()
}

func publishSkip(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
}

// The old nightly release is deleted first, then its tag, and only then is the new release created, at the commit that
// was built, as a pre-release.
func TestPublishReplacesTheNightlyReleaseInOrder(t *testing.T) {
	publishSkip(t)
	g := newFakeGH(t, true, true, "")
	out, err := g.publish(publishDir(t, true), nightlyCommit, nightlyVersion, "LeafAI/securl")
	if err != nil {
		t.Fatalf("publish failed: %v\n%s", err, out)
	}
	calls := g.calls()
	var verbs []string
	for _, c := range calls {
		f := strings.Fields(c)
		verbs = append(verbs, strings.Join(f[:2], " "))
	}
	want := []string{"release view", "release delete", "api repos/LeafAI/securl/git/ref/tags/nightly", "release create"}
	if strings.Join(verbs, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", verbs, want)
	}
	if !strings.Contains(calls[1], "--cleanup-tag") || !strings.Contains(calls[1], "--yes") {
		t.Errorf("the old release must be deleted together with its tag, without a prompt: %s", calls[1])
	}
	create := calls[len(calls)-1]
	for _, w := range []string{"create nightly", "--repo LeafAI/securl", "--target " + nightlyCommit, "--prerelease"} {
		if !strings.Contains(create, w) {
			t.Errorf("release create lacks %q: %s", w, create)
		}
	}
	if strings.Contains(create, "--latest") && !strings.Contains(create, "--latest=false") {
		t.Errorf("the nightly must never become the latest release: %s", create)
	}
}

// The file list is every archive and both checksum files, and nothing else in the directory.
func TestPublishUploadsEveryArchiveAndBothChecksumFiles(t *testing.T) {
	publishSkip(t)
	g := newFakeGH(t, false, false, "")
	dir := publishDir(t, true)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("stray"), 0o644)
	if out, err := g.publish(dir, nightlyCommit, nightlyVersion, "LeafAI/securl"); err != nil {
		t.Fatalf("publish failed: %v\n%s", err, out)
	}
	uploaded, _ := os.ReadFile(filepath.Join(g.state, "uploaded"))
	got := strings.Fields(string(uploaded))
	want := []string{"SHA1SUMS", "SHA256SUMS", "securl_linux_amd64.tar.gz", "securl_nightly-20261012-1a2b3c4_linux_amd64.tar.gz"}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("uploaded %v, want exactly %v", got, want)
	}
}

// The first night has nothing to delete, and the call to delete one must not be made: it would fail.
func TestPublishWorksTheFirstTimeWithNothingToReplace(t *testing.T) {
	publishSkip(t)
	g := newFakeGH(t, false, false, "")
	if out, err := g.publish(publishDir(t, true), nightlyCommit, nightlyVersion, "LeafAI/securl"); err != nil {
		t.Fatalf("publish failed: %v\n%s", err, out)
	}
	for _, c := range g.calls() {
		if strings.HasPrefix(c, "release delete") || strings.HasPrefix(c, "api -X") {
			t.Errorf("nothing exists, so nothing is deleted: %s", c)
		}
	}
	if !g.has("release") {
		t.Error("the release was not created")
	}
}

// An earlier run that died between deleting the release and creating the new one leaves a tag with no release. The tag is
// removed too, or the new release would be made on the old commit.
func TestPublishRemovesATagLeftWithoutARelease(t *testing.T) {
	publishSkip(t)
	g := newFakeGH(t, false, true, "")
	if out, err := g.publish(publishDir(t, true), nightlyCommit, nightlyVersion, "LeafAI/securl"); err != nil {
		t.Fatalf("publish failed: %v\n%s", err, out)
	}
	var deletedTag bool
	for _, c := range g.calls() {
		deletedTag = deletedTag || strings.HasPrefix(c, "api -X DELETE repos/LeafAI/securl/git/refs/tags/nightly")
	}
	if !deletedTag {
		t.Errorf("the leftover tag must be deleted: %v", g.calls())
	}
}

// Everything that can be wrong with the input is found before anything is deleted: a failure after the old release is
// gone leaves people with no download at all.
func TestPublishChecksItsInputBeforeItDeletesAnything(t *testing.T) {
	publishSkip(t)
	cases := map[string]struct {
		dir             func() string
		commit, version string
		repo            string
	}{
		"short commit":     {func() string { return publishDir(t, true) }, "1a2b3c4", nightlyVersion, "LeafAI/securl"},
		"branch as commit": {func() string { return publishDir(t, true) }, "master", nightlyVersion, "LeafAI/securl"},
		"upper-case sha":   {func() string { return publishDir(t, true) }, strings.ToUpper(nightlyCommit), nightlyVersion, "LeafAI/securl"},
		"bad version":      {func() string { return publishDir(t, true) }, nightlyCommit, "v1.0.0", "LeafAI/securl"},
		"bad repository":   {func() string { return publishDir(t, true) }, nightlyCommit, nightlyVersion, "LeafAI/securl; id"},
		"no checksums":     {func() string { return publishDir(t, false) }, nightlyCommit, nightlyVersion, "LeafAI/securl"},
		"no directory":     {func() string { return filepath.Join(t.TempDir(), "missing") }, nightlyCommit, nightlyVersion, "LeafAI/securl"},
	}
	for name, c := range cases {
		g := newFakeGH(t, true, true, "")
		if out, err := g.publish(c.dir(), c.commit, c.version, c.repo); err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		if n := len(g.calls()); n != 0 {
			t.Errorf("%s: gh was called %d times (%v) for input that is refused up front", name, n, g.calls())
		}
		if !g.has("release") || !g.has("tag") {
			t.Errorf("%s: the existing release was removed", name)
		}
	}
}

// A failure while deleting leaves the old release in place and creates nothing; a failure while creating is reported,
// not hidden, so the next night (or a manual run) can try again.
func TestPublishStopsAtTheFirstFailure(t *testing.T) {
	publishSkip(t)
	g := newFakeGH(t, true, true, "delete")
	if _, err := g.publish(publishDir(t, true), nightlyCommit, nightlyVersion, "LeafAI/securl"); err == nil {
		t.Error("a failed delete must fail the publish")
	}
	for _, c := range g.calls() {
		if strings.HasPrefix(c, "release create") {
			t.Error("nothing may be created after a failed delete")
		}
	}
	g = newFakeGH(t, false, false, "create")
	if _, err := g.publish(publishDir(t, true), nightlyCommit, nightlyVersion, "LeafAI/securl"); err == nil {
		t.Error("a failed create must fail the publish")
	}
}

// The README tells a person without Go to download `securl_<os>_<arch>.tar.gz` and `SHA256SUMS` from the nightly
// release. Those names must be ones the script produces, or the first command they type is a 404. (`releases/latest`
// never points at a pre-release, so the address names the tag.)
func TestReadmeDownloadNamesAreTheOnesTheNightlyPublishes(t *testing.T) {
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	base := "https://github.com/LeafAI/securl/releases/download/nightly/"
	for _, want := range []string{base + "securl_<os>_<arch>.tar.gz", base + "SHA256SUMS", "securl_<os>_<arch>.tar.gz"} {
		if !strings.Contains(readme, want) {
			t.Errorf("the README must contain %q", want)
		}
	}
	if strings.Contains(readme, "releases/latest") {
		t.Error("releases/latest never points at a pre-release: the README must use releases/download/nightly")
	}
	script, err := os.ReadFile(releaseScript)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"securl_${os}_${arch}.", "SHA256SUMS", "SHA1SUMS"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("the script no longer produces %q, which the README tells people to download", want)
		}
	}
	flat := strings.Join(strings.Fields(readme), " ")
	for _, want := range []string{"SHA1SUMS", "SHA256SUMS", "SHA-1 collisions can be made", "replaced every night"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the README must say %q", want)
		}
	}
}

// The README tells a Go developer to `go install` and everyone else to download the nightly. Both have to be there, the
// install for Go first because a developer reads from the top, and neither may claim the other's requirement.
func TestReadmeGivesBothWaysToGetTheBinary(t *testing.T) {
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	goAt := strings.Index(readme, "go install github.com/LeafAI/securl@latest")
	dlAt := strings.Index(readme, "releases/download/nightly/securl_<os>_<arch>.tar.gz")
	if goAt < 0 || dlAt < 0 {
		t.Fatalf("the README must show go install (at %d) and the nightly download (at %d)", goAt, dlAt)
	}
	flat := strings.Join(strings.Fields(readme), " ")
	for _, want := range []string{"Go 1.21 or newer, for a Go developer", "No Go toolchain", "the repository has no release tags"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the README must say %q", want)
		}
	}
	// The download is not presented as the fallback of a Go install, and `go install` as the way for a Go developer is not
	// presented as a pinned commit only: `@latest` is shown.
	if strings.Contains(flat, "if you need a known version") {
		t.Error("go install is the way for a Go developer, not only a way to pin a version")
	}
}
