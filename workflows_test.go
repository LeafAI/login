package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A workflow that does not say what its token may do gets the repository's default, which can be read and write. CodeQL
// reports that as actions/missing-workflow-permissions (alerts 1 and 7 were the two jobs of ci.yml). Every workflow here
// declares a least-privilege token, and a job that needs more says so on that job only.

type anyWorkflow struct {
	Permissions any `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions any `yaml:"permissions"`
	} `yaml:"jobs"`
}

func allWorkflows(t *testing.T) map[string]anyWorkflow {
	t.Helper()
	files, err := filepath.Glob(".github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	out := map[string]anyWorkflow{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var w anyWorkflow
		if err := yaml.Unmarshal(b, &w); err != nil {
			t.Fatalf("%s is not valid YAML: %v", f, err)
		}
		out[f] = w
	}
	return out
}

// permissionsOf reads a permissions block as scope -> level. A bare "read-all" / "write-all" string is returned under
// the scope "*".
func permissionsOf(p any) map[string]string {
	switch v := p.(type) {
	case map[string]any:
		m := map[string]string{}
		for k, x := range v {
			m[k], _ = x.(string)
		}
		return m
	case string:
		return map[string]string{"*": v}
	}
	return nil
}

func TestEveryWorkflowDeclaresItsTokenPermissions(t *testing.T) {
	for f, w := range allWorkflows(t) {
		top := permissionsOf(w.Permissions)
		if top != nil {
			continue
		}
		// Without a workflow-level block, every job must carry its own.
		for name, j := range w.Jobs {
			if permissionsOf(j.Permissions) == nil {
				t.Errorf("%s: job %q has no permissions and the workflow has none: it gets the repository default", f, name)
			}
		}
	}
}

func TestNoWorkflowGrantsMoreThanItNeeds(t *testing.T) {
	// What each workflow is allowed to write, and where. Anything else is read-only.
	allowed := map[string]map[string][]string{
		".github/workflows/pages.yml":   {"": {"pages", "id-token"}},
		".github/workflows/nightly.yml": {"publish": {"contents"}},
		// CodeQL uploads its results as code scanning alerts, which needs security-events: write on the analyze job.
		".github/workflows/codeql.yml": {"analyze": {"security-events"}},
	}
	for f, w := range allWorkflows(t) {
		check := func(where string, p map[string]string) {
			var writes []string
			for scope, level := range p {
				if level == "write" || level == "write-all" || level == "admin" {
					writes = append(writes, scope)
				}
			}
			sort.Strings(writes)
			ok := map[string]bool{}
			for _, s := range allowed[f][where] {
				ok[s] = true
			}
			for _, s := range writes {
				if !ok[s] {
					t.Errorf("%s (%s): %s: write is not expected for this workflow", f, strings.TrimSpace(where+" "), s)
				}
			}
		}
		check("", permissionsOf(w.Permissions))
		for name, j := range w.Jobs {
			check(name, permissionsOf(j.Permissions))
		}
		if top := permissionsOf(w.Permissions); top != nil {
			if top["*"] == "write-all" || top["*"] == "read-all" {
				t.Errorf("%s: name the scopes instead of %s", f, top["*"])
			}
		}
	}
}

// The ones that only read the repository say so in the one place that counts, the top of the file, so that a job added
// later is covered without anyone having to remember.
func TestReadOnlyWorkflowsSayContentsReadAtTheTop(t *testing.T) {
	for _, f := range []string{".github/workflows/ci.yml", ".github/workflows/nightly.yml", ".github/workflows/pages.yml"} {
		w := allWorkflows(t)[f]
		if got := permissionsOf(w.Permissions)["contents"]; got != "read" {
			t.Errorf("%s: workflow-level contents permission = %q, want read", f, got)
		}
	}
}
