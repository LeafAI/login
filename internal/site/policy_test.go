package site_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/site"
)

func TestADriverWithoutAPolicyAllowsEverything(t *testing.T) {
	d, _ := site.Resolve("gitlab", nil)
	if err := site.CheckRequest(d, "DELETE", "/api/v4/projects/1"); err != nil {
		t.Errorf("a site with no policy is unchanged: %v", err)
	}
}

// A policy is a list of what may pass; everything else is refused, so a path that nobody has thought of is refused too.
func TestAPolicyIsAnAllowListAndAnythingElseIsRefused(t *testing.T) {
	p := site.AllowList{Methods: []string{"GET"}, Exact: []string{"/login/check.query"}, Suffix: ".query", Deny: []string{"/message/"}}
	for _, ok := range []struct{ m, p string }{
		{"GET", "/topic/list.query"}, {"GET", "/consumer/groupList.query"}, {"GET", "/login/check.query"}, {"get", "/topic/list.query"},
	} {
		if err := p.Check(ok.m, ok.p); err != nil {
			t.Errorf("%s %s must pass: %v", ok.m, ok.p, err)
		}
	}
	for name, bad := range map[string]struct{ m, p string }{
		"write path":           {"GET", "/topic/deleteTopic.do"},
		"write via POST":       {"POST", "/topic/list.query"},
		"delete":               {"DELETE", "/topic/list.query"},
		"put":                  {"PUT", "/topic/list.query"},
		"unknown suffix":       {"GET", "/topic/list.json"},
		"no suffix":            {"GET", "/topic/list"},
		"suffix then more":     {"GET", "/topic/list.query.do"},
		"suffix in the middle": {"GET", "/topic/list.query/../deleteTopic.do"},
		"denied prefix":        {"GET", "/message/queryMessageByTopic.query"},
		"denied prefix, case":  {"GET", "/Message/queryMessageByTopic.query"},
		"denied, double slash": {"GET", "//message/queryMessageByTopic.query"},
		"denied, encoded":      {"GET", "/%6dessage/queryMessageByTopic.query"},
		"denied, dot segment":  {"GET", "/topic/../message/viewMessage.query"},
		"denied, encoded dots": {"GET", "/topic/%2e%2e/message/viewMessage.query"},
		"encoded slash":        {"GET", "/topic%2flist.query"},
		"backslash":            {"GET", `/topic\list.query`},
		"semicolon param":      {"GET", "/topic/list.query;x=/../deleteTopic.do"},
		"empty":                {"GET", ""},
		"root":                 {"GET", "/"},
		"query smuggled":       {"GET", "/topic/list.query?x=/y.do"},
		"fragment":             {"GET", "/topic/list.query#.do"},
		"nul":                  {"GET", "/topic/list.query\x00.do"},
		"newline":              {"GET", "/topic/list.query\n"},
		"trailing space":       {"GET", "/topic/list.query "},
		"trailing dot":         {"GET", "/topic/list.query."},
		"empty method":         {"", "/topic/list.query"},
		"method with space":    {"GET ", "/topic/list.query"},
	} {
		err := p.Check(bad.m, bad.p)
		if err == nil {
			t.Errorf("%s: %s %q must be refused", name, bad.m, bad.p)
			continue
		}
		if !errors.Is(err, site.ErrRequestRefused) {
			t.Errorf("%s: a refusal must be site.ErrRequestRefused: %v", name, err)
		}
	}
}

func TestARefusalSaysWhyAndNeverRepeatsTheWholeRequest(t *testing.T) {
	p := site.AllowList{Methods: []string{"GET"}, Suffix: ".query"}
	err := p.Check("POST", "/topic/deleteTopic.do")
	if err == nil || !strings.Contains(err.Error(), "POST") {
		t.Errorf("the method that was refused is named: %v", err)
	}
	err = p.Check("GET", "/topic/deleteTopic.do")
	if err == nil || !strings.Contains(err.Error(), ".query") {
		t.Errorf("what is allowed is named: %v", err)
	}
	if long := p.Check("GET", "/"+strings.Repeat("a", 5000)); long == nil || len(long.Error()) > 400 {
		t.Errorf("a refusal is short, whatever the path: %v", long)
	}
}

func TestACleanedPathIsWhatIsChecked(t *testing.T) {
	p := site.AllowList{Methods: []string{"GET"}, Suffix: ".query"}
	// A path that the proxy would send as something other than what it looks like is not let through on the strength of its
	// look: it is cleaned first, and a path that changes when it is cleaned is refused outright.
	for _, path := range []string{"/a/./b.query", "/a//b.query", "/a/../b.query", "/./b.query", "/a/b.query/"} {
		if err := p.Check("GET", path); err == nil {
			t.Errorf("%q changes when cleaned, so it is refused", path)
		}
	}
	if err := p.Check("GET", "/a/b.query"); err != nil {
		t.Errorf("a clean path passes: %v", err)
	}
}

// Each guard of AllowList.Check is tested alone: a path that only that guard stops (the others would let it through), so that
// taking the guard away is noticed. A guard that is only ever covered by another one is a guard nobody will notice losing.
func TestEveryGuardOfThePolicyStopsSomethingTheOthersWouldNot(t *testing.T) {
	// The list below allows anything ending in ".query" under /a/ and has no deny list, so what reaches a guard is decided
	// by that guard alone.
	p := site.AllowList{Methods: []string{"GET"}, Suffix: ".query"}
	for name, c := range map[string]struct{ m, p string }{
		// the method guard
		"method: POST": {"POST", "/a/b.query"},
		// the method guard rejects a method that only differs by white space, which EqualFold would not tell apart after trimming
		"method: trailing space": {"GET ", "/a/b.query"},
		"method: leading space":  {" GET", "/a/b.query"},
		"method: tab":            {"GET\t", "/a/b.query"},
		"method: empty":          {"", "/a/b.query"},
		// the shape guards: nothing else would stop these, since each still ends in .query
		"path: relative":          {"GET", "a/b.query"},
		"path: query":             {"GET", "/a/b.query?x=1"},
		"path: fragment":          {"GET", "/a/b.query#x"},
		"path: control character": {"GET", "/a/b\x01c.query"},
		"path: space inside":      {"GET", "/a/b c.query"},
		"path: tab inside":        {"GET", "/a/b\tc.query"},
		"path: delete character":  {"GET", "/a/b\x7fc.query"},
		"path: not clean":         {"GET", "/a/./b.query"},
		"path: doubled slash":     {"GET", "/a//b.query"},
		"path: trailing slash":    {"GET", "/a/b.query/"},
		// the suffix guard
		"suffix: bare .query":         {"GET", "/.query"},
		"suffix: another extension":   {"GET", "/a/b.do"},
		"suffix: nothing after slash": {"GET", "/a/"},
	} {
		if err := p.Check(c.m, c.p); err == nil {
			t.Errorf("%s: %s %q must be refused", name, c.m, c.p)
		}
	}
	d := site.AllowList{Methods: []string{"GET"}, Suffix: ".query", Deny: []string{"/message/"}}
	for name, p := range map[string]string{
		"deny: exact":      "/message/a.query",
		"deny: upper case": "/MESSAGE/a.query",
		"deny: mixed case": "/Message/a.query",
	} {
		if err := d.Check("GET", p); err == nil {
			t.Errorf("%s: %q must be refused by the deny list", name, p)
		}
	}
	// ... and the deny list does not refuse what only looks like it
	for _, ok := range []string{"/messages-not/a.query", "/a/message/b.query", "/topic/messageCount.query"} {
		if err := d.Check("GET", ok); err != nil {
			t.Errorf("%q is not under /message/: %v", ok, err)
		}
	}
	// an Exact path passes without the suffix, and still has to be clean
	e := site.AllowList{Methods: []string{"GET"}, Suffix: ".query", Exact: []string{"/health"}}
	if err := e.Check("GET", "/health"); err != nil {
		t.Errorf("%v", err)
	}
	if err := e.Check("GET", "/health/"); err == nil {
		t.Error("an exact path is exact")
	}
	if err := e.Check("GET", "/Health"); err == nil {
		t.Error("and case-sensitive")
	}
}

// The refusal carries the allowed methods without letting a very long method through.
func TestALongMethodIsClippedInTheRefusal(t *testing.T) {
	err := site.AllowList{Methods: []string{"GET"}, Suffix: ".query"}.Check(strings.Repeat("X", 500), "/a.query")
	if err == nil || len(err.Error()) > 200 || !strings.Contains(err.Error(), "...") {
		t.Errorf("%d bytes: %v", len(err.Error()), err)
	}
}

// Guards that another guard would also stop are tested with a list that has no other guard in the way: a Suffix that lets
// anything through ("") and exact paths, so the thing under test is the only thing between the request and the site.
func TestGuardsThatAnotherGuardWouldAlsoStopAreTestedAlone(t *testing.T) {
	// no suffix: only the shape guards, the method guard, the deny list and Exact decide
	open := site.AllowList{Methods: []string{"GET"}, Exact: []string{"/health", "/a/b.query"}}
	for name, c := range map[string]struct{ m, p string }{
		"method with a trailing space (exact path)": {"GET ", "/a/b.query"},
		"empty method (exact path)":                 {"", "/a/b.query"},
		"a query on an exact path":                  {"GET", "/health?x=1"},
		"a fragment on an exact path":               {"GET", "/health#x"},
		"a prefix of an exact path is not exact":    {"GET", "/healthz"},
		"an exact path with more after it":          {"GET", "/health/x"},
		"an exact path in another case":             {"GET", "/HEALTH"},
	} {
		if err := open.Check(c.m, c.p); err == nil {
			t.Errorf("%s: %s %q must be refused", name, c.m, c.p)
		}
	}
	// the method guard on its own: a list whose only allowed thing is one method, one exact path
	m := site.AllowList{Methods: []string{"GET"}, Exact: []string{"/x"}}
	for _, bad := range []string{"GET ", " GET", "GET\n", "GE T", "", "G", "GETX"} {
		if err := m.Check(bad, "/x"); err == nil {
			t.Errorf("method %q must be refused", bad)
		}
	}
	for _, good := range []string{"GET", "get", "Get"} {
		if err := m.Check(good, "/x"); err != nil {
			t.Errorf("method %q must pass: %v", good, err)
		}
	}
	// the deny list's case rule on its own: every path is under the denied prefix when compared without case
	deny := site.AllowList{Methods: []string{"GET"}, Exact: []string{"/message/a", "/MESSAGE/a", "/Message/a"}, Deny: []string{"/message/"}}
	for _, p := range []string{"/message/a", "/MESSAGE/a", "/Message/a"} {
		if err := deny.Check("GET", p); err == nil {
			t.Errorf("%q is under the denied prefix whatever its case, even when it is also listed as exact", p)
		}
	}
}

// The suffix test looks at the end of the whole string. A path that carries a query or a fragment must therefore be refused
// before the suffix is looked at: "/topic/deleteTopic.do?x=.query" ends in ".query" and is the write operation to the site.
func TestAQueryOrFragmentCannotHideTheSuffixOfAWriteOperation(t *testing.T) {
	p := site.AllowList{Methods: []string{"GET"}, Suffix: ".query"}
	for _, path := range []string{
		"/topic/deleteTopic.do?x=.query", "/topic/deleteTopic.do#.query", "/topic/deleteTopic.do?.query",
		"/topic/deleteTopic.do?a=/b.query", "/message/viewMessage?x=.query", "/topic/x?.query", "/topic/x#.query",
	} {
		if err := p.Check("GET", path); err == nil {
			t.Errorf("%q ends in .query but is not a .query path: it must be refused", path)
		}
	}
}

// The method guard's two parts, each alone: a method that differs from an allowed one only by white space is not that method,
// and an empty one is no method (an empty entry in the list must not let it in).
func TestAMethodThatDiffersOnlyByWhiteSpaceOrIsEmptyIsRefused(t *testing.T) {
	odd := site.AllowList{Methods: []string{"GET", " GET", "GET ", ""}, Exact: []string{"/x"}}
	for _, m := range []string{"GET ", " GET", ""} {
		if err := odd.Check(m, "/x"); err == nil {
			t.Errorf("method %q is refused even if the list names it: a method is a token, and one with white space around it is not one", m)
		}
	}
	if err := odd.Check("GET", "/x"); err != nil {
		t.Errorf("%v", err)
	}
}

// The deny list compares without regard to case, for the part of the path that is not under the owner's control.
func TestTheDenyListIsCaseInsensitiveEvenForAPathNothingElseStops(t *testing.T) {
	d := site.AllowList{Methods: []string{"GET"}, Exact: []string{"/MESSAGE/viewMessage.query", "/Message/viewMessage.query"}, Deny: []string{"/message/"}}
	for _, p := range []string{"/MESSAGE/viewMessage.query", "/Message/viewMessage.query"} {
		if err := d.Check("GET", p); err == nil {
			t.Errorf("%q must be refused by the deny list", p)
		}
	}
}

// An entry of the deny list written with capitals still denies: the path is lower-cased for the comparison, so the entry has to
// be too, or a list written "/Message/" would deny nothing.
func TestADenyEntryWrittenWithCapitalsStillDenies(t *testing.T) {
	d := site.AllowList{Methods: []string{"GET"}, Suffix: ".query", Deny: []string{"/Message/"}}
	for _, p := range []string{"/message/a.query", "/MESSAGE/a.query", "/Message/a.query"} {
		if err := d.Check("GET", p); err == nil {
			t.Errorf("%q must be denied by an entry written %q", p, "/Message/")
		}
	}
}
