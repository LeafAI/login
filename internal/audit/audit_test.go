package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func lines(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("not one JSON object per line: %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestRecordAppendsJSONLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "audit.jsonl")
	l, err := Open(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Record(Event{Event: "tool_call", Tool: "login", Host: "gitlab.corp.example", Result: "ok", Cached: true})
	l.Record(Event{Event: "human_request", Site: "gitlab", Reason: "deploy check"})
	got := lines(t, p)
	if len(got) != 2 || got[0].Tool != "login" || !got[0].Cached || got[1].Reason != "deploy check" || got[0].Time == "" {
		t.Fatalf("events = %+v", got)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("audit file mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Dir(p)); st.Mode().Perm() != 0o700 {
		t.Errorf("audit dir mode %v", st.Mode())
	}
	l2, _ := Open(p, nil) // a restart appends, never truncates
	l2.Record(Event{Event: "tool_call"})
	if n := len(lines(t, p)); n != 3 {
		t.Errorf("reopen lost history: %d lines", n)
	}
}

func TestDisabledLogIsHarmless(t *testing.T) {
	l, err := Open("", nil)
	if err != nil || l != nil {
		t.Fatalf("empty path must disable auditing: %v %v", l, err)
	}
	l.Record(Event{Event: "x"}) // nil receiver
}

func TestFingerprintNeverContainsTheText(t *testing.T) {
	n, h := Fingerprint("DELETE FROM users WHERE id = 7")
	if n != 30 || len(h) != 12 || strings.Contains(h, "DELETE") {
		t.Fatalf("%d %q", n, h)
	}
	if _, h2 := Fingerprint("DELETE FROM users WHERE id = 8"); h2 == h {
		t.Error("different statements must differ")
	}
}

func TestWriteFailureIsReportedNotFatal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	var warned []string
	l, err := Open(p, func(f string, a ...any) { warned = append(warned, f) })
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(p)
	os.Mkdir(p, 0o700) // now unopenable as a file
	l.Record(Event{Event: "x"})
	if len(warned) == 0 {
		t.Error("the operator must hear that auditing is failing")
	}
}

func TestConcurrentRecordsStayWholeLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p, nil)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Record(Event{Event: "tool_call", Tool: "login", Reason: strings.Repeat("x", 500)})
		}()
	}
	wg.Wait()
	if n := len(lines(t, p)); n != 100 {
		t.Fatalf("%d intact lines, want 100", n)
	}
}

func TestOpenFailsWhenPathUnusable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := Open(filepath.Join(f, "sub", "a.jsonl"), nil); err == nil {
		t.Fatal("a log that cannot be created should fail at start-up, not silently drop events")
	}
}
