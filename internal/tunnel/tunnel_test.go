package tunnel

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseURL(t *testing.T) {
	b := Builtins()
	cases := []struct {
		prov, line, want string
	}{
		{"pinggy", "http://abcde-1-2-3-4.a.free.pinggy.link", ""},
		{"pinggy", "https://abcde-1-2-3-4.a.free.pinggy.link", "https://abcde-1-2-3-4.a.free.pinggy.link"},
		{"pinggy", "\x1b[1mhttps://x.a.free.pinggy.link\x1b[0m", "https://x.a.free.pinggy.link"},
		{"localhost.run", "Create a free account: https://localhost.run/docs/forever-free/", ""},
		{"localhost.run", "abc123.lhr.life tunneled with tls termination, https://abc123.lhr.life", "https://abc123.lhr.life"},
		{"serveo", "Forwarding HTTP traffic from https://abc.serveousercontent.com", "https://abc.serveousercontent.com"},
		{"serveo", "Forwarding HTTP traffic from https://abc.serveo.net.", "https://abc.serveo.net"},
		{"tunnl", "Your URL: https://qwe.tunnl.gg/", "https://qwe.tunnl.gg"},
		{"tunnl", "visit https://tunnl.gg for more", ""},
	}
	for _, c := range cases {
		got, _ := b[c.prov].parseURL(c.line)
		if got != c.want {
			t.Errorf("%s %q: got %q want %q", c.prov, c.line, got, c.want)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	got, err := splitArgs(`ssh -i "~/.ssh/my key" -R {{port}}:localhost:{{port}} 'jump host'`)
	want := []string{"ssh", "-i", "~/.ssh/my key", "-R", "{{port}}:localhost:{{port}}", "jump host"}
	if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("%v %v", got, err)
	}
}

// fakeSSH writes an "ssh" script that prints a banner per its destination argument.
func fakeSSH(t *testing.T) string {
	dir := t.TempDir()
	p := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
echo "$@" >> "` + filepath.Join(dir, "calls") + `"
case "$*" in
  *pinggy.io*) echo "permission denied" >&2; exit 255;;
  *localhost.run*) echo "abc.lhr.life tunneled with tls termination, https://abc.lhr.life"; sleep 30;;
  *) exit 1;;
esac
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFallbackChain(t *testing.T) {
	b := Builtins()
	r := &Runner{SSH: fakeSSH(t), Timeout: 5 * time.Second}
	// ssh-j is a TCP provider and must be skipped; pinggy fails; localhost.run succeeds.
	tn, err := r.Start(context.Background(), []*Provider{b["ssh-j"], b["pinggy"], b["localhost.run"]}, 4321)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if tn.URL != "https://abc.lhr.life" || tn.Provider != "localhost.run" {
		t.Fatalf("got %+v", tn)
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(r.SSH), "calls"))
	if !strings.Contains(string(calls), "80:localhost:4321") || strings.Contains(string(calls), "ssh-j.com") {
		t.Errorf("calls:\n%s", calls)
	}
	tn.Close() // idempotent
	select {
	case <-tn.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("process not stopped")
	}
}

func TestAllFail(t *testing.T) {
	b := Builtins()
	r := &Runner{SSH: fakeSSH(t), Timeout: time.Second}
	_, err := r.Start(context.Background(), []*Provider{b["pinggy"], b["serveo"]}, 1)
	if err == nil || !strings.Contains(err.Error(), "pinggy") || !strings.Contains(err.Error(), "serveo") {
		t.Fatalf("err = %v", err)
	}
}

func TestCustomFixedURL(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "jump")
	os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o755)
	p, err := Custom("mycorp", script+" -R {{port}}", "https://jump.corp:{{port}}", "")
	if err != nil {
		t.Fatal(err)
	}
	tn, err := (&Runner{}).Start(context.Background(), []*Provider{p}, 8123)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	if tn.URL != "https://jump.corp:8123" {
		t.Errorf("url %q", tn.URL)
	}
}

// TestBuiltinCommandLinesParse lets the real ssh parse every built-in command line (ssh -G prints the
// effective config without connecting), catching misspelt options or malformed -R specs.
func TestBuiltinCommandLinesParse(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
	}
	for name, p := range Builtins() {
		args := append([]string{"-G"}, append(append([]string{}, sshBaseOpts...), p.Args(4321)...)...)
		if out, err := exec.Command("ssh", args...).CombinedOutput(); err != nil {
			t.Errorf("%s: ssh rejected %v: %v\n%s", name, args, err, out)
		}
	}
}

// A tunnel whose ssh process exits on its own must report Done (the flow relies on this to restart it).
func TestDoneClosesWhenSSHExits(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "ssh")
	os.WriteFile(script, []byte("#!/bin/sh\necho 'https://short-lived.lhr.life'\nsleep 1\n"), 0o755)
	tn, err := (&Runner{SSH: script, Timeout: 5 * time.Second}).Start(context.Background(), []*Provider{Builtins()["localhost.run"]}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	select {
	case <-tn.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not close after the process exited")
	}
}

// alive reports whether a process exists (signal 0 checks without disturbing it).
func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if !alive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("%s (pid %d) is still running after the tunnel was closed", what, pid)
	syscall.Kill(pid, syscall.SIGKILL) // do not leave it behind
}

// A tunnel is one-shot: closing it must end the whole process tree, not only the process that was started.
// Custom providers run through a command line (often a shell wrapper or a script that starts ssh), so a plain
// Process.Kill would leave the real ssh behind, still holding the forwarded port and the public name.
func TestCloseEndsTheWholeProcessTree(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "ssh")
	// The "ssh" prints its banner, starts a long-lived grandchild like a wrapper script would, and waits for it.
	body := "#!/bin/sh\necho 'https://wrapped.lhr.life'\nsleep 300 &\necho $! > " + pidFile + "\nwait\n"
	os.WriteFile(script, []byte(body), 0o755)
	tn, err := (&Runner{SSH: script, Timeout: 5 * time.Second}).Start(context.Background(), []*Provider{Builtins()["localhost.run"]}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var child int
	for i := 0; i < 100 && child == 0; i++ {
		if b, err := os.ReadFile(pidFile); err == nil {
			child, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if child == 0 || !alive(child) {
		t.Fatalf("test setup: the wrapper's child did not start (pid %d)", child)
	}
	parent := tn.cmd.Process.Pid
	tn.Close()
	waitGone(t, parent, "the tunnel process")
	waitGone(t, child, "the child the tunnel process started")
}

// Close is safe to call again, from several places, and never blocks forever.
func TestCloseIsIdempotentAndPrompt(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "ssh")
	os.WriteFile(script, []byte("#!/bin/sh\necho 'https://x.lhr.life'\nsleep 300\n"), 0o755)
	tn, err := (&Runner{SSH: script, Timeout: 5 * time.Second}).Start(context.Background(), []*Provider{Builtins()["localhost.run"]}, 1)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		tn.Close()
		tn.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	waitGone(t, tn.cmd.Process.Pid, "the tunnel process")
}
