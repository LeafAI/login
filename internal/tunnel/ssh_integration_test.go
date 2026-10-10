package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestRealSSHReverseForward starts a throwaway sshd and checks that a tunnel started by the runner
// really carries HTTP traffic from the "remote" port back to the local server.
func TestRealSSHReverseForward(t *testing.T) {
	for _, bin := range []string{"ssh", "sshd", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	sshdPath, _ := exec.LookPath("sshd")
	dir := t.TempDir()
	run := func(name string, args ...string) {
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Skipf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "host"))
	run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "client"))
	pub, _ := os.ReadFile(filepath.Join(dir, "client.pub"))
	os.WriteFile(filepath.Join(dir, "authorized_keys"), pub, 0o600)
	os.MkdirAll("/run/sshd", 0o755)
	sshPort := freePort(t)
	conf := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s/host
AuthorizedKeysFile %s/authorized_keys
PidFile %s/sshd.pid
UsePAM no
StrictModes no
PermitRootLogin yes
PasswordAuthentication no
AllowTcpForwarding yes
`, sshPort, dir, dir, dir)
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(conf), 0o600)
	sshd := exec.Command(sshdPath, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	if err := sshd.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	t.Cleanup(func() { sshd.Process.Kill(); sshd.Wait() })
	for i := 0; ; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshPort)); err == nil {
			c.Close()
			break
		}
		if i > 50 {
			t.Skip("sshd did not come up")
		}
		time.Sleep(100 * time.Millisecond)
	}

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello through the tunnel") }))
	defer local.Close()
	localPort := local.Listener.Addr().(*net.TCPAddr).Port
	remotePort := freePort(t)

	user := "root"
	if u := os.Getenv("USER"); u != "" {
		user = u
	}
	cmd := fmt.Sprintf("ssh -N -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -i %s/client -p %d -R 127.0.0.1:%d:localhost:{{port}} %s@127.0.0.1",
		dir, sshPort, remotePort, user)
	p, err := Custom("real-ssh", cmd, fmt.Sprintf("http://127.0.0.1:%d", remotePort), "")
	if err != nil {
		t.Fatal(err)
	}
	tn, err := (&Runner{Timeout: 10 * time.Second}).Start(context.Background(), []*Provider{p}, localPort)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer tn.Close()

	resp, err := http.Get(tn.URL + "/")
	if err != nil {
		t.Fatalf("GET via tunnel: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hello through the tunnel" {
		t.Errorf("body = %q", b)
	}

	// Closing the tunnel must tear the forward down.
	tn.Close()
	time.Sleep(300 * time.Millisecond)
	if resp, err := http.Get(tn.URL + "/"); err == nil {
		resp.Body.Close()
		t.Error("remote port still forwards after Close")
	}
}
