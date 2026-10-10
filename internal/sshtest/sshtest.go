// Package sshtest starts a throwaway sshd for tests that need a real SSH server.
package sshtest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type Server struct {
	Port int
	User string
	Key  string // client private key path
}

// FreePort returns an unused TCP port on 127.0.0.1.
func FreePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Start launches sshd on a free port, skipping the test when ssh tooling is unavailable.
func Start(t testing.TB) *Server {
	t.Helper()
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
	port := FreePort(t)
	conf := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s/host\nAuthorizedKeysFile %s/authorized_keys\nPidFile %s/sshd.pid\nUsePAM no\nStrictModes no\nPermitRootLogin yes\nPasswordAuthentication no\nAllowTcpForwarding yes\n", port, dir, dir, dir)
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(conf), 0o600)
	cmd := exec.Command(sshdPath, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; ; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			break
		}
		if i > 50 {
			t.Skip("sshd did not come up")
		}
		time.Sleep(100 * time.Millisecond)
	}
	user := "root"
	if u := os.Getenv("USER"); u != "" {
		user = u
	}
	return &Server{Port: port, User: user, Key: filepath.Join(dir, "client")}
}

// ReverseCommand is an ssh command line (with {{port}} for the local port) that exposes the local
// port on remotePort of the test server.
func (s *Server) ReverseCommand(remotePort int) string {
	return fmt.Sprintf("ssh -N -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -i %s -p %d -R 127.0.0.1:%d:localhost:{{port}} %s@127.0.0.1",
		s.Key, s.Port, remotePort, s.User)
}
