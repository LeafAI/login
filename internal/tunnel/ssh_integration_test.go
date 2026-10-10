package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/sshtest"
)

// TestRealSSHReverseForward checks, against a throwaway sshd, that a tunnel started by the runner
// really carries HTTP traffic from the "remote" port back to the local server.
func TestRealSSHReverseForward(t *testing.T) {
	srv := sshtest.Start(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello through the tunnel") }))
	defer local.Close()
	localPort := local.Listener.Addr().(*net.TCPAddr).Port
	remotePort := sshtest.FreePort(t)

	p, err := Custom("real-ssh", srv.ReverseCommand(remotePort), fmt.Sprintf("http://127.0.0.1:%d", remotePort), "")
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
