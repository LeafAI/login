// Package tunnel exposes a local port to the internet through an SSH remote-forwarding provider.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Kind int

const (
	HTTP Kind = iota // gives a public https URL usable for the login API
	TCP              // raw TCP forwarding only (e.g. ssh-j.com); never used for the web API
)

// Provider describes one SSH reverse-tunnel service.
type Provider struct {
	Name string
	Kind Kind
	// Args returns the ssh arguments for forwarding localPort.
	Args func(localPort int) []string
	// IgnoreHosts are host suffixes that appear in banners but are not the tunnel URL (docs, the provider itself).
	IgnoreHosts []string
	// FixedURL, when set, is used instead of parsing output (custom providers); {{port}} is expanded.
	FixedURL string
	// URLRegex, when set, extracts the URL from output (custom providers).
	URLRegex *regexp.Regexp
	// Raw makes Args the complete command line (custom providers) instead of ssh options + Args.
	Raw []string
}

var sshBaseOpts = []string{
	"-o", "StrictHostKeyChecking=accept-new",
	"-o", "ServerAliveInterval=15",
	"-o", "ServerAliveCountMax=3",
	"-o", "ExitOnForwardFailure=yes",
	"-o", "BatchMode=yes",
}

func fwd(port int) string { return "80:localhost:" + strconv.Itoa(port) }

// Builtins returns the built-in providers keyed by name.
func Builtins() map[string]*Provider {
	list := []*Provider{
		{Name: "pinggy", Args: func(p int) []string { return []string{"-R", fwd(p), "pinggy.io"} },
			IgnoreHosts: []string{"pinggy.io", "dashboard.pinggy.io"}},
		{Name: "localhost.run", Args: func(p int) []string { return []string{"-R", fwd(p), "nokey@localhost.run"} },
			IgnoreHosts: []string{"localhost.run", "admin.localhost.run"}},
		{Name: "serveo", Args: func(p int) []string { return []string{"-R", fwd(p), "serveo.net"} },
			IgnoreHosts: []string{"serveo.net"}},
		{Name: "tunnl", Args: func(p int) []string { return []string{"-t", "-R", fwd(p), "proxy.tunnl.gg"} },
			IgnoreHosts: []string{"tunnl.gg"}},
		{Name: "ssh-j", Kind: TCP, Args: func(p int) []string { return []string{"-R", "login:22:localhost:22", "ssh-j.com"} }},
	}
	m := map[string]*Provider{}
	for _, p := range list {
		m[p.Name] = p
	}
	return m
}

// Tunnel is a running tunnel.
type Tunnel struct {
	URL      string
	Provider string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	done     chan struct{}
	once     sync.Once
}

// Done is closed when the ssh process exits.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Close terminates the ssh process.
func (t *Tunnel) Close() {
	t.once.Do(func() {
		t.stdin.Close()
		if t.cmd.Process != nil {
			t.cmd.Process.Kill()
		}
	})
	<-t.done
}

type Runner struct {
	SSH     string // ssh binary, default "ssh"
	Timeout time.Duration
	Log     func(format string, args ...any)
}

func (r *Runner) logf(f string, a ...any) {
	if r.Log != nil {
		r.Log(f, a...)
	}
}

// Start tries providers in order and returns the first working tunnel.
func (r *Runner) Start(ctx context.Context, providers []*Provider, localPort int) (*Tunnel, error) {
	var errs []string
	for _, p := range providers {
		if p.Kind != HTTP {
			errs = append(errs, p.Name+": not an HTTP provider")
			continue
		}
		t, err := r.start(ctx, p, localPort)
		if err == nil {
			r.logf("tunnel %s up at %s", p.Name, t.URL)
			return t, nil
		}
		r.logf("tunnel %s failed: %v", p.Name, err)
		errs = append(errs, p.Name+": "+err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("no tunnel provider worked: %s", strings.Join(errs, "; "))
}

func (r *Runner) start(ctx context.Context, p *Provider, port int) (*Tunnel, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	var cmd *exec.Cmd
	if len(p.Raw) > 0 {
		args := make([]string, len(p.Raw))
		for i, a := range p.Raw {
			args[i] = strings.ReplaceAll(a, "{{port}}", strconv.Itoa(port))
		}
		cmd = exec.Command(args[0], args[1:]...)
	} else {
		bin := r.SSH
		if bin == "" {
			bin = "ssh"
		}
		cmd = exec.Command(bin, append(append([]string{}, sshBaseOpts...), p.Args(port)...)...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe() // stdout and stderr merged
	cmd.Stdout, cmd.Stderr = pw, pw
	cmd.WaitDelay = time.Second // do not hang on grandchildren holding the pipe
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	t := &Tunnel{Provider: p.Name, cmd: cmd, stdin: stdin, done: make(chan struct{})}
	go func() { cmd.Wait(); pw.Close(); close(t.done) }()

	urls := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		sent := false
		for sc.Scan() {
			line := sc.Text()
			if !sent {
				if u, ok := p.parseURL(line); ok {
					urls <- u
					sent = true
				}
			}
		}
	}()

	fixed := p.expandFixed(port)
	var wait <-chan time.Time
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	if fixed != "" {
		// no banner to parse: ready once the process survives a short grace period
		g := time.NewTimer(3 * time.Second)
		defer g.Stop()
		wait = g.C
	}
	select {
	case u := <-urls:
		t.URL = u
		return t, nil
	case <-wait:
		t.URL = fixed
		return t, nil
	case <-t.done:
		return nil, errors.New("ssh exited before a URL was printed")
	case <-timer.C:
		t.Close()
		return nil, fmt.Errorf("no URL after %s", timeout)
	case <-ctx.Done():
		t.Close()
		return nil, ctx.Err()
	}
}

func (p *Provider) expandFixed(port int) string {
	return strings.ReplaceAll(p.FixedURL, "{{port}}", strconv.Itoa(port))
}

var (
	ansi     = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	httpsURL = regexp.MustCompile(`https://[^\s"'<>\x1b]+`)
)

func (p *Provider) parseURL(line string) (string, bool) {
	line = ansi.ReplaceAllString(line, "")
	if p.URLRegex != nil {
		if m := p.URLRegex.FindStringSubmatch(line); m != nil {
			if len(m) > 1 {
				return m[1], true
			}
			return m[0], true
		}
		return "", false
	}
	if p.FixedURL != "" {
		return "", false
	}
	for _, m := range httpsURL.FindAllString(line, -1) {
		m = strings.TrimRight(m, ".,;:)]}")
		u, err := url.Parse(m)
		if err != nil || u.Host == "" || strings.Contains(u.Path, "/docs") {
			continue
		}
		host := strings.ToLower(u.Hostname())
		ignored := false
		for _, h := range p.IgnoreHosts {
			if host == h {
				ignored = true
			}
		}
		if ignored {
			continue
		}
		return u.Scheme + "://" + u.Host, true
	}
	return "", false
}
