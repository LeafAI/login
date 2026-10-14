// Package netguard builds the HTTP client login uses to reach the sites an agent asks about.
//
// The agent chooses the URL, so the client must not become a way to reach things on the machine that
// the agent has no business with: loopback services, the cloud metadata endpoint, link-local devices.
// Private (RFC 1918) networks stay reachable, because that is where the sites login serves live.
// Redirects that leave the site are not followed, which also stops a site from bouncing a login
// request, body and all, to a second host.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"
)

// Policy configures New.
type Policy struct {
	// AllowLocal turns the address checks off (security.allow_local_addresses), for development against a
	// service on this machine.
	AllowLocal bool
	// AllowedHosts are the patterns of security.allowed_hosts. A redirect may leave the site only for a
	// host that matches one of them.
	AllowedHosts []string
	// Proxy chooses the proxy for a request; nil means the environment (HTTP_PROXY and friends).
	Proxy   func(*http.Request) (*url.URL, error)
	Timeout time.Duration // default 30s
}

// ErrBlocked is returned for an address the policy refuses.
var ErrBlocked = errors.New("connection not permitted: loopback, link-local and cloud-metadata addresses are refused (security.allow_local_addresses lifts this)")

var blockedNets = mustCIDRs("0.0.0.0/8", "100.100.100.200/32", "fd00:ec2::254/128")

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("netguard: bad built-in CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}

// Blocked reports whether ip is an address login must not connect to. An address that cannot be parsed
// is blocked.
func Blocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// LocalHost reports whether host (a name or an address, with or without a port) is a local name or a
// blocked address.
func LocalHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	switch {
	case h == "":
		return false
	case h == "localhost" || strings.HasSuffix(h, ".localhost"):
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return Blocked(ip)
	}
	return false
}

// New returns a client that applies p.
func New(p Policy) *http.Client {
	if p.Timeout == 0 {
		p.Timeout = 30 * time.Second
	}
	proxy := p.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	direct := &http.Transport{
		DialContext:         newDialer(p.AllowLocal).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConns:        20,
		IdleConnTimeout:     60 * time.Second,
	}
	viaProxy := direct.Clone()
	viaProxy.Proxy = proxy
	viaProxy.DialContext = newDialer(true).DialContext // the proxy itself may well be a local process
	return &http.Client{
		Timeout:       p.Timeout,
		Transport:     &guard{allowLocal: p.AllowLocal, proxy: proxy, direct: direct, viaProxy: viaProxy},
		CheckRedirect: redirectPolicy(p.AllowedHosts),
	}
}

// DialContext returns a function that opens a TCP connection under the same rule as the HTTP client: unless allowLocal is
// set, the address about to be connected to (after name resolution) must not be loopback, link-local or a cloud
// metadata address. The database drivers use it.
func DialContext(allowLocal bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return newDialer(allowLocal).DialContext
}

// newDialer returns the dialer for direct connections. Unless local addresses are allowed it checks the
// address it is about to connect to, after name resolution.
func newDialer(allowLocal bool) *net.Dialer {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if !allowLocal {
		d.Control = checkConnectAddress
	}
	return d
}

// checkConnectAddress runs after name resolution, on the address about to be connected to, so a name
// that points at a blocked address (including by DNS rebinding) is refused too.
func checkConnectAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlocked
	}
	if Blocked(net.ParseIP(host)) {
		return ErrBlocked
	}
	return nil
}

// guard sends a request through the proxy when there is one for it, otherwise straight out. Through a
// proxy the connection is made by the proxy, so the target is checked here by name or literal address.
type guard struct {
	allowLocal       bool
	proxy            func(*http.Request) (*url.URL, error)
	direct, viaProxy *http.Transport
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if !g.allowLocal && LocalHost(req.URL.Hostname()) {
		return nil, ErrBlocked
	}
	if pu, err := g.proxy(req); err == nil && pu != nil {
		return g.viaProxy.RoundTrip(req)
	}
	return g.direct.RoundTrip(req)
}

const maxRedirects = 10

// redirectPolicy follows a redirect only while it stays on the site the request started at (same host and
// port; http may become https, never the reverse), or goes to a host in allowed. Anything else is not
// followed: the redirect response is handed back and no request is made.
func redirectPolicy(allowed []string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if len(via) == 0 {
			return nil
		}
		origin := via[0].URL
		for _, r := range append(append([]*http.Request{}, via[1:]...), req) {
			if !stays(origin, r.URL, allowed) {
				return http.ErrUseLastResponse
			}
		}
		return nil
	}
}

func stays(origin, next *url.URL, allowed []string) bool {
	if origin.Scheme == "https" && next.Scheme != "https" {
		return false
	}
	if sameSite(origin, next) {
		return true
	}
	return matchesAny(allowed, next)
}

func sameSite(a, b *url.URL) bool {
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	pa, pb := portOf(a), portOf(b)
	return pa == pb || (a.Scheme == "http" && b.Scheme == "https" && pa == "80" && pb == "443")
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func matchesAny(patterns []string, u *url.URL) bool {
	for _, pat := range patterns {
		for _, h := range []string{u.Host, u.Hostname()} {
			if ok, _ := path.Match(strings.ToLower(pat), strings.ToLower(h)); ok {
				return true
			}
		}
	}
	return false
}
