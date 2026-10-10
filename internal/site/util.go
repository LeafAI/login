package site

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JarClient returns a client sharing hc's transport/timeout but with its own cookie jar.
func JarClient(hc *http.Client) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if hc != nil {
		c.Transport, c.Timeout, c.CheckRedirect = hc.Transport, hc.Timeout, hc.CheckRedirect
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	return c
}

// NoRedirect returns a copy of c that does not follow redirects.
func NoRedirect(c *http.Client) *http.Client {
	n := *c
	n.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &n
}

// ReadBody reads at most 2 MiB of the response body and closes it.
func ReadBody(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return string(b)
}

// CookiesFrom returns the cookies the jar would send to base.
func CookiesFrom(c *http.Client, base *url.URL) []*http.Cookie { return c.Jar.Cookies(base) }

// CookieHeader renders cookies as a Cookie request header value.
func CookieHeader(cs []*http.Cookie) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

var twoFA = regexp.MustCompile(`(?i)\b(otp|totp|mfa|2fa|two[- ]?factor|verification code|authenticator|one[- ]time)\b`)

// Looks2FA reports whether a response body looks like a second-factor prompt/requirement.
// Drivers use it only on responses that already indicate "login not complete".
func Looks2FA(body string) bool { return twoFA.MatchString(body) }

// Clip shortens s for use in error messages.
func Clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Standard field sets.
var (
	LoginFields = []Field{{Name: "username", Label: "Username"}, {Name: "password", Label: "Password", Secret: true}}
	TOTPFields  = []Field{{Name: "code", Label: "One-time code"}}
)
