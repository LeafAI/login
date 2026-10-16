package site

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// ErrRequestRefused is what a site's request policy answers for a request it does not allow. The request is not sent.
var ErrRequestRefused = errors.New("the site's request policy does not allow this request")

// RequestPolicy is implemented by a driver for a site whose HTTP interface has write operations the agent must not reach
// through the request tool (a dashboard whose ".do" paths delete topics and reset offsets, say). The request tool asks it
// before anything is sent. A driver that does not implement it is not restricted.
//
// The policy is the driver's knowledge of the product, and the owner's switches (site_options) widen it; the agent can do
// neither. A refusal sends nothing: whatever the site would have done with the request, it never hears of it.
type RequestPolicy interface {
	// CheckRequest says whether a request with this method and absolute path may be sent. A nil answer allows it.
	CheckRequest(method, path string) error
}

// CheckRequest applies the driver's request policy, if it has one.
func CheckRequest(d Driver, method, path string) error {
	if p, ok := d.(RequestPolicy); ok {
		return p.CheckRequest(method, path)
	}
	return nil
}

// AllowList is a request policy that lists what may pass and refuses everything else, so a path nobody has thought of (a new
// version of the product adds a write operation) is refused until somebody allows it.
type AllowList struct {
	// Methods are the HTTP methods that may be used (compared case-insensitively).
	Methods []string
	// Suffix, when set, lets a path through if it ends with it.
	Suffix string
	// Exact lists paths that pass whether or not they end with Suffix.
	Exact []string
	// Deny lists path prefixes that are refused even if they would otherwise pass (compared case-insensitively).
	Deny []string
}

// Check applies the list.
//
// The path is judged as the site will read it. A path that is not already in its cleanest form (a dot segment, a doubled
// slash, a trailing slash), that holds an escape (%2e, %2f, a letter written as %XX), a backslash, a semicolon, a control
// character, a query or a fragment, is refused outright: cleaning it and letting the result through would mean the check
// and the site read different paths, and every way of doing that has been a way around a filter.
func (a AllowList) Check(method, p string) error {
	if !a.allowsMethod(method) {
		return refuse("the method %q is not allowed (allowed: %s)", clip(method), strings.Join(a.Methods, ", "))
	}
	if why := unreadable(p); why != "" {
		return refuse("the path %s", why)
	}
	if path.Clean(p) != p {
		return refuse("the path is not in its plain form (no dot segments, doubled or trailing slashes)")
	}
	low := strings.ToLower(p)
	for _, d := range a.Deny {
		if strings.HasPrefix(low, strings.ToLower(d)) {
			return refuse("paths under %s are not allowed through this tool (the owner can open them in the site's options)", d)
		}
	}
	for _, e := range a.Exact {
		if p == e {
			return nil
		}
	}
	if a.Suffix != "" && strings.HasSuffix(p, a.Suffix) && len(p) > len(a.Suffix)+1 {
		return nil
	}
	return refuse("only paths ending in %s are allowed", a.Suffix)
}

func (a AllowList) allowsMethod(m string) bool {
	if m != strings.TrimSpace(m) || m == "" {
		return false
	}
	for _, x := range a.Methods {
		if strings.EqualFold(x, m) {
			return true
		}
	}
	return false
}

// unreadable names what is wrong with a path that cannot be judged as written, or "" when it is plain.
func unreadable(p string) string {
	switch {
	case p == "" || p[0] != '/':
		return "must be an absolute path starting with /"
	case strings.ContainsAny(p, "?#"):
		return "must not carry a query or a fragment (use the query field)"
	case strings.ContainsAny(p, `\;`):
		return "holds a character the site might read as something else"
	case strings.Contains(p, "%"):
		if dec, err := url.PathUnescape(p); err != nil || dec != p {
			return "holds an escape: write the path as it is"
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f || p[i] == ' ' {
			return "holds a control character or a space"
		}
	}
	return ""
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRequestRefused, fmt.Sprintf(format, a...))
}

func clip(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}
