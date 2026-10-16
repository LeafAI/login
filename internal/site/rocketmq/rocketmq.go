// Package rocketmq logs in to the Apache RocketMQ Dashboard and restricts what the request tool may send to it.
//
// What the Dashboard is, checked against the production one and the 2.0.1 image: an AngularJS console whose server
// answers JSON for ".query" paths (reads) and ".do" paths (writes: create and delete topics, reset offsets, send a message,
// change the name server). Login is POST /login/login.do with the account in the QUERY STRING, answered with
// {"status":0,"data":{"loginUserName","loginUserRole",...}} and a JSESSIONID cookie; a wrong password is HTTP 200 with
// "status":-1, so the status in the body is what counts. There is no CSRF token. Read without a session is a 302 to the
// login page.
//
// Two things follow, and the driver handles both:
//
//   - The password travels in a URL, which the Dashboard's own front end does too, and which a gateway or the Dashboard
//     may log. The account must therefore be a Dashboard account used for nothing else.
//   - The Dashboard's "normal user" does refuse the writes ("no permission", checked on 2.0.1), but a role is not a
//     boundary securl should lean on: the request tool lets through only GET of ".query" paths, and never a path under
//     /message/ (the bodies of messages) unless the owner opens it with site_options.rocketmq.allow_message_body.
package rocketmq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct {
	mu   sync.RWMutex
	opts map[string]string
}

func init() { site.Register(&driver{}) }

func (*driver) Name() string     { return "rocketmq" }
func (*driver) NeedsLogin() bool { return true }
func (*driver) Match(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	return strings.Contains(h, "rocketmq") || strings.Contains(h, "-mq.") || strings.HasPrefix(h, "mq.") || strings.Contains(h, "rmq-")
}

// Configure takes the site_options of this driver.
func (d *driver) Configure(opts map[string]string) {
	d.mu.Lock()
	d.opts = opts
	d.mu.Unlock()
}

// Options lists the settings `securl config` offers for the Dashboard.
func (*driver) Options() []site.Option {
	return []site.Option{{
		Key:     "allow_message_body",
		Label:   "May the agent read the bodies of messages?",
		Help:    "no (the default) keeps everything under /message/ out of the request tool: a message can hold any business data. yes opens it.",
		Choices: []string{"no", "yes"}, Default: "no",
	}}
}

func (d *driver) allowBody() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return strings.EqualFold(strings.TrimSpace(d.opts["allow_message_body"]), "yes")
}

// CheckRequest is the request policy: GET of ".query" paths, and the check of the login state, and nothing else. A path under
// /message/ is read only when the owner has opened it.
func (d *driver) CheckRequest(method, path string) error {
	deny := []string{"/message/", "/messageTrace/", "/dlqMessage/"}
	if d.allowBody() {
		deny = nil
	}
	return site.AllowList{Methods: []string{"GET"}, Suffix: ".query", Deny: deny}.Check(method, path)
}

type reply struct {
	Status int             `json:"status"`
	Data   json.RawMessage `json:"data"`
	ErrMsg string          `json:"errMsg"`
}

// Login asks for the account and logs in once: a wrong attempt is counted by whatever guards the account behind the
// Dashboard, so there is no second try on a different footing.
func (d *driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	user, pass := strings.TrimSpace(creds["username"]), creds["password"]
	creds["password"] = ""
	if user == "" || pass == "" {
		return nil, fmt.Errorf("%w: the username and the password are both needed", site.ErrBadCredentials)
	}
	c := site.JarClient(hc)
	q := url.Values{"username": {user}, "password": {pass}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base.String(), "/")+"/login/login.do?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", site.ErrLoginRejected, "the address is not usable")
	}
	resp, err := site.NoRedirect(c).Do(req)
	if err != nil {
		return nil, site.Unreachable(scrub(err, pass))
	}
	body := site.ReadBody(resp)
	if site.TemporaryStatus(resp.StatusCode) {
		return nil, site.ProbeStatus("rocketmq", resp.StatusCode)
	}
	var r reply
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &r) != nil {
		return nil, fmt.Errorf("%w: %s did not answer like the RocketMQ Dashboard (HTTP %d)", site.ErrLoginRejected, base.Host, resp.StatusCode)
	}
	if r.Status != 0 {
		return nil, fmt.Errorf("%w: the Dashboard refused that username or password", site.ErrBadCredentials)
	}
	cookies := c.Jar.Cookies(base)
	if len(cookies) == 0 {
		return nil, fmt.Errorf("%w: the Dashboard accepted the login but set no session", site.ErrLoginRejected)
	}
	return &site.Session{Cookies: cookies}, nil
}

// Probe asks the Dashboard whether it still knows the session: /login/check.query answers logined:true for a live one.
func (*driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base.String(), "/")+"/login/check.query", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	resp, err := site.NoRedirect(hc).Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	body := site.ReadBody(resp)
	if resp.StatusCode != http.StatusOK {
		return site.ProbeStatus("rocketmq", resp.StatusCode)
	}
	var r struct {
		Data struct {
			Logined bool `json:"logined"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &r) != nil || !r.Data.Logined {
		return errors.New("rocketmq session invalid: the Dashboard does not know it")
	}
	return nil
}

// scrub removes the password from a transport error: the URL of the request holds it, and Go's client quotes the URL.
func scrub(err error, secrets ...string) error {
	msg := err.Error()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, s, "***")
		msg = strings.ReplaceAll(msg, url.QueryEscape(s), "***")
	}
	return errors.New(msg)
}
