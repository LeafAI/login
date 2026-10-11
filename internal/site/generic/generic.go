// Package generic builds login drivers from declarative YAML, so any form/JSON login can be added
// without Go code.
package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/LeafAI/securl/internal/site"
)

type Step struct {
	Method       string            `yaml:"method"`
	Path         string            `yaml:"path"`
	Form         map[string]string `yaml:"form,omitempty"`
	JSON         map[string]any    `yaml:"json,omitempty"`
	Headers      map[string]string `yaml:"headers,omitempty"`
	ExpectStatus []int             `yaml:"expect_status,omitempty"`
}

type TwoFA struct {
	DetectBody string `yaml:"detect_body,omitempty"` // regex on the last response body
	Step       Step   `yaml:"step,omitempty"`        // uses {{code}}
}

type Collect struct {
	Tokens  map[string]string `yaml:"tokens,omitempty"`  // name -> dotted JSON path in the last response
	Headers map[string]string `yaml:"headers,omitempty"` // header -> template, {{token:name}} allowed
}

type Probe struct {
	Path         string `yaml:"path"`
	ExpectStatus int    `yaml:"expect_status,omitempty"`
}

type Spec struct {
	Name      string  `yaml:"name"`
	MatchHost string  `yaml:"match_host,omitempty"`
	Steps     []Step  `yaml:"steps"`
	TwoFA     *TwoFA  `yaml:"twofa,omitempty"`
	Collect   Collect `yaml:"collect,omitempty"`
	Probe     Probe   `yaml:"probe,omitempty"`
}

type driver struct {
	spec Spec
	re2  *regexp.Regexp
}

// New validates spec and returns a driver.
func New(spec Spec) (site.Driver, error) {
	if spec.Name == "" || len(spec.Steps) == 0 {
		return nil, fmt.Errorf("generic site needs a name and at least one step")
	}
	d := &driver{spec: spec}
	if spec.TwoFA != nil && spec.TwoFA.DetectBody != "" {
		var err error
		if d.re2, err = regexp.Compile(spec.TwoFA.DetectBody); err != nil {
			return nil, fmt.Errorf("site %s: bad twofa.detect_body: %w", spec.Name, err)
		}
	}
	return d, nil
}

func (d *driver) Name() string     { return d.spec.Name }
func (d *driver) NeedsLogin() bool { return true }
func (d *driver) Match(u *url.URL) bool {
	return d.spec.MatchHost != "" && strings.Contains(strings.ToLower(u.Hostname()), strings.ToLower(d.spec.MatchHost))
}

func expand(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func expandAny(v any, vars map[string]string) any {
	switch x := v.(type) {
	case string:
		return expand(x, vars)
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = expandAny(e, vars)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, e := range x {
			out[fmt.Sprint(k)] = expandAny(e, vars)
		}
		return out
	}
	return v
}

func (d *driver) run(ctx context.Context, c *http.Client, base *url.URL, st Step, vars map[string]string) (int, string, error) {
	method := st.Method
	if method == "" {
		method = "POST"
	}
	var body *bytes.Reader
	ct := ""
	switch {
	case st.JSON != nil:
		b, _ := json.Marshal(expandAny(st.JSON, vars))
		body, ct = bytes.NewReader(b), "application/json"
	case st.Form != nil:
		f := url.Values{}
		for k, v := range st.Form {
			f.Set(k, expand(v, vars))
		}
		body, ct = bytes.NewReader([]byte(f.Encode())), "application/x-www-form-urlencoded"
	default:
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, base.String()+expand(st.Path, vars), body)
	if err != nil {
		return 0, "", err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for k, v := range st.Headers {
		req.Header.Set(k, expand(v, vars))
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return resp.StatusCode, site.ReadBody(resp), nil
}

func okStatus(st Step, code int) bool {
	if len(st.ExpectStatus) == 0 {
		return code >= 200 && code < 300
	}
	for _, c := range st.ExpectStatus {
		if c == code {
			return true
		}
	}
	return false
}

func (d *driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	c := site.JarClient(hc)
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{"username": creds["username"], "password": creds["password"]}
	var last string
	for i, st := range d.spec.Steps {
		code, body, err := d.run(ctx, c, base, st, vars)
		if err != nil {
			return nil, err
		}
		if !okStatus(st, code) {
			return nil, fmt.Errorf("%w: step %d returned %d: %s", site.ErrBadCredentials, i+1, code, site.Clip(body, 160))
		}
		last = body
	}
	if d.spec.TwoFA != nil && d.re2 != nil && d.re2.MatchString(last) {
		code, err := ask.Ask(ctx, "totp", site.TOTPFields)
		if err != nil {
			return nil, err
		}
		vars["code"] = strings.TrimSpace(code["code"])
		status, body, err := d.run(ctx, c, base, d.spec.TwoFA.Step, vars)
		if err != nil {
			return nil, err
		}
		if !okStatus(d.spec.TwoFA.Step, status) || d.re2.MatchString(body) {
			return nil, fmt.Errorf("%w: invalid two-factor code", site.ErrBadCredentials)
		}
		last = body
	}
	s := &site.Session{Cookies: site.CookiesFrom(c, base), Tokens: map[string]string{}, Headers: map[string]string{}}
	var parsed any
	json.Unmarshal([]byte(last), &parsed)
	for name, path := range d.spec.Collect.Tokens {
		if v, ok := dig(parsed, path); ok {
			s.Tokens[name] = v
		}
	}
	tv := map[string]string{}
	for k, v := range s.Tokens {
		tv["token:"+k] = v
	}
	for h, tpl := range d.spec.Collect.Headers {
		s.Headers[h] = expand(tpl, tv)
	}
	if len(s.Cookies) == 0 && len(s.Tokens) == 0 {
		return nil, fmt.Errorf("%w: login produced neither cookies nor tokens", site.ErrLoginRejected)
	}
	return s, nil
}

func dig(v any, path string) (string, bool) {
	for _, p := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		if v, ok = m[p]; !ok {
			return "", false
		}
	}
	switch x := v.(type) {
	case string:
		return x, true
	case float64, bool:
		return fmt.Sprint(x), true
	}
	return "", false
}

func (d *driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	if d.spec.Probe.Path == "" {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+d.spec.Probe.Path, nil)
	if len(s.Cookies) > 0 {
		req.Header.Set("Cookie", site.CookieHeader(s.Cookies))
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	want := d.spec.Probe.ExpectStatus
	if want == 0 {
		want = 200
	}
	if resp.StatusCode != want {
		return fmt.Errorf("%s session invalid: %s", d.spec.Name, resp.Status)
	}
	return nil
}
