package configcli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/LeafAI/securl/internal/site/generic"
)

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)

func validName(v string) error {
	if !nameRe.MatchString(v) {
		return errors.New("2-32 characters: lowercase letters, digits, - and _, starting with a letter")
	}
	return nil
}

func validPath(v string) error {
	if !strings.HasPrefix(v, "/") {
		return errors.New("a path starting with /, e.g. /api/login")
	}
	return nil
}

func validRegex(v string) error { _, err := regexp.Compile(v); return err }

// siteCustom builds a declarative (generic driver) site from answers, so no YAML has to be written.
func siteCustom(env Env) error {
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	p.Say("Describe how a person logs in to the website. The password is never stored here;")
	p.Say("the person types it when an agent needs access.\n")
	spec, err := askSpec(p)
	if err != nil {
		return err
	}
	if isBuiltin(spec.Name) {
		return fmt.Errorf("%q is the name of a built-in driver; choose another name", spec.Name)
	}
	if err := ed.SetSite(spec); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nAgents can now log in to hosts containing %q. Check it with: securl doctor -site https://<host>", spec.MatchHost)
	return nil
}

func isBuiltin(name string) bool {
	switch name {
	case "gitlab", "jenkins", "kibana", "kubesphere", "nightingale", "archery", "skywalking", "rocketmq":
		return true
	}
	return false
}

func askSpec(p *Prompter) (generic.Spec, error) {
	var spec generic.Spec
	var err error
	if spec.Name, err = p.Require("Name for this site (e.g. grafana)", "", validName); err != nil {
		return spec, err
	}
	if spec.MatchHost, err = p.Require("A part of the host name that identifies it (e.g. grafana)", spec.Name, nil); err != nil {
		return spec, err
	}
	step, err := askLoginStep(p)
	if err != nil {
		return spec, err
	}
	spec.Steps = []generic.Step{step}
	if spec.Collect, err = askCollect(p); err != nil {
		return spec, err
	}
	if spec.TwoFA, err = askTwoFA(p); err != nil {
		return spec, err
	}
	spec.Probe, err = askProbe(p)
	return spec, err
}

func askLoginStep(p *Prompter) (generic.Step, error) {
	var st generic.Step
	path, err := p.Require("Login address path (e.g. /login or /api/auth/login)", "", validPath)
	if err != nil {
		return st, err
	}
	kind, err := p.Choose("How does the login page send the credentials?", []string{"json", "form"}, "json")
	if err != nil {
		return st, err
	}
	userKey, err := p.Require("Name of the username field in the request", "username", nil)
	if err != nil {
		return st, err
	}
	passKey, err := p.Require("Name of the password field in the request", "password", nil)
	if err != nil {
		return st, err
	}
	st = generic.Step{Method: "POST", Path: path}
	if kind == "json" {
		st.JSON = map[string]any{userKey: "{{username}}", passKey: "{{password}}"}
	} else {
		st.Form = map[string]string{userKey: "{{username}}", passKey: "{{password}}"}
	}
	return st, nil
}

func askCollect(p *Prompter) (generic.Collect, error) {
	var c generic.Collect
	kind, err := p.Choose("What does the website give back after login?",
		[]string{"cookie", "token"}, "cookie")
	if err != nil {
		return c, err
	}
	if kind == "cookie" {
		return c, nil
	}
	path, err := p.Require("Where is the token in the JSON response (e.g. data.token)", "data.token", nil)
	if err != nil {
		return c, err
	}
	c.Tokens = map[string]string{"access": path}
	hdr, err := p.Ask("Send it in this header with every request", "Authorization", nil)
	if err != nil {
		return c, err
	}
	if hdr == "" {
		return c, nil
	}
	tpl := "{{token:access}}"
	if strings.EqualFold(hdr, "Authorization") {
		tpl = "Bearer " + tpl
	}
	c.Headers = map[string]string{hdr: tpl}
	return c, nil
}

func askTwoFA(p *Prompter) (*generic.TwoFA, error) {
	yes, err := p.Confirm("Does the website sometimes ask for a one-time code (2FA) after the password?", false)
	if err != nil || !yes {
		return nil, err
	}
	detect, err := p.Require("Text in the login response that shows a code is needed (a regular expression, e.g. otp_required)", "", validRegex)
	if err != nil {
		return nil, err
	}
	path, err := p.Require("Address path that receives the code (e.g. /login/otp)", "", validPath)
	if err != nil {
		return nil, err
	}
	field, err := p.Require("Name of the code field in that request", "code", nil)
	if err != nil {
		return nil, err
	}
	return &generic.TwoFA{DetectBody: detect, Step: generic.Step{Method: "POST", Path: path, Form: map[string]string{field: "{{code}}"}}}, nil
}

func askProbe(p *Prompter) (generic.Probe, error) {
	path, err := p.Ask("A page that answers 200 only when logged in, used to reuse sessions (e.g. /api/user; Enter to skip)", "", func(v string) error { return validPath(v) })
	if err != nil {
		return generic.Probe{}, err
	}
	return generic.Probe{Path: path}, nil
}
