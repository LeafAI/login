package configcli

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/LeafAI/securl/internal/configedit"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/site"
)

func cmdSite(env Env, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: securl config site add [url] | custom | list | remove <host|name>")
	}
	switch args[0] {
	case "add":
		return siteAdd(env, args[1:])
	case "custom":
		return siteCustom(env)
	case "list":
		return siteList(env)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: securl config site remove <host|name>")
		}
		return siteRemove(env, args[1])
	}
	return fmt.Errorf("unknown site command %q (add, custom, list, remove)", args[0])
}

func parseSiteURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%q is not a website address (try https://gitlab.corp.example)", raw)
	}
	return u, nil
}

func validURL(v string) error { _, err := parseSiteURL(v); return err }

// siteAdd records everything the tools need to log in to one website: which driver handles it, a path
// prefix when the site is not at the root, and the driver's own options.
func siteAdd(env Env, args []string) error {
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	if cfg, err := parseEditor(ed); err == nil {
		_ = registerSites(cfg) // so custom sites can be picked as drivers
	}
	raw := ""
	if len(args) > 0 {
		raw = args[0]
	}
	if raw == "" {
		if raw, err = p.Require("Website address (e.g. https://gitlab.corp.example)", "", validURL); err != nil {
			return err
		}
	}
	u, err := parseSiteURL(raw)
	if err != nil {
		return err
	}
	driver, err := pickDriver(p, u)
	if err != nil {
		return err
	}
	if err := recordHost(p, ed, u, driver); err != nil {
		return err
	}
	if err := askDriverOptions(p, ed, driver); err != nil {
		return err
	}
	if err := offerAllowedHost(p, ed, u); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	p.Say("\nNo password is needed here: the person is asked when an agent first logs in.")
	p.Say("Check what securl will do with this site (no credentials sent): securl doctor -site %s", u.Scheme+"://"+u.Host)
	return nil
}

// pickDriver auto-detects the driver from the address and lets the user confirm or choose another.
func pickDriver(p *Prompter, u *url.URL) (string, error) {
	names := site.Names()
	detected := ""
	if d, err := site.Resolve("", &url.URL{Scheme: u.Scheme, Host: u.Host}); err == nil {
		detected = d.Name()
	}
	if detected != "" {
		ok, err := p.Confirm(fmt.Sprintf("Detected the %q driver from the address. Use it?", detected), true)
		if err != nil {
			return "", err
		}
		if ok {
			return detected, nil
		}
	} else {
		p.Say("The address does not say which product it is, so pick the driver:")
	}
	return p.Choose("Which kind of website is this?", names, detected)
}

// recordHost stores what is needed so the tools pick `driver` for this host, and the path prefix if any.
func recordHost(p *Prompter, ed *configedit.Editor, u *url.URL, driver string) error {
	probe := &url.URL{Scheme: u.Scheme, Host: u.Host}
	if d, err := site.Resolve("", probe); err != nil || d.Name() != driver {
		if err := ed.Set("aliases."+u.Host, driver); err != nil {
			return err
		}
		p.Say("  -> %s will be handled by the %s driver", u.Host, driver)
	}
	prefix := strings.TrimRight(u.Path, "/")
	if prefix == "" {
		var err error
		if prefix, err = p.Ask("Is the site served under a path, e.g. /kibana? (Enter if it is at the root)", "", validPrefix); err != nil {
			return err
		}
	}
	if prefix = strings.TrimRight(strings.TrimSpace(prefix), "/"); prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		return ed.Set("roots."+u.Host, u.Scheme+"://"+u.Host+prefix)
	}
	return nil
}

var prefixRe = regexp.MustCompile(`^/?[A-Za-z0-9._~\-/]*$`)

func validPrefix(v string) error {
	if !prefixRe.MatchString(v) {
		return errors.New("a path such as /kibana (letters, digits and - _ . / only)")
	}
	return nil
}

// askDriverOptions asks for each option the driver declares, showing the current value as the default.
func askDriverOptions(p *Prompter, ed *configedit.Editor, driver string) error {
	opts := site.OptionsOf(driver)
	if len(opts) == 0 {
		p.Say("The %s driver needs no further settings.", driver)
		return nil
	}
	p.Say("\nSettings for the %s driver (Enter accepts the default):", driver)
	for _, o := range opts {
		path := "site_options." + driver + "." + o.Key
		cur, has, _ := ed.Get(path)
		def := o.Default
		if has {
			def = cur
		}
		if o.Help != "" {
			p.Say("  %s", o.Help)
		}
		var v string
		var err error
		if len(o.Choices) > 0 && !o.FreeText {
			v, err = p.Choose(o.Label, o.Choices, def)
		} else {
			label := o.Label
			if len(o.Choices) > 0 {
				label += " (" + strings.Join(o.Choices, ", ") + ", or a name)"
			}
			v, err = p.Ask(label, def, o.Validate)
		}
		if err != nil {
			return err
		}
		switch {
		case v == "" || v == o.Default && !has:
			// not worth storing: the driver's own default applies
		default:
			if err := ed.Set(path, v); err != nil {
				return err
			}
		}
		if v == "" && has {
			if _, err := ed.Unset(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// offerAllowedHost keeps an existing allow-list working for the website that was just added.
func offerAllowedHost(p *Prompter, ed *configedit.Editor, u *url.URL) error {
	cur, ok, _ := ed.Get("security.allowed_hosts")
	if !ok || cur == "" {
		return nil
	}
	cfg, err := parseEditor(ed)
	if err != nil {
		return err
	}
	if mcpserver.HostAllowed(cfg, &url.URL{Scheme: u.Scheme, Host: u.Host}) {
		return nil
	}
	yes, err := p.Confirm(fmt.Sprintf("security.allowed_hosts is set and does not include %s, so agents could not use it. Add it?", u.Host), true)
	if err != nil || !yes {
		return err
	}
	return ed.Set("security.allowed_hosts", cur+","+u.Host)
}

func siteList(env Env) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	cfg, err := parseEditor(ed)
	if err != nil {
		return err
	}
	if err := registerSites(cfg); err != nil {
		return err
	}
	fmt.Fprintln(env.Out, "drivers:")
	for _, n := range site.Names() {
		extra := ""
		if o := site.OptionsOf(n); len(o) > 0 {
			var k []string
			for _, x := range o {
				k = append(k, x.Key)
			}
			extra = "  (options: " + strings.Join(k, ", ") + ")"
		}
		fmt.Fprintf(env.Out, "  %s%s\n", n, extra)
	}
	fmt.Fprintln(env.Out, "\nconfigured websites:")
	hosts := map[string]bool{}
	for h := range cfg.Aliases {
		hosts[h] = true
	}
	for h := range cfg.Roots {
		hosts[h] = true
	}
	var list []string
	for h := range hosts {
		list = append(list, h)
	}
	sort.Strings(list)
	for _, h := range list {
		line := "  " + h
		if a := cfg.Aliases[h]; a != "" {
			line += "  driver=" + a
		}
		if r := cfg.Roots[h]; r != "" {
			line += "  root=" + r
		}
		fmt.Fprintln(env.Out, line)
	}
	for _, s := range cfg.Sites {
		fmt.Fprintf(env.Out, "  %s  custom site, matches hosts containing %q\n", s.Name, s.MatchHost)
	}
	if len(list) == 0 && len(cfg.Sites) == 0 {
		fmt.Fprintln(env.Out, "  (none; sites whose host name contains the product name, e.g. gitlab.corp.example, work without any setting)")
	}
	return nil
}

func siteRemove(env Env, what string) error {
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	host := strings.TrimSpace(what)
	removed := ed.RemoveSite(host)
	for _, k := range []string{"aliases.", "roots."} {
		if ok, err := ed.Unset(k + host); err != nil {
			return err
		} else if ok {
			removed = true
		}
	}
	if !removed {
		return fmt.Errorf("nothing is configured for %q (see `securl config site list`)", host)
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "removed the settings for %s\n", host)
	return nil
}
