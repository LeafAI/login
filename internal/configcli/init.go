package configcli

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/configedit"
)

func validWebhook(v string) error {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("expected the robot's https webhook address, https://oapi.dingtalk.com/robot/send?access_token=...")
	}
	if u.Query().Get("access_token") == "" {
		return errors.New("the address has no access_token=... part; copy the whole webhook from the DingTalk robot settings")
	}
	return nil
}

func validMobiles(v string) error {
	for _, m := range strings.Split(v, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		for _, r := range m {
			if r < '0' || r > '9' {
				return fmt.Errorf("%q is not a phone number (digits only, separate several with commas)", m)
			}
		}
	}
	return nil
}

// cmdInit walks a new user through the settings that are needed before the first login.
func cmdInit(env Env) error {
	p := prompter(env)
	ed, err := openEditor(env)
	if err != nil {
		return err
	}
	cur := func(k string) string { v, _, _ := ed.Get(k); return v }

	p.Say("login setup. Press Enter to keep the value in [brackets]. Nothing is saved until the end.\n")
	p.Say("1) DingTalk robot. A person receives the login link here. Create a custom robot in a DingTalk group")
	p.Say("   (Group settings > Robots > Add > Custom) and copy its webhook address.")
	webhook, err := askSecretURL(p, cur("dingtalk.webhook"))
	if err != nil {
		return err
	}
	secret, err := p.Secret("   Signing secret (only if the robot uses \"sign\", starts with SEC)", cur("dingtalk.secret") != "")
	if err != nil {
		return err
	}
	keyword, err := p.Ask("   Keyword (only if the robot requires one; the messages will contain it)", cur("dingtalk.keyword"), nil)
	if err != nil {
		return err
	}
	mobiles, err := p.Ask("   Phone numbers to @mention, comma separated (optional)", cur("dingtalk.at_mobiles"), validMobiles)
	if err != nil {
		return err
	}

	p.Say("\n2) Safety")
	hosts, err := p.Ask("   Websites an agent may log in to, e.g. *.corp.example (empty = any website)", cur("security.allowed_hosts"), nil)
	if err != nil {
		return err
	}
	persist, err := p.Confirm("   Keep logins (encrypted) between restarts so people are asked less often?", cur("sessions.persist") == "true")
	if err != nil {
		return err
	}

	set := func(k, v string) error {
		if v == "" {
			_, err := ed.Unset(k)
			return err
		}
		return ed.Set(k, v)
	}
	for _, kv := range [][2]string{
		{"dingtalk.webhook", webhook}, {"dingtalk.keyword", keyword},
		{"dingtalk.at_mobiles", mobiles}, {"security.allowed_hosts", hosts},
	} {
		if err := set(kv[0], kv[1]); err != nil {
			return err
		}
	}
	if secret != "" {
		if err := ed.Set("dingtalk.secret", secret); err != nil {
			return err
		}
	}
	if err := ed.Set("sessions.persist", fmt.Sprint(persist)); err != nil {
		return err
	}
	if err := commit(env, ed); err != nil {
		return err
	}
	return finishInit(env, p, ed)
}

func askSecretURL(p *Prompter, current string) (string, error) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		v, err := p.Secret("   Webhook address", current != "")
		if err != nil {
			return "", err
		}
		if v == "" && current != "" {
			return current, nil
		}
		if err := validWebhook(v); err != nil {
			p.Say("  ! %v", err)
			continue
		}
		return strings.TrimSpace(v), nil
	}
	return "", errors.New("webhook: too many invalid answers")
}

func finishInit(env Env, p *Prompter, ed *configedit.Editor) error {
	if env.SendTest != nil {
		if ok, err := p.Confirm("\nSend a test message to the DingTalk group now?", true); err == nil && ok {
			cfg, err := parseEditor(ed)
			if err != nil {
				return err
			}
			if err := env.SendTest(cfg.DingTalk.Webhook, cfg.DingTalk.Secret, cfg.DingTalk.Keyword, cfg.DingTalk.Mobiles); err != nil {
				p.Say("  ! the test message failed: %v", err)
				p.Say("  Check the webhook, the signing secret and the keyword, then run `login config init` again.")
			} else {
				p.Say("  sent; look for it in the group")
			}
		}
	}
	p.Say("\nNext: add the websites your agents use with `login config site add`,")
	p.Say("then check everything with `login doctor` and register the server: claude mcp add login -- login")
	return nil
}
