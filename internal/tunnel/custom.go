package tunnel

import (
	"fmt"
	"regexp"
	"strings"
)

// Custom builds a provider from configuration. command is the full command line with {{port}}.
func Custom(name, command, fixedURL, urlRegex string) (*Provider, error) {
	args, err := splitArgs(command)
	if err != nil || len(args) == 0 {
		return nil, fmt.Errorf("provider %s: bad command %q", name, command)
	}
	p := &Provider{Name: name, Raw: args, FixedURL: fixedURL}
	if urlRegex != "" {
		if p.URLRegex, err = regexp.Compile(urlRegex); err != nil {
			return nil, fmt.Errorf("provider %s: bad url_regex: %w", name, err)
		}
	}
	if fixedURL == "" && urlRegex == "" {
		p.URLRegex = regexp.MustCompile(`https://[^\s"'<>]+`)
	}
	return p, nil
}

// splitArgs splits a command line honouring single and double quotes.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	has := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, has = r, true
		case r == ' ' || r == '\t':
			if has || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if has || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out, nil
}
