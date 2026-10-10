package configedit

import (
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// secretPaths are the settings whose values must not be echoed to a terminal.
var secretPaths = [][]string{{"dingtalk", "secret"}, {"dingtalk", "webhook"}}

// Mask hides all but the last 4 characters of a secret; short values are hidden entirely. A DingTalk
// webhook keeps its address and only the access_token is masked.
func Mask(v string) string {
	if v == "" {
		return ""
	}
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		if q := u.Query(); q.Get("access_token") != "" {
			q.Set("access_token", Mask(q.Get("access_token")))
			u.RawQuery = strings.ReplaceAll(q.Encode(), "%2A", "*")
			return u.String()
		}
	}
	if len(v) <= 8 {
		return "****"
	}
	return "****" + v[len(v)-4:]
}

// IsSecret reports whether a dotted setting path holds a secret.
func IsSecret(path string) bool {
	for _, p := range secretPaths {
		if strings.Join(p, ".") == path {
			return true
		}
	}
	return false
}

// Redacted renders the document with secrets masked (safe to print).
func (e *Editor) Redacted() ([]byte, error) {
	b, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	cp := &Editor{path: e.path, root: e.root}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		cp.root = doc.Content[0]
	}
	for _, p := range secretPaths {
		if parent := cp.parent(p, false); parent != nil {
			if n := mapGet(parent, p[len(p)-1]); n != nil && n.Kind == yaml.ScalarNode {
				n.Value = Mask(n.Value)
			}
		}
	}
	return cp.Bytes()
}
