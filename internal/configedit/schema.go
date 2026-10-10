// Package configedit changes the login config file programmatically (for `login config`) without
// disturbing what the user wrote: comments and ordering survive, values are type-checked against the
// config schema, the result is validated before it is saved, and the write is atomic with a backup.
package configedit

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LeafAI/login/internal/config"
)

var durationType = reflect.TypeOf(time.Duration(0))

// Setting describes one key that can be set from the command line.
type Setting struct {
	Path string // e.g. "dingtalk.webhook" or "aliases.<host>"
	Type string // string | bool | int | duration | list
}

func yamlName(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("yaml")
	if !ok {
		return strings.ToLower(f.Name)
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}

func fieldByYAML(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if n := yamlName(f); n != "-" && n == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

func kindName(t reflect.Type) string {
	t = deref(t)
	switch {
	case t == durationType:
		return "duration"
	case t.Kind() == reflect.Bool:
		return "bool"
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Int64:
		return "int"
	case t.Kind() == reflect.String:
		return "string"
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		return "list"
	}
	return ""
}

// resolve maps a dotted setting path to the YAML key path and the type of the value. Map keys (host names)
// may themselves contain dots: for a map of strings the rest of the path is the key.
func resolve(path string) (keys []string, leaf reflect.Type, err error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, fmt.Errorf("empty setting name")
	}
	t, rest := reflect.TypeOf(config.Config{}), path
	for {
		switch t.Kind() {
		case reflect.Struct:
			if rest == "" {
				return nil, nil, fmt.Errorf("%q is a section, not a value; one of its keys is needed (see `login config set` help)", path)
			}
			name, tail, _ := strings.Cut(rest, ".")
			f, ok := fieldByYAML(t, name)
			if !ok {
				return nil, nil, fmt.Errorf("unknown setting %q%s", path, suggest(path))
			}
			keys, t, rest = append(keys, name), deref(f.Type), tail
		case reflect.Map:
			if rest == "" {
				return nil, nil, fmt.Errorf("%q needs a key, e.g. %s.<name>", path, path)
			}
			if t.Elem().Kind() == reflect.Map {
				key, tail, _ := strings.Cut(rest, ".")
				keys, t, rest = append(keys, key), t.Elem(), tail
				continue
			}
			return append(keys, rest), deref(t.Elem()), nil
		case reflect.Slice:
			if kindName(t) == "" {
				return nil, nil, fmt.Errorf("%q is a list of entries; use `login config site add` or edit the file", path)
			}
			fallthrough
		default:
			if rest != "" {
				return nil, nil, fmt.Errorf("%q: %s has no sub-keys", path, strings.Join(keys, "."))
			}
			return keys, t, nil
		}
	}
}

// Settings lists every setting that `login config set` accepts, sorted by path.
func Settings() []Setting {
	var out []Setting
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := yamlName(f)
			if name == "-" {
				continue
			}
			ft, p := deref(f.Type), prefix+name
			switch {
			case ft.Kind() == reflect.Struct:
				walk(ft, p+".")
			case ft.Kind() == reflect.Map && ft.Elem().Kind() == reflect.Map:
				out = append(out, Setting{Path: p + ".<name>.<key>", Type: "string"})
			case ft.Kind() == reflect.Map:
				out = append(out, Setting{Path: p + ".<host>", Type: "string"})
			case kindName(ft) != "":
				out = append(out, Setting{Path: p, Type: kindName(ft)})
			}
		}
	}
	walk(reflect.TypeOf(config.Config{}), "")
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// suggest names the closest known settings for a mistyped one.
func suggest(path string) string {
	head, _, _ := strings.Cut(path, ".")
	var near []string
	for _, s := range Settings() {
		if strings.HasPrefix(s.Path, head+".") || strings.HasPrefix(s.Path, head) || strings.Contains(s.Path, path) {
			near = append(near, s.Path)
		}
	}
	if len(near) == 0 || len(near) > 8 {
		return " (run `login config set` without arguments to list the settings)"
	}
	return " (did you mean " + strings.Join(near, ", ") + "?)"
}

// valueNode builds the YAML node for value according to the setting's type.
func valueNode(t reflect.Type, value string) (*yaml.Node, error) {
	value = strings.TrimSpace(value)
	scalar := func(tag, v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: v} }
	switch kindName(t) {
	case "string":
		return scalar("!!str", value), nil
	case "bool":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not true or false", value)
		}
		return scalar("!!bool", strconv.FormatBool(b)), nil
	case "int":
		n, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not a whole number", value)
		}
		return scalar("!!int", strconv.Itoa(n)), nil
	case "duration":
		if _, err := time.ParseDuration(value); err != nil {
			return nil, fmt.Errorf("%q is not a duration such as 30s, 10m or 24h", value)
		}
		return scalar("!!str", value), nil
	case "list":
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				seq.Content = append(seq.Content, scalar("!!str", part))
			}
		}
		return seq, nil
	}
	return nil, fmt.Errorf("unsupported setting type %s", t)
}
