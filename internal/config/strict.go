package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseStrict reports fields in b that Config does not know (typos); it does not apply defaults. Each
// problem names the key, its line and the section it was found in, and suggests the closest valid key.
// Values are never echoed, because a mistyped key may sit next to a secret.
func ParseStrict(b []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	err := dec.Decode(&Config{})
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return err
	}
	lines := make([]string, 0, len(te.Errors))
	for _, e := range te.Errors {
		lines = append(lines, explain(e))
	}
	return fmt.Errorf("invalid configuration:\n  %s", strings.Join(lines, "\n  "))
}

var unknownField = regexp.MustCompile(`^line (\d+): field (\S+) not found in type (\S+)$`)

func explain(msg string) string {
	m := unknownField.FindStringSubmatch(msg)
	if m == nil {
		return msg
	}
	line, key, typ := m[1], m[2], m[3]
	out := fmt.Sprintf("line %s: unknown key %q", line, key)
	if section := sectionOf(typ); section != "" {
		out += " in " + section
	}
	if s := closest(key, knownKeys()[typ]); s != "" {
		out += fmt.Sprintf(" (did you mean %q?)", s)
	} else if valid := knownKeys()[typ]; len(valid) > 0 {
		out += " (valid keys: " + strings.Join(valid, ", ") + ")"
	}
	return out
}

func sectionOf(typ string) string {
	if typ == "config.Config" {
		return "the top level"
	}
	for name, t := range sectionTypes() {
		if t == typ {
			return name
		}
	}
	return ""
}

// sectionTypes maps the top-level YAML section names to their struct type names.
func sectionTypes() map[string]string {
	out := map[string]string{}
	t := reflect.TypeOf(Config{})
	for i := 0; i < t.NumField(); i++ {
		if name := yamlName(t.Field(i)); name != "" {
			out[name] = elemType(t.Field(i).Type).String()
		}
	}
	return out
}

func yamlName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if name == "-" {
		return ""
	}
	return name
}

func elemType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	return t
}

var knownKeysCache = func() map[string][]string {
	out := map[string][]string{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		t = elemType(t)
		if t.Kind() != reflect.Struct || t.PkgPath() == "time" {
			return
		}
		if _, seen := out[t.String()]; seen {
			return
		}
		keys := []string{}
		out[t.String()] = keys
		for i := 0; i < t.NumField(); i++ {
			if name := yamlName(t.Field(i)); name != "" {
				keys = append(keys, name)
				walk(t.Field(i).Type)
			}
		}
		out[t.String()] = keys
	}
	walk(reflect.TypeOf(Config{}))
	return out
}()

func knownKeys() map[string][]string { return knownKeysCache }

// closest returns the valid key nearest to key, or "" when none is near enough to be a plausible typo.
func closest(key string, valid []string) string {
	best, bestD := "", 1<<30
	for _, v := range valid {
		if d := distance(strings.ToLower(key), v); d < bestD {
			best, bestD = v, d
		}
	}
	limit := 2
	if len(key) >= 9 {
		limit = 3
	}
	if bestD > limit {
		return ""
	}
	return best
}

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
