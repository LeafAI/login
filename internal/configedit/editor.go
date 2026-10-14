package configedit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/filelock"
	"github.com/LeafAI/securl/internal/site/generic"
)

// Editor holds a config file as a YAML node tree. Methods mutate the tree; Save validates and writes it.
type Editor struct {
	path string
	root *yaml.Node // a MappingNode
}

// Open loads path; a missing or empty file yields an empty document.
func Open(path string) (*Editor, error) {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	e := &Editor{path: path}
	var doc yaml.Node
	if len(bytes.TrimSpace(b)) > 0 {
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("%s is not valid YAML: %w", path, err)
		}
	}
	switch {
	case doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode:
		e.root = doc.Content[0]
	case doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0):
		e.root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	default:
		return nil, fmt.Errorf("%s: the top level must be a mapping of sections", path)
	}
	return e, nil
}

// Path is the file this editor saves to.
func (e *Editor) Path() string { return e.path }

// Exists reports whether the file is already on disk.
func (e *Editor) Exists() bool { _, err := os.Stat(e.path); return err == nil }

func mapGet(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v.HeadComment, v.LineComment, v.FootComment = m.Content[i+1].HeadComment, m.Content[i+1].LineComment, m.Content[i+1].FootComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

func mapDelete(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// parent walks (and with create, builds) the mapping that holds the last key.
func (e *Editor) parent(keys []string, create bool) *yaml.Node {
	m := e.root
	for _, k := range keys[:len(keys)-1] {
		next := mapGet(m, k)
		if next == nil || next.Kind != yaml.MappingNode {
			if !create {
				return nil
			}
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			mapSet(m, k, next)
		}
		m = next
	}
	return m
}

// Set stores value at the dotted setting path after checking that it fits the setting's type.
func (e *Editor) Set(path, value string) error {
	keys, t, err := resolve(path)
	if err != nil {
		return err
	}
	n, err := valueNode(t, value)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	mapSet(e.parent(keys, true), keys[len(keys)-1], n)
	return nil
}

// Unset removes a setting (and empty parent sections) and reports whether it was present.
func (e *Editor) Unset(path string) (bool, error) {
	keys, _, err := resolve(path)
	if err != nil {
		return false, err
	}
	p := e.parent(keys, false)
	if p == nil || !mapDelete(p, keys[len(keys)-1]) {
		return false, nil
	}
	for i := len(keys) - 1; i > 0; i-- { // drop sections left empty
		pp := e.parent(keys[:i], false)
		if pp == nil {
			break
		}
		child := mapGet(pp, keys[i-1])
		if child == nil || len(child.Content) > 0 {
			break
		}
		mapDelete(pp, keys[i-1])
	}
	return true, nil
}

// Get returns the stored value of a setting as text ("" and false when unset).
func (e *Editor) Get(path string) (string, bool, error) {
	keys, _, err := resolve(path)
	if err != nil {
		return "", false, err
	}
	p := e.parent(keys, false)
	if p == nil {
		return "", false, nil
	}
	n := mapGet(p, keys[len(keys)-1])
	if n == nil {
		return "", false, nil
	}
	if n.Kind == yaml.SequenceNode {
		var parts []string
		for _, c := range n.Content {
			parts = append(parts, c.Value)
		}
		return strings.Join(parts, ","), true, nil
	}
	return n.Value, true, nil
}

// Sites returns the custom (generic driver) sites defined in the file.
func (e *Editor) Sites() ([]generic.Spec, error) {
	n := mapGet(e.root, "sites")
	if n == nil {
		return nil, nil
	}
	var out []generic.Spec
	if err := n.Decode(&out); err != nil {
		return nil, fmt.Errorf("sites: %w", err)
	}
	return out, nil
}

// SetSite adds or replaces (by name) a custom site.
func (e *Editor) SetSite(spec generic.Spec) error {
	var node yaml.Node
	if err := node.Encode(spec); err != nil {
		return fmt.Errorf("encode site %s: %w", spec.Name, err)
	}
	seq := mapGet(e.root, "sites")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(e.root, "sites", seq)
	}
	for i, c := range seq.Content {
		if m := mapGet(c, "name"); m != nil && m.Value == spec.Name {
			node.HeadComment = c.HeadComment
			seq.Content[i] = &node
			return nil
		}
	}
	seq.Content = append(seq.Content, &node)
	return nil
}

// RemoveSite deletes a custom site by name.
func (e *Editor) RemoveSite(name string) bool {
	seq := mapGet(e.root, "sites")
	if seq == nil {
		return false
	}
	for i, c := range seq.Content {
		if m := mapGet(c, "name"); m != nil && m.Value == name {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			if len(seq.Content) == 0 {
				mapDelete(e.root, "sites")
			}
			return true
		}
	}
	return false
}

// databaseEntry is how a database target is written to the file: only what the owner chose, so that the defaults stay
// the program's to change, and in an order a person reads top to bottom.
type databaseEntry struct {
	Name             string   `yaml:"name"`
	Driver           string   `yaml:"driver"`
	Host             string   `yaml:"host"`
	Port             int      `yaml:"port,omitempty"`
	Environment      string   `yaml:"environment"`
	Databases        []string `yaml:"databases,omitempty,flow"`
	Mode             string   `yaml:"mode,omitempty"`
	AllowDDL         bool     `yaml:"allow_ddl,omitempty"`
	TLS              string   `yaml:"tls,omitempty"`
	MaxRows          int      `yaml:"max_rows,omitempty"`
	MaxChangedRows   int      `yaml:"max_changed_rows,omitempty"`
	StatementTimeout string   `yaml:"statement_timeout,omitempty"`
}

func entryOf(d config.Database) databaseEntry {
	e := databaseEntry{Name: d.Name, Driver: d.Driver, Host: d.Host, Port: d.Port, Environment: d.Environment, Databases: d.Databases,
		Mode: d.Mode, AllowDDL: d.AllowDDL, TLS: d.TLS, MaxRows: d.MaxRows, MaxChangedRows: d.MaxChangedRows}
	if e.Mode == config.ModeReadOnly {
		e.Mode = "" // the default, which the program may change: the file keeps what the owner chose beyond it
	}
	if d.StatementTimeout > 0 {
		e.StatementTimeout = d.StatementTimeout.String()
	}
	return e
}

// Databases returns the database targets defined in the file, as written (defaults are not filled in).
func (e *Editor) Databases() ([]config.Database, error) {
	n := mapGet(e.root, "databases")
	if n == nil {
		return nil, nil
	}
	var out []config.Database
	if err := n.Decode(&out); err != nil {
		return nil, fmt.Errorf("databases: %w", err)
	}
	return out, nil
}

// SetDatabase adds or replaces (by name) a database target. It never writes an account: the person types that on the
// login page, and it lives in the vault.
func (e *Editor) SetDatabase(d config.Database) error {
	var node yaml.Node
	if err := node.Encode(entryOf(d)); err != nil {
		return fmt.Errorf("encode database %s: %w", d.Name, err)
	}
	seq := mapGet(e.root, "databases")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(e.root, "databases", seq)
	}
	for i, c := range seq.Content {
		if m := mapGet(c, "name"); m != nil && m.Value == d.Name {
			node.HeadComment = c.HeadComment
			seq.Content[i] = &node
			return nil
		}
	}
	seq.Content = append(seq.Content, &node)
	return nil
}

// RemoveDatabase deletes a database target by name.
func (e *Editor) RemoveDatabase(name string) bool {
	seq := mapGet(e.root, "databases")
	if seq == nil {
		return false
	}
	for i, c := range seq.Content {
		if m := mapGet(c, "name"); m != nil && m.Value == name {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			if len(seq.Content) == 0 {
				mapDelete(e.root, "databases")
			}
			return true
		}
	}
	return false
}

// Bytes renders the document.
func (e *Editor) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(e.root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Validate renders the document and checks it the way the server will read it: unknown keys are errors
// (typos), and every generic site must build.
func (e *Editor) Validate() error {
	b, err := e.Bytes()
	if err != nil {
		return err
	}
	if err := config.ParseStrict(b); err != nil {
		return err
	}
	cfg, err := config.Parse(b, filepath.Dir(e.path))
	if err != nil {
		return err
	}
	for _, s := range cfg.Sites {
		if _, err := generic.New(s); err != nil {
			return err
		}
	}
	return cfg.Validate()
}

// Save validates and writes the file atomically (0600), keeping the previous version as <file>.bak.
func (e *Editor) Save() error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("refusing to save an invalid configuration: %w", err)
	}
	b, err := e.Bytes()
	if err != nil {
		return err
	}
	dir := filepath.Dir(e.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	unlock, err := filelock.Lock(e.path + ".lock")
	if err != nil {
		return fmt.Errorf("lock %s: %w", e.path, err)
	}
	defer unlock()
	if old, err := os.ReadFile(e.path); err == nil {
		if err := os.WriteFile(e.path+".bak", old, 0o600); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), e.path); err != nil {
		return fmt.Errorf("replace %s: %w", e.path, err)
	}
	return nil
}
