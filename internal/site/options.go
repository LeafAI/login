package site

import (
	"fmt"
	"strings"
)

// Option describes one driver-specific setting (the `site_options:` section) so that tooling, such as
// `login config`, can ask the user for it without them having to know the YAML layout.
type Option struct {
	Key     string   // key under site_options.<driver>
	Label   string   // one-line question shown to the user
	Help    string   // longer explanation, may be empty
	Choices []string // when non-empty the value must be one of these
	Default string   // value used when the option is unset ("" = no default)
	// FreeText allows values outside Choices (Choices are then only suggestions).
	FreeText bool
}

// Optioned drivers describe the options they accept.
type Optioned interface {
	Options() []Option
}

// Validate checks value against the option's constraints. An empty value is always valid (it means "unset").
func (o Option) Validate(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(o.Choices) == 0 || o.FreeText {
		return nil
	}
	for _, c := range o.Choices {
		if c == value {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of: %s", o.Key, strings.Join(o.Choices, ", "))
}

// OptionsOf returns the options accepted by the named driver (nil when it has none or is unknown).
func OptionsOf(name string) []Option {
	mu.RLock()
	d, ok := registry[name]
	mu.RUnlock()
	if !ok {
		return nil
	}
	if o, ok := d.(Optioned); ok {
		return o.Options()
	}
	return nil
}

// OptionOf returns one option of the named driver.
func OptionOf(driver, key string) (Option, bool) {
	for _, o := range OptionsOf(driver) {
		if o.Key == key {
			return o, true
		}
	}
	return Option{}, false
}
