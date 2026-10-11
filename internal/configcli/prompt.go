// Package configcli implements `securl config`: guided, validated editing of the config file so users never
// have to hand-write YAML.
package configcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrNoInput means a question could not be answered because the input ended.
var ErrNoInput = errors.New("no more input to answer the question")

const maxAttempts = 3

// Prompter asks questions on Out and reads answers from In. Secret answers are read without echo when
// ReadSecret is set (a terminal), otherwise as a plain line (piped input in scripts and tests).
type Prompter struct {
	r          *bufio.Reader
	w          io.Writer
	ReadSecret func() (string, error)
}

func NewPrompter(in io.Reader, out io.Writer, readSecret func() (string, error)) *Prompter {
	return &Prompter{r: bufio.NewReader(in), w: out, ReadSecret: readSecret}
}

func (p *Prompter) line() (string, error) {
	s, err := p.r.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || s == "") {
		if errors.Is(err, io.EOF) {
			return "", ErrNoInput
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (p *Prompter) printf(f string, a ...any) { fmt.Fprintf(p.w, f, a...) }

// Say prints an informational line.
func (p *Prompter) Say(f string, a ...any) { p.printf(f+"\n", a...) }

// Ask asks for a text value; Enter accepts def. Validation errors are shown and the question repeated.
func (p *Prompter) Ask(label, def string, validate func(string) error) (string, error) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if def != "" {
			p.printf("%s [%s]: ", label, def)
		} else {
			p.printf("%s: ", label)
		}
		v, err := p.line()
		if err != nil {
			return "", err
		}
		if v == "" {
			v = def
		}
		if validate != nil && v != "" {
			if verr := validate(v); verr != nil {
				p.Say("  ! %v", verr)
				continue
			}
		}
		return v, nil
	}
	return "", fmt.Errorf("%s: too many invalid answers", label)
}

// Require is Ask but an empty answer is not accepted.
func (p *Prompter) Require(label, def string, validate func(string) error) (string, error) {
	check := func(v string) error {
		if strings.TrimSpace(v) == "" {
			return errors.New("a value is required")
		}
		if validate != nil {
			return validate(v)
		}
		return nil
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		v, err := p.Ask(label, def, validate)
		if err != nil {
			return "", err
		}
		if err := check(v); err != nil {
			p.Say("  ! %v", err)
			continue
		}
		return v, nil
	}
	return "", fmt.Errorf("%s: too many invalid answers", label)
}

// Secret asks for a value that must not be echoed. Empty input returns "" (callers treat it as "keep").
func (p *Prompter) Secret(label string, haveCurrent bool) (string, error) {
	hint := ""
	if haveCurrent {
		hint = " (Enter keeps the current value)"
	}
	p.printf("%s%s: ", label, hint)
	if p.ReadSecret != nil {
		v, err := p.ReadSecret()
		p.printf("\n")
		return strings.TrimSpace(v), err
	}
	return p.line()
}

// Confirm asks a yes/no question.
func (p *Prompter) Confirm(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		p.printf("%s [%s]: ", label, hint)
		v, err := p.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(v) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		p.Say("  ! please answer y or n")
	}
	return false, fmt.Errorf("%s: too many invalid answers", label)
}

// Choose offers numbered choices; the answer may be the number or the text. Enter accepts def.
func (p *Prompter) Choose(label string, choices []string, def string) (string, error) {
	p.Say("%s", label)
	for i, c := range choices {
		mark := " "
		if c == def {
			mark = "*"
		}
		p.Say("  %s %d) %s", mark, i+1, c)
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if def != "" {
			p.printf("choice [%s]: ", def)
		} else {
			p.printf("choice: ")
		}
		v, err := p.line()
		if err != nil {
			return "", err
		}
		if v == "" && def != "" {
			return def, nil
		}
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(choices) {
			return choices[n-1], nil
		}
		for _, c := range choices {
			if strings.EqualFold(c, v) {
				return c, nil
			}
		}
		p.Say("  ! pick a number between 1 and %d or type one of the names", len(choices))
	}
	return "", fmt.Errorf("%s: too many invalid answers", label)
}
