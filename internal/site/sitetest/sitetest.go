// Package sitetest has helpers for testing drivers.
package sitetest

import (
	"context"
	"fmt"

	"github.com/LeafAI/login/internal/site"
)

// Asker answers rounds from a script and records which modes were requested.
type Asker struct {
	Answers map[string]site.Credentials // by mode; a missing mode fails the test
	Asked   []string
	Reject  string // when non-empty, rejects with this reason on the first Ask
}

type Rejected struct{ Reason string }

func (r *Rejected) Error() string { return "rejected: " + r.Reason }

func (a *Asker) Ask(_ context.Context, mode string, _ []site.Field) (site.Credentials, error) {
	a.Asked = append(a.Asked, mode)
	if a.Reject != "" {
		return nil, &Rejected{a.Reject}
	}
	c, ok := a.Answers[mode]
	if !ok {
		return nil, fmt.Errorf("unexpected round %q", mode)
	}
	return c, nil
}
