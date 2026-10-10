package archery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Errors with stable meaning for the MCP layer.
var (
	ErrDDLDisabled = errors.New("DDL statements are disabled by configuration (archery.allow_ddl: false)")
	ErrNotFound    = errors.New("workflow not found")
)

// CheckFailed carries the findings of a failed pre-submit review.
type CheckFailed struct{ Rows []CheckRow }

func (e *CheckFailed) Error() string {
	var msgs []string
	for _, r := range e.Rows {
		if r.Level == "error" {
			msgs = append(msgs, fmt.Sprintf("#%d: %s", r.Sequence, r.Message))
		}
	}
	return "Archery rejected the SQL during review: " + strings.Join(msgs, "; ")
}

type Notifier interface {
	Markdown(ctx context.Context, title, text string) error
}

// Outcome is what run/wait return.
type Outcome struct {
	Status      string      `json:"status"` // done | failed | pending | aborted
	Phase       string      `json:"phase,omitempty"`
	WorkflowID  int         `json:"workflow_id"`
	WorkflowURL string      `json:"workflow_url"`
	Check       []CheckRow  `json:"check,omitempty"`
	Results     []ResultRow `json:"results,omitempty"`
	Reason      string      `json:"reason,omitempty"`
}

type track struct {
	title    string
	deadline time.Time
	mu       sync.Mutex
	executed bool
}

// Tracker remembers submitted workflows so that waiting is idempotent and execution happens once.
type Tracker struct {
	AllowDDL               bool
	Poll                   time.Duration // default 5s
	DefaultApprovalTimeout time.Duration

	mu sync.Mutex
	m  map[string]*track
}

func NewTracker(allowDDL bool, approvalTimeout time.Duration) *Tracker {
	return &Tracker{AllowDDL: allowDDL, Poll: 5 * time.Second, DefaultApprovalTimeout: approvalTimeout, m: map[string]*track{}}
}

func key(base *url.URL, id int) string {
	return base.Scheme + "://" + base.Host + "#" + strconv.Itoa(id)
}

func (t *Tracker) get(base *url.URL, id int, title string) *track {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := key(base, id)
	if tr := t.m[k]; tr != nil {
		return tr
	}
	tr := &track{title: title, deadline: time.Now().Add(t.DefaultApprovalTimeout)}
	t.m[k] = tr
	return tr
}

func workflowURL(base *url.URL, id int) string {
	return strings.TrimRight(base.String(), "/") + "/detail/" + strconv.Itoa(id) + "/"
}

// Submit validates, checks and submits the SQL, then tells the approvers. It does not wait.
func (t *Tracker) Submit(ctx context.Context, c *Client, n Notifier, r SubmitRequest, approvalTimeout time.Duration) (*Outcome, error) {
	if !t.AllowDDL && HasDDL(r.SQL) {
		return nil, ErrDDLDisabled
	}
	rows, err := c.Check(ctx, r.Instance, r.Database, r.SQL)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Level == "error" {
			return nil, &CheckFailed{Rows: rows}
		}
	}
	id, err := c.Submit(ctx, r)
	if err != nil {
		return nil, err
	}
	tr := t.get(c.Base, id, r.Title)
	if approvalTimeout > 0 {
		tr.deadline = time.Now().Add(approvalTimeout)
	}
	out := &Outcome{Status: "pending", Phase: PhaseAwaitingApproval, WorkflowID: id, WorkflowURL: workflowURL(c.Base, id), Check: rows}
	if n != nil {
		preview := r.SQL
		if len(preview) > 500 {
			preview = preview[:500] + "..."
		}
		text := fmt.Sprintf("### SQL approval needed: %s\n\n- **Instance / DB**: %s / %s\n- **Requested by AI agent**: %s\n\n```sql\n%s\n```\n\n[Open workflow #%d in Archery](%s)\n\nAfter approval the SQL is executed automatically.",
			r.Title, r.Instance, r.Database, orNone(r.Remark), preview, id, out.WorkflowURL)
		if err := n.Markdown(ctx, "SQL approval: "+r.Title, text); err != nil {
			out.Reason = "workflow submitted but the DingTalk notification failed: " + err.Error()
		}
	}
	return out, nil
}

func orNone(s string) string {
	if s == "" {
		return "(no remark)"
	}
	return s
}

// Wait advances the workflow (executing it once when approved) until it ends or maxBlock elapses.
func (t *Tracker) Wait(ctx context.Context, c *Client, id int, maxBlock time.Duration, progress func(phase string)) (*Outcome, error) {
	tr := t.get(c.Base, id, "")
	deadline := time.Now().Add(maxBlock)
	out := &Outcome{WorkflowID: id, WorkflowURL: workflowURL(c.Base, id)}
	last := ""
	for {
		w, err := c.Status(ctx, id, tr.title)
		if err != nil {
			return nil, err
		}
		if w.Phase != last {
			last = w.Phase
			if progress != nil {
				progress(w.Phase)
			}
		}
		out.Phase = w.Phase
		switch w.Phase {
		case PhaseApproved:
			tr.mu.Lock()
			if !tr.executed {
				if err := c.Execute(ctx, id); err != nil {
					tr.mu.Unlock()
					return nil, err
				}
				tr.executed = true
			}
			tr.mu.Unlock()
		case PhaseDone, PhaseFailed:
			res, err := c.Results(ctx, id)
			if err != nil {
				return nil, err
			}
			out.Results = res
			out.Status = "done"
			if w.Phase == PhaseFailed {
				out.Status = "failed"
			}
			for _, r := range res {
				if r.State == "error" {
					out.Status = "failed"
				}
			}
			return out, nil
		case PhaseAborted:
			out.Status = "aborted"
			out.Reason = "the workflow was rejected or aborted in Archery"
			return out, nil
		case PhaseCheckFailed:
			out.Status = "failed"
			out.Reason = "Archery's automatic review failed"
			return out, nil
		case PhaseAwaitingApproval:
			if time.Now().After(tr.deadline) {
				_ = c.Cancel(ctx, id, "approval timed out (requested by AI agent)")
				out.Status, out.Phase = "aborted", PhaseAborted
				out.Reason = "nobody approved in time; the workflow was cancelled"
				return out, nil
			}
		}
		if time.Now().After(deadline) {
			out.Status = "pending"
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(t.Poll):
		}
	}
}
