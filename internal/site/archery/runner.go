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

	"github.com/LeafAI/securl/internal/notify"
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

// Outcome is what run/wait return. WorkflowID is Archery's handle for every workflow operation.
type Outcome struct {
	Status      string      `json:"status"` // done | failed | pending | aborted | rejected
	Phase       string      `json:"phase,omitempty"`
	WorkflowID  int         `json:"workflow_id"`
	AuditID     int         `json:"audit_id,omitempty"` // newer Archery only
	WorkflowURL string      `json:"workflow_url"`
	Check       []CheckRow  `json:"check,omitempty"`
	Results     []ResultRow `json:"results,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	By          string      `json:"by,omitempty"`
}

type track struct {
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

func (t *Tracker) get(base *url.URL, id int) *track {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := key(base, id)
	if tr := t.m[k]; tr != nil {
		return tr
	}
	tr := &track{deadline: time.Now().Add(t.DefaultApprovalTimeout)}
	t.m[k] = tr
	return tr
}

// FindGroup picks a resource group by name (case-insensitive); the error lists the available names.
func FindGroup(gs []Group, name string) (Group, error) { return findGroup(gs, name) }

func findGroup(gs []Group, name string) (Group, error) {
	var names []string
	for _, g := range gs {
		if strings.EqualFold(g.Name, name) {
			return g, nil
		}
		names = append(names, g.Name)
	}
	return Group{}, &APIError{"/submitsql/", fmt.Sprintf("resource group %q not found; available: %s", name, strings.Join(names, ", "))}
}

func findInstance(is []Instance, name string) (Instance, error) {
	var names []string
	for _, i := range is {
		if i.Name == name {
			return i, nil
		}
		names = append(names, i.Name)
	}
	return Instance{}, &APIError{"/group/instances/", fmt.Sprintf("instance %q is not writable in this resource group; available: %s", name, strings.Join(names, ", "))}
}

// Submit validates, checks and submits the SQL, then tells the approvers. It does not wait.
func (t *Tracker) Submit(ctx context.Context, c *Client, n Notifier, r SubmitRequest, approvalTimeout time.Duration) (*Outcome, error) {
	if !t.AllowDDL && HasDDL(r.SQL) {
		return nil, ErrDDLDisabled
	}
	groups, err := c.Groups(ctx)
	if err != nil {
		return nil, err
	}
	g, err := findGroup(groups, r.Group)
	if err != nil {
		return nil, err
	}
	instances, err := c.GroupInstances(ctx, g.Name)
	if err != nil {
		return nil, err
	}
	inst, err := findInstance(instances, r.Instance)
	if err != nil {
		return nil, err
	}
	rows, err := c.Check(ctx, inst.ID, r.Database, r.SQL)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Level == "error" {
			return nil, &CheckFailed{Rows: rows}
		}
	}
	sub, err := c.Submit(ctx, r, g.ID, inst.ID)
	if err != nil {
		return nil, err
	}
	tr := t.get(c.Base, sub.WorkflowID)
	if approvalTimeout > 0 {
		tr.deadline = time.Now().Add(approvalTimeout)
	}
	out := &Outcome{Status: "pending", Phase: PhaseAwaitingApproval, WorkflowID: sub.WorkflowID, AuditID: sub.AuditID,
		WorkflowURL: workflowURL(c.Base, sub.WorkflowID), Check: rows}
	if n != nil {
		text := fmt.Sprintf("### SQL approval needed: %s\n\n- **Instance / DB**: %s / %s\n- **Requested by AI agent**: %s\n\n```sql\n%s\n```\n\n[Open workflow #%d in Archery](%s)\n\nAfter approval the SQL is executed automatically.",
			notify.Escape(r.Title, 50), notify.Escape(r.Instance, 80), notify.Escape(r.Database, 80), orNone(notify.Escape(r.Remark, 200)),
			notify.CodeBlock(r.SQL, 500), sub.WorkflowID, out.WorkflowURL)
		if err := n.Markdown(ctx, "SQL approval: "+notify.Escape(r.Title, 50), text); err != nil {
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
	tr := t.get(c.Base, id)
	deadline := time.Now().Add(maxBlock)
	out := &Outcome{WorkflowID: id, WorkflowURL: workflowURL(c.Base, id)}
	last := ""
	for {
		code, err := c.Status(ctx, id)
		if err != nil {
			return nil, err
		}
		phase := PhaseOf(code)
		if phase != last {
			last = phase
			if progress != nil {
				progress(phase)
			}
		}
		out.Phase = phase
		switch phase {
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
			if phase == PhaseFailed {
				out.Status = "failed"
			}
			for _, r := range res {
				if r.State == "error" {
					out.Status = "failed"
				}
			}
			return out, nil
		case PhaseAborted:
			t.describeAbort(ctx, c, id, out)
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

// describeAbort distinguishes a rejection from a cancellation using the workflow log
// (Archery sets the same status for both) and extracts who did it and why.
func (t *Tracker) describeAbort(ctx context.Context, c *Client, id int, out *Outcome) {
	out.Status = "aborted"
	out.Reason = "the workflow was cancelled in Archery"
	logs, err := c.Logs(ctx, id)
	if err != nil || len(logs) == 0 {
		return
	}
	last := logs[0] // newest first
	out.By = last.Operator
	if last.Info != "" {
		out.Reason = last.Info
	}
	if strings.Contains(last.Operation, "不通过") || strings.Contains(strings.ToLower(last.Operation), "reject") {
		out.Status = "rejected"
		if last.Info == "" {
			out.Reason = "the approver rejected the workflow"
		}
	}
}
