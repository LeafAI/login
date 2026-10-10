package archery

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Workflow phases reported to callers.
const (
	PhaseAwaitingApproval = "awaiting_approval"
	PhaseApproved         = "approved"
	PhaseExecuting        = "executing"
	PhaseDone             = "done"
	PhaseFailed           = "failed"
	PhaseAborted          = "aborted"
	PhaseCheckFailed      = "check_failed"
)

// PhaseOf maps Archery's workflow status code (SqlWorkflow.status) to a phase.
func PhaseOf(status string) string {
	switch status {
	case "workflow_manreviewing":
		return PhaseAwaitingApproval
	case "workflow_review_pass", "workflow_timingtask":
		return PhaseApproved
	case "workflow_queuing", "workflow_executing":
		return PhaseExecuting
	case "workflow_finish":
		return PhaseDone
	case "workflow_exception":
		return PhaseFailed
	case "workflow_abort":
		return PhaseAborted
	case "workflow_autoreviewwrong":
		return PhaseCheckFailed
	}
	return PhaseAwaitingApproval
}

type CheckRow struct {
	Sequence int    `json:"sequence"`
	Level    string `json:"level"` // ok | warning | error
	Message  string `json:"message,omitempty"`
	SQL      string `json:"sql,omitempty"`
}

type reviewRow struct {
	ID       int    `json:"id"`
	ErrLevel int    `json:"errlevel"`
	Message  string `json:"errormessage"`
	SQL      string `json:"sql"`
	Affected int    `json:"affected_rows"`
	ExecTime string `json:"execute_time"`
	Backup   string `json:"backup_dbname"`
}

// Check runs Archery's pre-submit review (POST /api/v1/workflow/sqlcheck/).
func (c *Client) Check(ctx context.Context, instanceID int, db, sql string) ([]CheckRow, error) {
	var res struct {
		Rows []reviewRow `json:"rows"`
	}
	if err := c.call(ctx, "POST", "/api/v1/workflow/sqlcheck/", map[string]any{
		"instance_id": instanceID, "db_name": db, "full_sql": sql}, &res); err != nil {
		return nil, err
	}
	out := make([]CheckRow, len(res.Rows))
	for i, r := range res.Rows {
		lv := map[int]string{0: "ok", 1: "warning", 2: "error"}[r.ErrLevel]
		if lv == "" {
			lv = "error"
		}
		out[i] = CheckRow{Sequence: r.ID, Level: lv, Message: r.Message, SQL: r.SQL}
	}
	return out, nil
}

type SubmitRequest struct {
	Instance, Database, SQL, Title, Remark, Group string
	Backup                                        bool
}

// Submitted identifies the new workflow. WorkflowID is the handle used everywhere; AuditID is known
// for the REST generation only.
type Submitted struct {
	WorkflowID int
	AuditID    int
}

// Submit creates the workflow. groupID and instanceID are Archery ids.
func (c *Client) Submit(ctx context.Context, r SubmitRequest, groupID, instanceID int) (*Submitted, error) {
	return c.be().submit(ctx, r, groupID, instanceID)
}

// Status returns Archery's workflow status code (SqlWorkflow.status).
func (c *Client) Status(ctx context.Context, id int) (string, error) { return c.be().status(ctx, id) }

// Execute queues an approved workflow for automatic execution.
func (c *Client) Execute(ctx context.Context, id int) error { return c.be().execute(ctx, id) }

// Cancel aborts a workflow that has not started executing (a reason is mandatory in Archery).
func (c *Client) Cancel(ctx context.Context, id int, reason string) error {
	if strings.TrimSpace(reason) == "" {
		reason = "cancelled by the AI agent"
	}
	return c.be().cancel(ctx, id, reason)
}

// ResultRow is one executed statement.
type ResultRow struct {
	Sequence     int    `json:"sequence"`
	SQL          string `json:"sql"`
	State        string `json:"state"` // success | warning | error
	AffectedRows int    `json:"affected_rows"`
	Error        string `json:"error,omitempty"`
	ExecuteMS    int64  `json:"execute_ms,omitempty"`
	BackupID     string `json:"backup_id,omitempty"`
}

// Results fetches the per-statement execution result.
func (c *Client) Results(ctx context.Context, id int) ([]ResultRow, error) {
	return c.be().results(ctx, id)
}

type LogEntry struct {
	Operation string `json:"operation_type_desc"`
	Info      string `json:"operation_info"`
	Operator  string `json:"operator_display"`
	Time      string `json:"operation_time"`
}

// Logs returns the workflow's audit log, newest first.
func (c *Client) Logs(ctx context.Context, id int) ([]LogEntry, error) { return c.be().logs(ctx, id) }

func toResultRows(rows []reviewRow) []ResultRow {
	out := make([]ResultRow, len(rows))
	for i, r := range rows {
		st := "success"
		switch {
		case r.ErrLevel >= 2:
			st = "error"
		case r.ErrLevel == 1:
			st = "warning"
		}
		secs, _ := strconv.ParseFloat(r.ExecTime, 64)
		out[i] = ResultRow{Sequence: r.ID, SQL: r.SQL, State: st, AffectedRows: r.Affected, Error: r.Message, ExecuteMS: int64(secs * 1000), BackupID: r.Backup}
	}
	return out
}

var ddl = regexp.MustCompile(`(?im)^\s*(create|alter|drop|truncate|rename)\b`)

// HasDDL reports whether any statement looks like DDL.
func HasDDL(sql string) bool { return ddl.MatchString(sql) }

// workflowURL is the page of a workflow in the Archery web UI (the same in both generations).
func workflowURL(base *url.URL, workflowID int) string {
	return strings.TrimRight(base.String(), "/") + "/detail/" + strconv.Itoa(workflowID) + "/"
}
