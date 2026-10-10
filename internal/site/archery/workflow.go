package archery

import (
	"context"
	"fmt"
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

// Submitted identifies the new workflow. Archery's operations are addressed by AuditID.
type Submitted struct {
	AuditID    int
	WorkflowID int
}

// Submit creates the workflow (POST /api/v1/sql-workflows/). groupID and instanceID are Archery ids.
func (c *Client) Submit(ctx context.Context, r SubmitRequest, groupID, instanceID int) (*Submitted, error) {
	var env envelope
	const path = "/api/v1/sql-workflows/"
	if err := c.call(ctx, "POST", path, map[string]any{
		"workflow": map[string]any{
			"workflow_name": r.Title, "demand_url": r.Remark, "group_id": groupID, "instance": instanceID,
			"db_name": r.Database, "is_backup": r.Backup, "is_offline_export": 0,
		},
		"sql_content": r.SQL,
	}, &env); err != nil {
		return nil, err
	}
	if err := c.legacy(path, &env); err != nil {
		return nil, err
	}
	var d struct {
		AuditID    int `json:"audit_id"`
		WorkflowID int `json:"workflow_id"`
	}
	if err := jsonUnmarshal(env.Data, &d); err != nil || d.AuditID == 0 {
		return nil, &APIError{path, "no audit_id in response"}
	}
	return &Submitted{AuditID: d.AuditID, WorkflowID: d.WorkflowID}, nil
}

func auditPath(id int, op string) string {
	return "/api/v1/sql-workflows/" + strconv.Itoa(id) + "/" + op + "/"
}

// Status returns Archery's workflow status code.
func (c *Client) Status(ctx context.Context, auditID int) (string, error) {
	var res struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, "GET", auditPath(auditID, "status"), nil, &res); err != nil {
		var ae *APIError
		if asAPIError(err, &ae) && strings.Contains(ae.Msg, "HTTP 404") {
			return "", fmt.Errorf("%w: %d (not visible to this user?)", ErrNotFound, auditID)
		}
		return "", err
	}
	return res.Status, nil
}

// Execute queues an approved workflow for automatic execution.
func (c *Client) Execute(ctx context.Context, auditID int) error {
	var env envelope
	if err := c.call(ctx, "POST", auditPath(auditID, "execution"), map[string]string{"mode": "auto"}, &env); err != nil {
		return err
	}
	return c.legacy("execution", &env)
}

// Cancel aborts a workflow that has not started executing (a reason is mandatory in Archery).
func (c *Client) Cancel(ctx context.Context, auditID int, reason string) error {
	if strings.TrimSpace(reason) == "" {
		reason = "cancelled by the AI agent"
	}
	var env envelope
	if err := c.call(ctx, "POST", auditPath(auditID, "cancellation"), map[string]string{"cancel_remark": reason}, &env); err != nil {
		return err
	}
	return c.legacy("cancellation", &env)
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

// Results fetches the per-statement review/execution result (GET .../content/).
func (c *Client) Results(ctx context.Context, auditID int) ([]ResultRow, error) {
	var res struct {
		Rows []reviewRow `json:"rows"`
	}
	if err := c.call(ctx, "GET", auditPath(auditID, "content"), nil, &res); err != nil {
		return nil, err
	}
	out := make([]ResultRow, len(res.Rows))
	for i, r := range res.Rows {
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
	return out, nil
}

type LogEntry struct {
	Operation string `json:"operation_type_desc"`
	Info      string `json:"operation_info"`
	Operator  string `json:"operator_display"`
	Time      string `json:"operation_time"`
}

// Logs returns the workflow's audit log, newest first.
func (c *Client) Logs(ctx context.Context, auditID int) ([]LogEntry, error) {
	var res struct {
		Rows []LogEntry `json:"rows"`
	}
	if err := c.call(ctx, "GET", auditPath(auditID, "logs"), nil, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}

var ddl = regexp.MustCompile(`(?im)^\s*(create|alter|drop|truncate|rename)\b`)

// HasDDL reports whether any statement looks like DDL.
func HasDDL(sql string) bool { return ddl.MatchString(sql) }

func workflowURL(base *url.URL, auditID int) string {
	return strings.TrimRight(base.String(), "/") + "/workflow/" + strconv.Itoa(auditID) + "/"
}
