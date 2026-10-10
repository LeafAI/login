package archery

import (
	"context"
	"encoding/json"
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

// PhaseOf maps Archery's workflow status code to a phase.
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

// Check runs Archery's pre-submit review.
func (c *Client) Check(ctx context.Context, instance, db, sql string) ([]CheckRow, error) {
	env, err := c.must(ctx, "POST", "/simplecheck/", url.Values{"sql_content": {sql}, "instance_name": {instance}, "db_name": {db}})
	if err != nil {
		return nil, err
	}
	var d struct {
		Rows []struct {
			ID       int    `json:"id"`
			ErrLevel int    `json:"errlevel"`
			Message  string `json:"errormessage"`
			SQL      string `json:"sql"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return nil, fmt.Errorf("archery check: %w", err)
	}
	out := make([]CheckRow, len(d.Rows))
	for i, r := range d.Rows {
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

var detailRe = regexp.MustCompile(`/detail/(\d+)`)

// Submit creates the workflow and returns its id.
func (c *Client) Submit(ctx context.Context, r SubmitRequest) (int, error) {
	form := url.Values{
		"sql_content": {r.SQL}, "workflow_name": {r.Title}, "group_name": {r.Group}, "instance_name": {r.Instance},
		"db_name": {r.Database}, "is_backup": {map[bool]string{true: "True", false: "False"}[r.Backup]},
		"demand_url": {r.Remark}, "run_date_start": {""}, "run_date_end": {""}}
	resp, raw, err := c.do(ctx, "POST", "/autoreview/", form, false)
	if err != nil {
		return 0, err
	}
	// Newer Archery answers JSON {status,msg,data:{workflow_id}}; older ones redirect to /detail/<id>/.
	if loc := resp.Header.Get("Location"); loc != "" {
		if m := detailRe.FindStringSubmatch(loc); m != nil {
			return strconv.Atoi(m[1])
		}
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return 0, fmt.Errorf("archery autoreview: unexpected response (%d): %s", resp.StatusCode, truncate(raw, 160))
	}
	if env.Status != 0 {
		return 0, &APIError{"/autoreview/", truncate(env.Msg, 300)}
	}
	var d struct {
		ID int `json:"workflow_id"`
	}
	if err := json.Unmarshal(env.Data, &d); err == nil && d.ID > 0 {
		return d.ID, nil
	}
	if m := detailRe.FindStringSubmatch(string(env.Data)); m != nil {
		return strconv.Atoi(m[1])
	}
	return 0, fmt.Errorf("archery autoreview: no workflow id in response: %s", truncate(raw, 160))
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Workflow is a workflow summary.
type Workflow struct {
	ID        int    `json:"workflow_id"`
	Title     string `json:"title"`
	Status    string `json:"-"`
	StatusTxt string `json:"status_text"`
	Phase     string `json:"status"`
	Submitter string `json:"submitter"`
	Instance  string `json:"instance"`
	Database  string `json:"database"`
	CreatedAt string `json:"created_at"`
}

// Status looks a workflow up in Archery's workflow list, paging through at most 200 recent workflows
// (titleHint narrows the server-side search when known).
func (c *Client) Status(ctx context.Context, id int, titleHint string) (*Workflow, error) {
	const page = 50
	for offset := 0; offset < 4*page; offset += page {
		resp, raw, err := c.do(ctx, "POST", "/sqlworkflow_list/", url.Values{
			"limit": {strconv.Itoa(page)}, "offset": {strconv.Itoa(offset)}, "navStatus": {""}, "search": {titleHint}}, false)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("archery session is no longer valid (sqlworkflow_list -> %d)", resp.StatusCode)
		}
		// The list endpoint answers {"total":N,"rows":[...]}; tolerate the {status,data:{rows}} envelope too.
		var body struct {
			Rows []map[string]any `json:"rows"`
			Data struct {
				Rows []map[string]any `json:"rows"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			return nil, fmt.Errorf("archery sqlworkflow_list: unexpected response: %s", truncate(raw, 160))
		}
		rows := body.Rows
		if len(rows) == 0 {
			rows = body.Data.Rows
		}
		if w, err := pick(rows, id); err == nil {
			return w, nil
		}
		if len(rows) < page {
			break
		}
	}
	return nil, fmt.Errorf("%w: %d (not visible to this user?)", ErrNotFound, id)
}

func pick(rows []map[string]any, id int) (*Workflow, error) {
	for _, r := range rows {
		if num(r["id"]) != id {
			continue
		}
		w := &Workflow{ID: id, Title: str(r["workflow_name"]), Status: str(r["status"]), StatusTxt: str(r["status_desc"]),
			Submitter: str(r["engineer_display"]), Instance: str(r["instance__instance_name"]),
			Database: str(r["db_name"]), CreatedAt: str(r["create_time"])}
		w.Phase = PhaseOf(w.Status)
		return w, nil
	}
	return nil, fmt.Errorf("workflow %d not found (not visible to this user?)", id)
}

func num(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Execute starts execution of an approved workflow.
func (c *Client) Execute(ctx context.Context, id int) error {
	resp, raw, err := c.do(ctx, "POST", "/execute/", url.Values{"workflow_id": {strconv.Itoa(id)}, "mode": {"auto"}}, false)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil // legacy redirect to the detail page
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err == nil && env.Status != 0 {
		return &APIError{"/execute/", truncate(env.Msg, 300)}
	}
	return nil
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
	resp, raw, err := c.do(ctx, "GET", "/workflow/detail_content/?workflow_id="+strconv.Itoa(id), nil, false)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("archery detail_content: %s", resp.Status)
	}
	var d struct {
		Rows []struct {
			ID      int    `json:"id"`
			Level   int    `json:"errlevel"`
			Message string `json:"errormessage"`
			SQL     string `json:"sql"`
			Rows    int    `json:"affected_rows"`
			Secs    string `json:"execute_time"`
			Backup  string `json:"backup_dbname"`
			Stage   string `json:"stagestatus"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return nil, fmt.Errorf("archery detail_content: %w", err)
	}
	out := make([]ResultRow, len(d.Rows))
	for i, r := range d.Rows {
		st := "success"
		switch {
		case r.Level >= 2:
			st = "error"
		case r.Level == 1:
			st = "warning"
		}
		secs, _ := strconv.ParseFloat(r.Secs, 64)
		out[i] = ResultRow{Sequence: r.ID, SQL: r.SQL, State: st, AffectedRows: r.Rows, Error: r.Message, ExecuteMS: int64(secs * 1000), BackupID: r.Backup}
	}
	return out, nil
}

// Cancel aborts a workflow that has not started executing.
func (c *Client) Cancel(ctx context.Context, id int, reason string) error {
	_, err := c.must(ctx, "POST", "/cancel/", url.Values{"workflow_id": {strconv.Itoa(id)}, "cancel_remark": {reason}})
	return err
}

var ddl = regexp.MustCompile(`(?im)^\s*(create|alter|drop|truncate|rename)\b`)

// HasDDL reports whether any statement looks like DDL.
func HasDDL(sql string) bool { return ddl.MatchString(sql) }
