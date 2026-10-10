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

// legacyBackend speaks the Archery 1.x ajax endpoints (verified against v1.12.0): form-encoded POSTs
// to /query/, /execute/, /cancel/, /getWorkflowStatus/, /workflow/log/, a GET to
// /sqlworkflow/detail_content/ and JSON POST /api/v1/workflow/ to submit. Workflows are addressed
// by workflow id.
type legacyBackend struct{ c *Client }

func (b *legacyBackend) instances(ctx context.Context) ([]Instance, error) {
	const path = "/group/user_all_instances/"
	var env envelope
	if err := b.c.call(ctx, "GET", path, nil, &env); err != nil {
		return nil, err
	}
	if err := b.c.legacy(path, &env); err != nil {
		return nil, err
	}
	return toInstances(env.Data)
}

func (b *legacyBackend) databases(ctx context.Context, instance string) ([]string, error) {
	path := "/instance/instance_resource/?resource_type=database&instance_name=" + url.QueryEscape(instance)
	var env envelope
	if err := b.c.call(ctx, "GET", path, nil, &env); err != nil {
		return nil, err
	}
	if err := b.c.legacy(path, &env); err != nil {
		return nil, err
	}
	var dbs []string
	json.Unmarshal(env.Data, &dbs)
	return dbs, nil
}

func (b *legacyBackend) query(ctx context.Context, q QueryRequest) (*QueryResult, error) {
	var env envelope
	if err := b.c.form(ctx, "/query/", url.Values{
		"instance_name": {q.Instance}, "db_name": {q.Database}, "schema_name": {q.Schema}, "tb_name": {""},
		"sql_content": {q.SQL}, "limit_num": {strconv.Itoa(q.Limit)}}, &env); err != nil {
		return nil, err
	}
	return queryResult("/query/", &env, q.Limit, b.c)
}

func (b *legacyBackend) submit(ctx context.Context, r SubmitRequest, groupID, instanceID int) (*Submitted, error) {
	const path = "/api/v1/workflow/"
	// 1.x answers the serialized SqlWorkflowContent (201): {"id", "workflow_id", "workflow": {...}, ...}.
	var res struct {
		WorkflowID int `json:"workflow_id"`
		Workflow   struct {
			ID int `json:"id"`
		} `json:"workflow"`
	}
	if err := b.c.call(ctx, "POST", path, map[string]any{
		"workflow": map[string]any{
			"workflow_name": r.Title, "demand_url": r.Remark, "group_id": groupID, "instance": instanceID,
			"db_name": r.Database, "is_backup": r.Backup,
		},
		"sql_content": r.SQL,
	}, &res); err != nil {
		return nil, err
	}
	id := res.WorkflowID
	if id == 0 {
		id = res.Workflow.ID
	}
	if id == 0 {
		return nil, &APIError{path, "no workflow_id in response"}
	}
	return &Submitted{WorkflowID: id}, nil
}

func (b *legacyBackend) status(ctx context.Context, id int) (string, error) {
	var res struct {
		Status json.RawMessage `json:"status"`
		Msg    string          `json:"msg"`
	}
	code, raw, err := b.c.do(ctx, "POST", "/getWorkflowStatus/", []byte(url.Values{"workflow_id": {strconv.Itoa(id)}}.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return "", err
	}
	if code == 404 {
		return "", fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	if err := b.c.finish(code, raw, nil)("/getWorkflowStatus/", &res); err != nil {
		return "", err
	}
	var s string
	if json.Unmarshal(res.Status, &s) != nil || s == "" {
		return "", &APIError{"/getWorkflowStatus/", "unexpected status: " + res.Msg + string(res.Status)}
	}
	return s, nil
}

var htmlTag = regexp.MustCompile(`<[^>]*>`)

// action posts a form to an endpoint that answers with a redirect to the detail page on success and
// with a rendered HTML error page otherwise.
func (b *legacyBackend) action(ctx context.Context, path string, form url.Values) error {
	code, raw, err := b.c.do(ctx, "POST", path, []byte(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return err
	}
	if code == 302 || code == 301 {
		return nil
	}
	if code == 401 || code == 403 && strings.Contains(raw, "credentials") {
		return ErrSessionInvalid
	}
	msg := strings.Join(strings.Fields(htmlTag.ReplaceAllString(raw, " ")), " ")
	return &APIError{path, fmt.Sprintf("HTTP %d: %s", code, truncate(msg, 300))}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func (b *legacyBackend) execute(ctx context.Context, id int) error {
	return b.action(ctx, "/execute/", url.Values{"workflow_id": {strconv.Itoa(id)}, "mode": {"auto"}})
}

func (b *legacyBackend) cancel(ctx context.Context, id int, reason string) error {
	return b.action(ctx, "/cancel/", url.Values{"workflow_id": {strconv.Itoa(id)}, "cancel_remark": {reason}})
}

func (b *legacyBackend) results(ctx context.Context, id int) ([]ResultRow, error) {
	var res struct {
		Rows []reviewRow `json:"rows"`
	}
	if err := b.c.call(ctx, "GET", "/sqlworkflow/detail_content/?workflow_id="+strconv.Itoa(id), nil, &res); err != nil {
		return nil, err
	}
	return toResultRows(res.Rows), nil
}

func (b *legacyBackend) logs(ctx context.Context, id int) ([]LogEntry, error) {
	var res struct {
		Rows []LogEntry `json:"rows"`
	}
	// workflow_type 2 = SQL_REVIEW (common/utils/const.py)
	if err := b.c.form(ctx, "/workflow/log/", url.Values{"workflow_id": {strconv.Itoa(id)}, "workflow_type": {"2"}}, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}
