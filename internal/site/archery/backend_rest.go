package archery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// restBackend speaks the newer /api/v1 REST API. Its workflow operations are addressed by audit_id,
// which is mapped from the workflow id (remembered at submit time, else looked up in the list API).
type restBackend struct{ c *Client }

var auditIDs sync.Map // "scheme://host#workflowID" -> audit id

func (b *restBackend) key(id int) string {
	return b.c.Base.Scheme + "://" + b.c.Base.Host + "#" + strconv.Itoa(id)
}

func (b *restBackend) audit(ctx context.Context, workflowID int) (int, error) {
	if v, ok := auditIDs.Load(b.key(workflowID)); ok {
		return v.(int), nil
	}
	const page = 50
	for offset := 0; offset < 4*page; offset += page {
		var res struct {
			Rows []struct {
				WorkflowID int `json:"workflow_id"`
				AuditID    int `json:"audit_id"`
			} `json:"rows"`
		}
		if err := b.c.call(ctx, "POST", "/api/v1/sql-workflows/list/", map[string]int{"limit": page, "offset": offset}, &res); err != nil {
			return 0, err
		}
		for _, r := range res.Rows {
			if r.WorkflowID == workflowID && r.AuditID > 0 {
				auditIDs.Store(b.key(workflowID), r.AuditID)
				return r.AuditID, nil
			}
		}
		if len(res.Rows) < page {
			break
		}
	}
	return 0, fmt.Errorf("%w: %d (not visible to this user?)", ErrNotFound, workflowID)
}

func auditPath(id int, op string) string {
	return "/api/v1/sql-workflows/" + strconv.Itoa(id) + "/" + op + "/"
}

func (b *restBackend) instances(ctx context.Context) ([]Instance, error) {
	const path = "/api/v1/sqlquery/instances/"
	var env envelope
	if err := b.c.call(ctx, "GET", path, nil, &env); err != nil {
		return nil, err
	}
	if err := b.c.legacy(path, &env); err != nil {
		return nil, err
	}
	return toInstances(env.Data)
}

func (b *restBackend) databases(ctx context.Context, instance string) ([]string, error) {
	path := "/api/v1/sqlquery/resources/?resource_type=database&instance_name=" + url.QueryEscape(instance)
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

func (b *restBackend) query(ctx context.Context, q QueryRequest) (*QueryResult, error) {
	const path = "/api/v1/sqlquery/execute/"
	var env envelope
	if err := b.c.call(ctx, "POST", path, map[string]any{
		"instance_name": q.Instance, "db_name": q.Database, "schema_name": q.Schema, "tb_name": "",
		"sql_content": q.SQL, "limit_num": q.Limit}, &env); err != nil {
		return nil, err
	}
	return queryResult(path, &env, q.Limit, b.c)
}

func (b *restBackend) submit(ctx context.Context, r SubmitRequest, groupID, instanceID int) (*Submitted, error) {
	const path = "/api/v1/sql-workflows/"
	var env envelope
	if err := b.c.call(ctx, "POST", path, map[string]any{
		"workflow": map[string]any{
			"workflow_name": r.Title, "demand_url": r.Remark, "group_id": groupID, "instance": instanceID,
			"db_name": r.Database, "is_backup": r.Backup, "is_offline_export": 0,
		},
		"sql_content": r.SQL,
	}, &env); err != nil {
		return nil, err
	}
	if err := b.c.legacy(path, &env); err != nil {
		return nil, err
	}
	var d struct {
		AuditID    int `json:"audit_id"`
		WorkflowID int `json:"workflow_id"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil || d.AuditID == 0 || d.WorkflowID == 0 {
		return nil, &APIError{path, "no audit_id/workflow_id in response"}
	}
	auditIDs.Store(b.key(d.WorkflowID), d.AuditID)
	return &Submitted{WorkflowID: d.WorkflowID, AuditID: d.AuditID}, nil
}

func (b *restBackend) status(ctx context.Context, id int) (string, error) {
	a, err := b.audit(ctx, id)
	if err != nil {
		return "", err
	}
	var res struct {
		Status string `json:"status"`
	}
	if err := b.c.call(ctx, "GET", auditPath(a, "status"), nil, &res); err != nil {
		var ae *APIError
		if asAPIError(err, &ae) && strings.Contains(ae.Msg, "HTTP 404") {
			return "", fmt.Errorf("%w: %d (not visible to this user?)", ErrNotFound, id)
		}
		return "", err
	}
	return res.Status, nil
}

func (b *restBackend) execute(ctx context.Context, id int) error {
	a, err := b.audit(ctx, id)
	if err != nil {
		return err
	}
	var env envelope
	if err := b.c.call(ctx, "POST", auditPath(a, "execution"), map[string]string{"mode": "auto"}, &env); err != nil {
		return err
	}
	return b.c.legacy("execution", &env)
}

func (b *restBackend) cancel(ctx context.Context, id int, reason string) error {
	a, err := b.audit(ctx, id)
	if err != nil {
		return err
	}
	var env envelope
	if err := b.c.call(ctx, "POST", auditPath(a, "cancellation"), map[string]string{"cancel_remark": reason}, &env); err != nil {
		return err
	}
	return b.c.legacy("cancellation", &env)
}

func (b *restBackend) results(ctx context.Context, id int) ([]ResultRow, error) {
	a, err := b.audit(ctx, id)
	if err != nil {
		return nil, err
	}
	var res struct {
		Rows []reviewRow `json:"rows"`
	}
	if err := b.c.call(ctx, "GET", auditPath(a, "content"), nil, &res); err != nil {
		return nil, err
	}
	return toResultRows(res.Rows), nil
}

func (b *restBackend) logs(ctx context.Context, id int) ([]LogEntry, error) {
	a, err := b.audit(ctx, id)
	if err != nil {
		return nil, err
	}
	var res struct {
		Rows []LogEntry `json:"rows"`
	}
	if err := b.c.call(ctx, "GET", auditPath(a, "logs"), nil, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}
