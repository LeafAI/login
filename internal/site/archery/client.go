package archery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/LeafAI/login/internal/site"
)

// Client calls Archery with an established session.
type Client struct {
	Base *url.URL
	Sess *site.Session
	HC   *http.Client
}

func (c *Client) do(ctx context.Context, method, path string, form url.Values, follow bool) (*http.Response, string, error) {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.Base.String()+path, body)
	req.Header.Set("Cookie", site.CookieHeader(c.Sess.Cookies))
	req.Header.Set("X-CSRFToken", c.Sess.Headers["X-CSRFToken"])
	req.Header.Set("Referer", c.Base.String()+"/")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	hc := c.HC
	if !follow {
		hc = site.NoRedirect(hc)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return resp, site.ReadBody(resp), nil
}

// call performs a request and decodes Archery's {status,msg,data} envelope.
func (c *Client) call(ctx context.Context, method, path string, form url.Values) (*envelope, error) {
	resp, raw, err := c.do(ctx, method, path, form, false)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 302 || resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("archery session is no longer valid (%s %s -> %d)", method, path, resp.StatusCode)
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, fmt.Errorf("archery %s: unexpected response (%d): %s", path, resp.StatusCode, site.Clip(raw, 160))
	}
	return &env, nil
}

// APIError is an error reported by Archery itself.
type APIError struct{ Path, Msg string }

func (e *APIError) Error() string { return "archery " + e.Path + ": " + e.Msg }

func (c *Client) must(ctx context.Context, method, path string, form url.Values) (*envelope, error) {
	env, err := c.call(ctx, method, path, form)
	if err != nil {
		return nil, err
	}
	if env.Status != 0 {
		return nil, &APIError{path, site.Clip(env.Msg, 300)}
	}
	return env, nil
}

type Instance struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	DBType string `json:"db_type"`
}

// Instances lists the instances the user can access.
func (c *Client) Instances(ctx context.Context) ([]Instance, error) {
	env, err := c.must(ctx, "POST", "/group/user_all_instances/", url.Values{"db_type[]": {}})
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Name   string `json:"instance_name"`
		Type   string `json:"type"`
		DBType string `json:"db_type"`
	}
	if err := json.Unmarshal(env.Data, &rows); err != nil {
		return nil, fmt.Errorf("archery instances: %w", err)
	}
	out := make([]Instance, len(rows))
	for i, r := range rows {
		out[i] = Instance{Name: r.Name, Type: r.Type, DBType: r.DBType}
	}
	return out, nil
}

// Databases lists the databases of an instance.
func (c *Client) Databases(ctx context.Context, instance string) ([]string, error) {
	env, err := c.must(ctx, "POST", "/instance/instance_resource/", url.Values{"instance_name": {instance}, "resource_type": {"database"}})
	if err != nil {
		return nil, err
	}
	var dbs []string
	json.Unmarshal(env.Data, &dbs)
	return dbs, nil
}

type QueryRequest struct {
	Instance, Database, Schema, SQL string
	Limit                           int
}

type QueryResult struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	RowCount  int      `json:"row_count"`
	Truncated bool     `json:"truncated"`
	CostMS    int64    `json:"cost_ms"`
	Warnings  []string `json:"warnings,omitempty"`
}

var readOnly = regexp.MustCompile(`(?is)^\s*(select|show|desc|describe|explain|with)\b`)

// IsReadOnly reports whether sql is a single read-only statement.
func IsReadOnly(sql string) bool {
	s := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(sql), ";"))
	return readOnly.MatchString(s) && !strings.Contains(s, ";")
}

func (c *Client) Query(ctx context.Context, q QueryRequest) (*QueryResult, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	env, err := c.must(ctx, "POST", "/query/", url.Values{
		"instance_name": {q.Instance}, "db_name": {q.Database}, "schema_name": {q.Schema}, "tb_name": {""},
		"sql_content": {q.SQL}, "limit_num": {strconv.Itoa(q.Limit)}})
	if err != nil {
		return nil, err
	}
	var d struct {
		Columns   []string `json:"column_list"`
		Rows      [][]any  `json:"rows"`
		Affected  int      `json:"affected_rows"`
		QueryTime float64  `json:"query_time"`
		MaskHit   bool     `json:"mask_rule_hit"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return nil, fmt.Errorf("archery query: %w", err)
	}
	r := &QueryResult{Columns: d.Columns, Rows: d.Rows, RowCount: len(d.Rows), CostMS: int64(d.QueryTime * 1000),
		Truncated: len(d.Rows) >= q.Limit}
	if d.MaskHit {
		r.Warnings = append(r.Warnings, "some columns were masked by Archery")
	}
	if env.Msg != "" && env.Msg != "ok" {
		r.Warnings = append(r.Warnings, env.Msg)
	}
	return r, nil
}
