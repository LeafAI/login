package archery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
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

// ErrSessionInvalid means the session cookie was rejected (expired or logged out).
var ErrSessionInvalid = errors.New("archery session is no longer valid")

// APIError is an error reported by Archery itself.
type APIError struct{ Path, Msg string }

func (e *APIError) Error() string { return "archery " + e.Path + ": " + e.Msg }

func (c *Client) do(ctx context.Context, method, path string, body []byte, contentType string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base.String()+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Cookie", site.CookieHeader(c.Sess.Cookies))
	req.Header.Set("X-CSRFToken", c.Sess.Headers["X-CSRFToken"])
	req.Header.Set("Referer", c.Base.String()+"/")
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := site.NoRedirect(c.HC).Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return resp.StatusCode, site.ReadBody(resp), nil
}

// call performs a JSON request and decodes a successful JSON response into out (if non-nil).
func (c *Client) call(ctx context.Context, method, path string, payload, out any) error {
	var body []byte
	ct := ""
	if payload != nil {
		body, _ = json.Marshal(payload)
		ct = "application/json"
	}
	return c.finish(c.do(ctx, method, path, body, ct))(path, out)
}

// form performs a form-encoded request (Archery's older ajax endpoints).
func (c *Client) form(ctx context.Context, path string, v url.Values, out any) error {
	return c.finish(c.do(ctx, "POST", path, []byte(v.Encode()), "application/x-www-form-urlencoded"))(path, out)
}

func (c *Client) finish(code int, raw string, err error) func(string, any) error {
	return func(path string, out any) error {
		if err != nil {
			return err
		}
		switch {
		case code >= 300 && code < 400:
			return ErrSessionInvalid
		case code == 401, code == 403 && strings.Contains(raw, "credentials were not provided"):
			return ErrSessionInvalid
		case code >= 400:
			return &APIError{path, fmt.Sprintf("HTTP %d: %s", code, site.Clip(raw, 300))}
		}
		if out != nil {
			if err := json.Unmarshal([]byte(raw), out); err != nil {
				return &APIError{path, "unexpected response: " + site.Clip(raw, 160)}
			}
		}
		return nil
	}
}

// legacy decodes Archery's {status,msg,data} envelope and fails on status != 0.
func (c *Client) legacy(path string, env *envelope) error {
	if env.Status != 0 {
		return &APIError{path, site.Clip(env.Msg, 300)}
	}
	return nil
}

type Instance struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	DBType string `json:"db_type"`
}

type rawInstance struct {
	ID     int    `json:"id"`
	Name   string `json:"instance_name"`
	Type   string `json:"type"`
	DBType string `json:"db_type"`
}

func toInstances(data json.RawMessage) ([]Instance, error) {
	var rows []rawInstance
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	out := make([]Instance, len(rows))
	for i, r := range rows {
		out[i] = Instance{ID: r.ID, Name: r.Name, Type: r.Type, DBType: r.DBType}
	}
	return out, nil
}

// Generation names stored in Session.Tokens["api"].
const (
	GenLegacy = "legacy" // Archery 1.x ajax endpoints (e.g. v1.12.0)
	GenREST   = "rest"   // newer Archery with /api/v1/sqlquery and /api/v1/sql-workflows
)

// backend implements the generation-specific operations. Workflow handles are Archery workflow ids.
type backend interface {
	instances(ctx context.Context) ([]Instance, error)
	databases(ctx context.Context, instance string) ([]string, error)
	query(ctx context.Context, q QueryRequest) (*QueryResult, error)
	submit(ctx context.Context, r SubmitRequest, groupID, instanceID int) (*Submitted, error)
	status(ctx context.Context, id int) (string, error)
	execute(ctx context.Context, id int) error
	cancel(ctx context.Context, id int, reason string) error
	results(ctx context.Context, id int) ([]ResultRow, error)
	logs(ctx context.Context, id int) ([]LogEntry, error)
}

func (c *Client) be() backend {
	if c.Sess.Tokens["api"] == GenREST {
		return &restBackend{c: c}
	}
	return &legacyBackend{c: c}
}

// Instances lists the instances the user may query.
func (c *Client) Instances(ctx context.Context) ([]Instance, error) { return c.be().instances(ctx) }

// Databases lists the databases of an instance.
func (c *Client) Databases(ctx context.Context, instance string) ([]string, error) {
	return c.be().databases(ctx, instance)
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

// Query runs a read-only statement through Archery's query API.
func (c *Client) Query(ctx context.Context, q QueryRequest) (*QueryResult, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	return c.be().query(ctx, q)
}

type Group struct {
	ID   int
	Name string
}

var groupOption = regexp.MustCompile(`<option\s+value="([^"]*)"\s+group-id="(\d+)"`)

// Groups lists the resource groups of the user, read from the SQL submission page (Archery has no
// non-admin API for it).
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	code, raw, err := c.do(ctx, "GET", "/submitsql/", nil, "")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, c.finish(code, raw, nil)("/submitsql/", nil)
	}
	var out []Group
	for _, m := range groupOption.FindAllStringSubmatch(raw, -1) {
		id, _ := strconv.Atoi(m[2])
		out = append(out, Group{ID: id, Name: html.UnescapeString(m[1])})
	}
	return out, nil
}

// GroupInstances lists the instances of a resource group that may receive changes.
func (c *Client) GroupInstances(ctx context.Context, group string) ([]Instance, error) {
	var env envelope
	if err := c.form(ctx, "/group/instances/", url.Values{"group_name": {group}, "tag_code": {"can_write"}}, &env); err != nil {
		return nil, err
	}
	if err := c.legacy("/group/instances/", &env); err != nil {
		return nil, err
	}
	return toInstances(env.Data)
}

// queryResult converts the {status,msg,data} answer of Archery's query endpoints (both generations).
func queryResult(path string, env *envelope, limit int, c *Client) (*QueryResult, error) {
	if err := c.legacy(path, env); err != nil {
		return nil, err
	}
	var d struct {
		Columns   []string `json:"column_list"`
		Rows      [][]any  `json:"rows"`
		QueryTime float64  `json:"query_time"`
		MaskHit   bool     `json:"mask_rule_hit"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil {
		return nil, &APIError{path, "unexpected data: " + err.Error()}
	}
	r := &QueryResult{Columns: d.Columns, Rows: d.Rows, RowCount: len(d.Rows), CostMS: int64(d.QueryTime * 1000),
		Truncated: len(d.Rows) >= limit}
	if d.MaskHit {
		r.Warnings = append(r.Warnings, "some columns were masked by Archery")
	}
	if env.Msg != "" && env.Msg != "ok" {
		r.Warnings = append(r.Warnings, env.Msg)
	}
	return r, nil
}
