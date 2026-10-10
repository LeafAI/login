package mcpserver

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/archery"
)

// archeryClient logs in (cached or interactive) and returns an API client. When the login is still
// pending after max, pending is non-nil.
func (s *Server) archeryClient(ctx context.Context, req *mcp.CallToolRequest, u ArcheryURL, max time.Duration) (c *archery.Client, pending *LoginOutput, terr *ToolError) {
	name := u.Site
	if name == "" {
		name = "archery"
	}
	out, terr := s.ensureLogin(ctx, req, u.URL, name, "Archery access for an SQL task", false, true, max)
	if terr != nil {
		return nil, nil, terr
	}
	if out.Status != "ok" {
		return nil, out, nil
	}
	base, _ := baseOf(u.URL)
	e, ok := s.cache.Get(ctx, base, s.hc)
	if !ok {
		return nil, nil, errf("internal", true, "session vanished right after login; retry")
	}
	return &archery.Client{Base: base, Sess: e.Session, HC: s.hc}, nil, nil
}

func archeryErr(err error) *ToolError {
	var cf *archery.CheckFailed
	var ae *archery.APIError
	switch {
	case errors.Is(err, archery.ErrDDLDisabled):
		return errf("ddl_disabled", false, "%v", err)
	case errors.As(err, &cf):
		e := errf("sql_check_failed", false, "%v", err)
		e.Hint = "Fix the SQL and call archery_run_sql again."
		return e
	case errors.Is(err, archery.ErrSessionInvalid):
		e := errf("session_expired", true, "%v", err)
		e.Hint = "Call login with force_refresh=true, then retry."
		return e
	case errors.Is(err, archery.ErrNotFound):
		return errf("workflow_not_found", false, "%v", err)
	case errors.As(err, &ae):
		return errf("archery_error", false, "%v", err)
	case errors.Is(err, site.ErrUnreachable):
		return errf("site_unreachable", true, "%v", err)
	}
	return errf("internal", false, "%v", err)
}

func (s *Server) archeryInstances(ctx context.Context, req *mcp.CallToolRequest, in InstancesInput) (any, *ToolError) {
	c, pending, terr := s.archeryClient(ctx, req, in.ArcheryURL, s.maxBlock(0))
	if terr != nil {
		return nil, terr
	}
	if pending != nil {
		return InstancesOutput{Pending: pending}, nil
	}
	var out InstancesOutput
	var err error
	if out.Instances, err = c.Instances(ctx); err != nil {
		return nil, archeryErr(err)
	}
	if in.Instance != "" {
		if out.Databases, err = c.Databases(ctx, in.Instance); err != nil {
			return nil, archeryErr(err)
		}
	}
	return out, nil
}

func (s *Server) archeryQuery(ctx context.Context, req *mcp.CallToolRequest, in QueryInput) (any, *ToolError) {
	if !archery.IsReadOnly(in.SQL) {
		return nil, errf("invalid_argument", false, "archery_query accepts a single read-only statement; use archery_run_sql for changes")
	}
	if in.Instance == "" || in.Database == "" {
		return nil, errf("invalid_argument", false, "instance and database are required")
	}
	c, pending, terr := s.archeryClient(ctx, req, in.ArcheryURL, s.maxBlock(0))
	if terr != nil {
		return nil, terr
	}
	if pending != nil {
		return QueryOutput{Login: pending}, nil
	}
	if in.Limit > 10000 {
		in.Limit = 10000
	}
	r, err := c.Query(ctx, archery.QueryRequest{Instance: in.Instance, Database: in.Database, Schema: in.Schema, SQL: in.SQL, Limit: in.Limit})
	if err != nil {
		return nil, archeryErr(err)
	}
	return QueryOutput{QueryResult: r}, nil
}

func pendingLogin(p *LoginOutput) ArcheryOut {
	return ArcheryOut{Outcome: archery.Outcome{Status: "pending", Phase: "login"}, LoginID: p.LoginID, NextTool: "login_wait"}
}

func finishOutcome(o *archery.Outcome) ArcheryOut {
	out := ArcheryOut{Outcome: *o}
	if o.Status == "pending" {
		out.NextTool = "archery_wait"
	}
	return out
}

func (s *Server) archeryRunSQL(ctx context.Context, req *mcp.CallToolRequest, in RunSQLInput) (any, *ToolError) {
	if in.Instance == "" || in.Database == "" || in.SQL == "" || in.Title == "" {
		return nil, errf("invalid_argument", false, "instance, database, sql and title are required")
	}
	if len(in.Title) > 50 {
		in.Title = in.Title[:50]
	}
	group := in.ResourceGroup
	if group == "" {
		group = s.cfg.Archery.DefaultGroup
	}
	if group == "" {
		return nil, errf("invalid_argument", false, "resource_group is required (or set archery.default_group in the config)")
	}
	max := s.maxBlock(in.MaxBlockSeconds)
	c, pending, terr := s.archeryClient(ctx, req, in.ArcheryURL, max)
	if terr != nil {
		return nil, terr
	}
	if pending != nil {
		return pendingLogin(pending), nil
	}
	backup := in.Backup == nil || *in.Backup
	sub, err := s.tracker.Submit(ctx, c, s.notify, archery.SubmitRequest{
		Instance: in.Instance, Database: in.Database, SQL: in.SQL, Title: in.Title, Remark: in.Remark, Group: group, Backup: backup},
		time.Duration(in.ApprovalTimeout)*time.Second)
	if err != nil {
		return nil, archeryErr(err)
	}
	if in.Wait != nil && !*in.Wait {
		return finishOutcome(sub), nil
	}
	return s.waitWorkflow(ctx, req, c, sub.AuditID, max, sub.Check)
}

func (s *Server) waitWorkflow(ctx context.Context, req *mcp.CallToolRequest, c *archery.Client, id int, max time.Duration, check []archery.CheckRow) (any, *ToolError) {
	var n float64
	out, err := s.tracker.Wait(ctx, c, id, max, func(phase string) {
		s.progress(ctx, req, &n, "archery workflow "+itoa(id)+": "+phase)
	})
	if err != nil {
		return nil, archeryErr(err)
	}
	if out.Check == nil {
		out.Check = check
	}
	return finishOutcome(out), nil
}

func (s *Server) archeryWait(ctx context.Context, req *mcp.CallToolRequest, in WaitInput) (any, *ToolError) {
	max := s.maxBlock(in.MaxBlockSeconds)
	c, pending, terr := s.archeryClient(ctx, req, in.ArcheryURL, max)
	if terr != nil {
		return nil, terr
	}
	if pending != nil {
		return pendingLogin(pending), nil
	}
	return s.waitWorkflow(ctx, req, c, in.AuditID, max, nil)
}

func (s *Server) archeryStatus(ctx context.Context, req *mcp.CallToolRequest, in StatusInput) (any, *ToolError) {
	c, pending, terr := s.archeryClient(ctx, req, in.ArcheryURL, s.maxBlock(0))
	if terr != nil {
		return nil, terr
	}
	if pending != nil {
		return pendingLogin(pending), nil
	}
	code, err := c.Status(ctx, in.AuditID)
	if err != nil {
		return nil, archeryErr(err)
	}
	phase := archery.PhaseOf(code)
	out := StatusOutput{AuditID: in.AuditID, Status: phase, StatusCode: code, WorkflowURL: strings.TrimRight(c.Base.String(), "/") + "/workflow/" + itoa(in.AuditID) + "/"}
	if phase == archery.PhaseDone || phase == archery.PhaseFailed {
		if out.Results, err = c.Results(ctx, in.AuditID); err != nil {
			return nil, archeryErr(err)
		}
	}
	return out, nil
}

func (s *Server) archeryCancel(ctx context.Context, req *mcp.CallToolRequest, in CancelInput) (any, *ToolError) {
	c, pending, terr := s.archeryClient(ctx, req, in.ArcheryURL, s.maxBlock(0))
	if terr != nil {
		return nil, terr
	}
	if pending != nil {
		return pendingLogin(pending), nil
	}
	code, err := c.Status(ctx, in.AuditID)
	if err != nil {
		return nil, archeryErr(err)
	}
	if phase := archery.PhaseOf(code); phase == archery.PhaseExecuting || phase == archery.PhaseDone || phase == archery.PhaseFailed || phase == archery.PhaseAborted {
		return nil, errf("invalid_argument", false, "workflow %d is already %s and cannot be cancelled", in.AuditID, phase)
	}
	if err := c.Cancel(ctx, in.AuditID, in.Reason); err != nil {
		return nil, archeryErr(err)
	}
	return CancelOutput{Status: "aborted"}, nil
}

func itoa(n int) string { return url.QueryEscape(sprintf("%d", n)) }
