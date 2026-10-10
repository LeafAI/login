// Package archerytest provides a fake Archery server for tests. It mimics the contract found in the
// Archery source (ajax login + 2FA verify, session/CSRF handling, /api/v1 REST endpoints).
package archerytest

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

const (
	AuditID    = 42
	WorkflowID = 9
	csrfBefore = "CSRF"  // issued by /login/
	csrfAfter  = "CSRF2" // Django rotates the CSRF token when the user logs in
	tempKey    = "TEMPKEY"
)

// Fake is an in-memory imitation of the Archery endpoints used by the client.
type Fake struct {
	Mu           sync.Mutex
	TwoFA        bool
	Verified     bool
	Status       string // SqlWorkflow.status code, e.g. workflow_manreviewing
	Executed     int
	Cancelled    bool
	CancelRemark string
	Submitted    map[string]any
	LogOp        string // newest workflow log entry (operation_type_desc), if any
	LogInfo      string
}

func (f *Fake) Handler() http.Handler {
	mux := http.NewServeMux()
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	login := func(w http.ResponseWriter) {
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "S", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: csrfAfter, Path: "/"})
	}
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		c, err := r.Cookie("sessionid")
		if err != nil || c.Value != "S" {
			out(w, 403, map[string]string{"detail": "Authentication credentials were not provided."})
			return false
		}
		if r.Method != http.MethodGet && r.Header.Get("X-CSRFToken") != csrfAfter {
			out(w, 403, map[string]string{"detail": "CSRF Failed: CSRF token missing or incorrect."})
			return false
		}
		return true
	}
	body := func(r *http.Request) map[string]any {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		return m
	}

	mux.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: csrfBefore, Path: "/"})
		w.Write([]byte("login page"))
	})
	mux.HandleFunc("/authenticate/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Header.Get("X-CSRFToken") != csrfBefore || r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
			out(w, 200, map[string]any{"status": 1, "msg": "用户名或密码错误，请重新输入！", "data": ""})
			return
		}
		if f.TwoFA { // Archery returns a temporary session key and does not log the user in yet
			out(w, 200, map[string]any{"status": 0, "msg": "ok", "data": tempKey})
			return
		}
		login(w)
		out(w, 200, map[string]any{"status": 0, "msg": "ok", "data": nil})
	})
	mux.HandleFunc("/api/v1/user/2fa/verify/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if c, err := r.Cookie("sessionid"); err != nil || c.Value != tempKey {
			out(w, 200, map[string]any{"status": 1, "msg": "需先校验用户密码！"})
			return
		}
		if r.PostForm.Get("otp") != "123456" || r.PostForm.Get("auth_type") != "totp" || r.PostForm.Get("engineer") != "alice" {
			out(w, 200, map[string]any{"status": 1, "msg": "验证码错误"})
			return
		}
		f.Mu.Lock()
		f.Verified = true
		f.Mu.Unlock()
		login(w)
		out(w, 200, map[string]any{"status": 0, "msg": "ok"})
	})

	mux.HandleFunc("/api/v1/sqlquery/instances/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			out(w, 200, map[string]any{"status": 0, "msg": "ok", "data": []map[string]any{{"id": 7, "type": "master", "db_type": "mysql", "instance_name": "prod"}}})
		}
	})
	mux.HandleFunc("/api/v1/sqlquery/resources/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		if r.URL.Query().Get("resource_type") != "database" || r.URL.Query().Get("instance_name") != "prod" {
			out(w, 400, map[string]string{"detail": "bad query"})
			return
		}
		out(w, 200, map[string]any{"status": 0, "msg": "ok", "data": []string{"d", "orders"}})
	})
	mux.HandleFunc("/api/v1/sqlquery/execute/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		b := body(r)
		if b["instance_name"] != "prod" || b["sql_content"] == nil {
			out(w, 400, map[string]string{"detail": "bad payload"})
			return
		}
		out(w, 200, map[string]any{"status": 0, "msg": "ok", "data": map[string]any{
			"column_list": []string{"id", "name"}, "rows": [][]any{{1, "a"}, {2, "b"}}, "query_time": 0.012}})
	})
	mux.HandleFunc("/submitsql/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			w.Write([]byte(`<select id="group_name"><option value="dba"
                                                group-id="3">dba</option><option value="dev" group-id="4">dev</option></select>`))
		}
	})
	mux.HandleFunc("/group/instances/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		r.ParseForm()
		if r.PostForm.Get("group_name") != "dba" || r.PostForm.Get("tag_code") != "can_write" {
			out(w, 200, map[string]any{"status": 0, "data": []any{}})
			return
		}
		out(w, 200, map[string]any{"status": 0, "msg": "ok", "data": []map[string]any{{"id": 7, "instance_name": "prod", "db_type": "mysql"}}})
	})
	mux.HandleFunc("/api/v1/workflow/sqlcheck/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		b := body(r)
		lvl, msg := 0, ""
		if s, _ := b["full_sql"].(string); strings.Contains(s, "BADSQL") {
			lvl, msg = 2, "syntax error"
		}
		if b["instance_id"] != float64(7) {
			out(w, 400, map[string]any{"errors": "no such instance"})
			return
		}
		out(w, 200, map[string]any{"error_count": lvl / 2, "rows": []map[string]any{{"id": 1, "errlevel": lvl, "errormessage": msg, "sql": "x"}}})
	})
	mux.HandleFunc("/api/v1/sql-workflows/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/sql-workflows/"), "/")
		if path == "" && r.Method == http.MethodPost {
			b := body(r)
			wf, _ := b["workflow"].(map[string]any)
			if wf == nil || wf["group_id"] != float64(3) || wf["instance"] != float64(7) || b["sql_content"] == nil {
				out(w, 400, map[string]any{"errors": "bad payload"})
				return
			}
			f.Mu.Lock()
			f.Submitted = b
			f.Status = "workflow_manreviewing"
			f.Mu.Unlock()
			out(w, 201, map[string]any{"status": 0, "msg": "提交成功", "data": map[string]any{"audit_id": AuditID, "workflow_id": WorkflowID, "redirect_url": "/detail/9/"}})
			return
		}
		parts := strings.Split(path, "/")
		if len(parts) != 2 || parts[0] != "42" {
			out(w, 404, map[string]string{"detail": "工单不存在"})
			return
		}
		f.Mu.Lock()
		defer f.Mu.Unlock()
		switch parts[1] {
		case "status":
			out(w, 200, map[string]any{"status": f.Status, "msg": "", "data": ""})
		case "execution":
			if body(r)["mode"] != "auto" {
				out(w, 400, map[string]string{"mode": "bad"})
				return
			}
			f.Executed++
			f.Status = "workflow_finish"
			out(w, 200, map[string]any{"status": 0, "msg": "工单执行排队中", "data": map[string]any{"audit_id": AuditID}})
		case "cancellation":
			remark, _ := body(r)["cancel_remark"].(string)
			if strings.TrimSpace(remark) == "" {
				out(w, 400, map[string]any{"cancel_remark": []string{"This field may not be blank."}})
				return
			}
			f.Cancelled, f.CancelRemark, f.Status = true, remark, "workflow_abort"
			out(w, 200, map[string]any{"status": 0, "msg": "工单已终止"})
		case "content":
			out(w, 200, map[string]any{"rows": []map[string]any{{"id": 1, "errlevel": 0, "sql": "UPDATE t SET a=1", "affected_rows": 3, "execute_time": "0.008", "backup_dbname": ""}}})
		case "logs":
			rows := []map[string]any{{"operation_type_desc": "提交", "operation_info": "", "operator_display": "alice", "operation_time": "2026-01-01T00:00:00"}}
			if f.LogOp != "" {
				rows = append([]map[string]any{{"operation_type_desc": f.LogOp, "operation_info": f.LogInfo, "operator_display": "lisi", "operation_time": "2026-01-01T00:05:00"}}, rows...)
			}
			out(w, 200, map[string]any{"total": len(rows), "rows": rows})
		default:
			out(w, 404, map[string]string{"detail": "not found"})
		}
	})
	return mux
}
