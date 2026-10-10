// Package archerytest provides a fake Archery server for tests.
package archerytest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Fake is an in-memory imitation of the Archery endpoints used by the client.
type Fake struct {
	Mu        sync.Mutex
	TwoFA     bool
	Verified  bool
	Status    string // workflow status code
	Executed  int
	Cancelled bool
	Submitted url.Values
}

func (f *Fake) Handler() http.Handler {
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		c, err := r.Cookie("sessionid")
		if err != nil || c.Value != "S" || (r.Method != http.MethodGet && r.Header.Get("X-CSRFToken") != "CSRF") {
			http.Redirect(w, r, "/login/", 302)
			return false
		}
		return true
	}
	jsonOut := func(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "CSRF", Path: "/"})
		w.Write([]byte("login page"))
	})
	mux.HandleFunc("/authenticate/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Header.Get("X-CSRFToken") != "CSRF" || r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
			jsonOut(w, map[string]any{"status": 1, "msg": "invalid username or password"})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "S", Path: "/"})
		data := "/"
		if f.TwoFA {
			data = "/2fa/"
		}
		jsonOut(w, map[string]any{"status": 0, "msg": "ok", "data": data})
	})
	mux.HandleFunc("/twofa/verify/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("otp") != "123456" {
			jsonOut(w, map[string]any{"status": 1, "msg": "wrong otp"})
			return
		}
		f.Verified = true
		jsonOut(w, map[string]any{"status": 0, "msg": "ok"})
	})
	mux.HandleFunc("/sqlquery/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			w.Write([]byte("ok"))
		}
	})
	mux.HandleFunc("/query/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		r.ParseForm()
		jsonOut(w, map[string]any{"status": 0, "msg": "ok", "data": map[string]any{
			"column_list": []string{"id", "name"}, "rows": [][]any{{1, "a"}, {2, "b"}}, "query_time": 0.012}})
	})
	mux.HandleFunc("/group/user_all_instances/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			jsonOut(w, map[string]any{"status": 0, "data": []map[string]any{{"instance_name": "prod", "type": "master", "db_type": "mysql"}}})
		}
	})
	mux.HandleFunc("/simplecheck/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		r.ParseForm()
		lvl, msg := 0, ""
		if strings.Contains(r.PostForm.Get("sql_content"), "BADSQL") {
			lvl, msg = 2, "syntax error"
		}
		jsonOut(w, map[string]any{"status": 0, "data": map[string]any{"rows": []map[string]any{{"id": 1, "errlevel": lvl, "errormessage": msg, "sql": "x"}}}})
	})
	mux.HandleFunc("/autoreview/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		r.ParseForm()
		f.Mu.Lock()
		f.Submitted = r.PostForm
		f.Status = "workflow_manreviewing"
		f.Mu.Unlock()
		jsonOut(w, map[string]any{"status": 0, "msg": "", "data": map[string]any{"workflow_id": 42}})
	})
	mux.HandleFunc("/sqlworkflow_list/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		f.Mu.Lock()
		defer f.Mu.Unlock()
		jsonOut(w, map[string]any{"total": 1, "rows": []map[string]any{{"id": 42, "workflow_name": "t", "status": f.Status, "engineer_display": "alice", "db_name": "d"}}})
	})
	mux.HandleFunc("/execute/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		f.Mu.Lock()
		f.Executed++
		f.Status = "workflow_finish"
		f.Mu.Unlock()
		jsonOut(w, map[string]any{"status": 0, "msg": "ok"})
	})
	mux.HandleFunc("/cancel/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		f.Mu.Lock()
		f.Cancelled, f.Status = true, "workflow_abort"
		f.Mu.Unlock()
		jsonOut(w, map[string]any{"status": 0})
	})
	mux.HandleFunc("/workflow/detail_content/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			jsonOut(w, map[string]any{"total": 1, "rows": []map[string]any{{"id": 1, "errlevel": 0, "sql": "UPDATE t SET a=1", "affected_rows": 3, "execute_time": "0.008"}}})
		}
	})
	return mux
}
