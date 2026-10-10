package archery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/sitetest"
)

type fake struct {
	mu        sync.Mutex
	twoFA     bool
	verified  bool
	status    string // workflow status code
	executed  int
	cancelled bool
	submitted url.Values
}

func (f *fake) handler() http.Handler {
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		c, err := r.Cookie("sessionid")
		if err != nil || c.Value != "S" || r.Header.Get("X-CSRFToken") != "CSRF" {
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
		if f.twoFA {
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
		f.verified = true
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
		f.mu.Lock()
		f.submitted = r.PostForm
		f.status = "workflow_manreviewing"
		f.mu.Unlock()
		jsonOut(w, map[string]any{"status": 0, "msg": "", "data": map[string]any{"workflow_id": 42}})
	})
	mux.HandleFunc("/sqlworkflow_list/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		jsonOut(w, map[string]any{"total": 1, "rows": []map[string]any{{"id": 42, "workflow_name": "t", "status": f.status, "engineer_display": "alice", "db_name": "d"}}})
	})
	mux.HandleFunc("/execute/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		f.mu.Lock()
		f.executed++
		f.status = "workflow_finish"
		f.mu.Unlock()
		jsonOut(w, map[string]any{"status": 0, "msg": "ok"})
	})
	mux.HandleFunc("/cancel/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		f.mu.Lock()
		f.cancelled, f.status = true, "workflow_abort"
		f.mu.Unlock()
		jsonOut(w, map[string]any{"status": 0})
	})
	mux.HandleFunc("/workflow/detail_content/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			jsonOut(w, map[string]any{"total": 1, "rows": []map[string]any{{"id": 1, "errlevel": 0, "sql": "UPDATE t SET a=1", "affected_rows": 3, "execute_time": "0.008"}}})
		}
	})
	return mux
}

func setup(t *testing.T, f *fake, answers map[string]site.Credentials) (*Client, *sitetest.Asker) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	a := &sitetest.Asker{Answers: answers}
	s, err := driver{}.Login(context.Background(), base, a, srv.Client())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return &Client{Base: base, Sess: s, HC: srv.Client()}, a
}

var okCreds = map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}, "totp": {"code": "123456"}}

func TestLoginAnd2FA(t *testing.T) {
	f := &fake{}
	_, a := setup(t, f, okCreds)
	if strings.Join(a.Asked, ",") != "login" {
		t.Errorf("asked %v", a.Asked)
	}
	f2 := &fake{twoFA: true}
	_, a = setup(t, f2, okCreds)
	if strings.Join(a.Asked, ",") != "login,totp" || !f2.verified {
		t.Errorf("2fa asked %v verified=%v", a.Asked, f2.verified)
	}
}

func TestLoginFailures(t *testing.T) {
	srv := httptest.NewServer((&fake{twoFA: true}).handler())
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	bad := &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := (driver{}).Login(context.Background(), base, bad, srv.Client()); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad password: %v", err)
	}
	wrongCode := &sitetest.Asker{Answers: map[string]site.Credentials{"login": okCreds["login"], "totp": {"code": "000000"}}}
	if _, err := (driver{}).Login(context.Background(), base, wrongCode, srv.Client()); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad otp: %v", err)
	}
}

func TestQueryAndInstances(t *testing.T) {
	c, _ := setup(t, &fake{}, okCreds)
	q, err := c.Query(context.Background(), QueryRequest{Instance: "prod", Database: "d", SQL: "select 1", Limit: 100})
	if err != nil || q.RowCount != 2 || q.Columns[1] != "name" || q.CostMS != 12 {
		t.Fatalf("%+v %v", q, err)
	}
	ins, err := c.Instances(context.Background())
	if err != nil || len(ins) != 1 || ins[0].Name != "prod" {
		t.Fatalf("%+v %v", ins, err)
	}
	if !IsReadOnly("SELECT 1;") || IsReadOnly("delete from t") || IsReadOnly("select 1; drop table t") {
		t.Error("IsReadOnly misclassified")
	}
}

type recNotifier struct{ msgs []string }

func (r *recNotifier) Markdown(_ context.Context, title, text string) error {
	r.msgs = append(r.msgs, title+"\n"+text)
	return nil
}

func TestRunSQLApprovalToExecution(t *testing.T) {
	f := &fake{}
	c, _ := setup(t, f, okCreds)
	tr := NewTracker(true, time.Minute)
	tr.Poll = 10 * time.Millisecond
	n := &recNotifier{}

	sub, err := tr.Submit(context.Background(), c, n, SubmitRequest{Instance: "prod", Database: "d", SQL: "UPDATE t SET a=1", Title: "t", Group: "dba", Backup: true}, 0)
	if err != nil || sub.WorkflowID != 42 || len(n.msgs) != 1 || !strings.Contains(n.msgs[0], "/detail/42/") {
		t.Fatalf("submit: %+v %v %v", sub, err, n.msgs)
	}
	if f.submitted.Get("group_name") != "dba" || f.submitted.Get("is_backup") != "True" {
		t.Errorf("submitted form: %v", f.submitted)
	}

	// Not approved yet: wait times out as pending and does NOT execute.
	out, err := tr.Wait(context.Background(), c, 42, 50*time.Millisecond, nil)
	if err != nil || out.Status != "pending" || out.Phase != PhaseAwaitingApproval || f.executed != 0 {
		t.Fatalf("pending: %+v %v executed=%d", out, err, f.executed)
	}
	// A human approves; concurrent waits must execute exactly once.
	f.mu.Lock()
	f.status = "workflow_review_pass"
	f.mu.Unlock()
	var wg sync.WaitGroup
	outs := make([]*Outcome, 3)
	for i := range outs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], _ = tr.Wait(context.Background(), c, 42, 2*time.Second, nil)
		}()
	}
	wg.Wait()
	if f.executed != 1 {
		t.Errorf("executed %d times", f.executed)
	}
	for _, o := range outs {
		if o == nil || o.Status != "done" || len(o.Results) != 1 || o.Results[0].AffectedRows != 3 {
			t.Errorf("outcome %+v", o)
		}
	}
}

func TestSubmitGuards(t *testing.T) {
	c, _ := setup(t, &fake{}, okCreds)
	noDDL := NewTracker(false, time.Minute)
	if _, err := noDDL.Submit(context.Background(), c, nil, SubmitRequest{SQL: "ALTER TABLE t ADD c int", Title: "t"}, 0); !errors.Is(err, ErrDDLDisabled) {
		t.Errorf("ddl: %v", err)
	}
	withDDL := NewTracker(true, time.Minute)
	_, err := withDDL.Submit(context.Background(), c, nil, SubmitRequest{SQL: "BADSQL", Title: "t"}, 0)
	var cf *CheckFailed
	if !errors.As(err, &cf) || !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("check: %v", err)
	}
}

func TestApprovalTimeoutCancels(t *testing.T) {
	f := &fake{}
	c, _ := setup(t, f, okCreds)
	tr := NewTracker(true, time.Minute)
	tr.Poll = 5 * time.Millisecond
	if _, err := tr.Submit(context.Background(), c, nil, SubmitRequest{SQL: "UPDATE t SET a=1", Title: "t"}, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	out, err := tr.Wait(context.Background(), c, 42, 2*time.Second, nil)
	if err != nil || out.Status != "aborted" || !f.cancelled || f.executed != 0 {
		t.Fatalf("%+v %v cancelled=%v", out, err, f.cancelled)
	}
	_ = fmt.Sprint
}
