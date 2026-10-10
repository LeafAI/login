package archery

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/login/internal/site"
	"github.com/LeafAI/login/internal/site/archery/archerytest"
	"github.com/LeafAI/login/internal/site/sitetest"
)

func setup(t *testing.T, f *archerytest.Fake, answers map[string]site.Credentials) (*Client, *sitetest.Asker) {
	t.Helper()
	srv := httptest.NewServer(f.Handler())
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
	f := &archerytest.Fake{}
	_, a := setup(t, f, okCreds)
	if strings.Join(a.Asked, ",") != "login" {
		t.Errorf("asked %v", a.Asked)
	}
	f2 := &archerytest.Fake{TwoFA: true}
	_, a = setup(t, f2, okCreds)
	if strings.Join(a.Asked, ",") != "login,totp" || !f2.Verified {
		t.Errorf("2fa asked %v verified=%v", a.Asked, f2.Verified)
	}
}

func TestLoginFailures(t *testing.T) {
	srv := httptest.NewServer((&archerytest.Fake{TwoFA: true}).Handler())
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
	c, _ := setup(t, &archerytest.Fake{}, okCreds)
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
	f := &archerytest.Fake{}
	c, _ := setup(t, f, okCreds)
	tr := NewTracker(true, time.Minute)
	tr.Poll = 10 * time.Millisecond
	n := &recNotifier{}

	sub, err := tr.Submit(context.Background(), c, n, SubmitRequest{Instance: "prod", Database: "d", SQL: "UPDATE t SET a=1", Title: "t", Group: "dba", Backup: true}, 0)
	if err != nil || sub.WorkflowID != 42 || len(n.msgs) != 1 || !strings.Contains(n.msgs[0], "/detail/42/") {
		t.Fatalf("submit: %+v %v %v", sub, err, n.msgs)
	}
	if f.Submitted.Get("group_name") != "dba" || f.Submitted.Get("is_backup") != "True" {
		t.Errorf("submitted form: %v", f.Submitted)
	}

	// Not approved yet: wait times out as pending and does NOT execute.
	out, err := tr.Wait(context.Background(), c, 42, 50*time.Millisecond, nil)
	if err != nil || out.Status != "pending" || out.Phase != PhaseAwaitingApproval || f.Executed != 0 {
		t.Fatalf("pending: %+v %v executed=%d", out, err, f.Executed)
	}
	// A human approves; concurrent waits must execute exactly once.
	f.Mu.Lock()
	f.Status = "workflow_review_pass"
	f.Mu.Unlock()
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
	if f.Executed != 1 {
		t.Errorf("executed %d times", f.Executed)
	}
	for _, o := range outs {
		if o == nil || o.Status != "done" || len(o.Results) != 1 || o.Results[0].AffectedRows != 3 {
			t.Errorf("outcome %+v", o)
		}
	}
}

func TestSubmitGuards(t *testing.T) {
	c, _ := setup(t, &archerytest.Fake{}, okCreds)
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
	f := &archerytest.Fake{}
	c, _ := setup(t, f, okCreds)
	tr := NewTracker(true, time.Minute)
	tr.Poll = 5 * time.Millisecond
	if _, err := tr.Submit(context.Background(), c, nil, SubmitRequest{SQL: "UPDATE t SET a=1", Title: "t"}, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	out, err := tr.Wait(context.Background(), c, 42, 2*time.Second, nil)
	if err != nil || out.Status != "aborted" || !f.Cancelled || f.Executed != 0 {
		t.Fatalf("%+v %v cancelled=%v", out, err, f.Cancelled)
	}
	_ = fmt.Sprint
}
