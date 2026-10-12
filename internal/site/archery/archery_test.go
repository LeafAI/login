package archery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/archery/archerytest"
)

// setup serves the fake over TLS, as Archery is in production: its cookies are Secure, which a client sends back only over
// https. srv.Client() trusts the test server's certificate.
func setup(t *testing.T, f *archerytest.Fake, answers map[string]site.Credentials) (*Client, *sitetestAsker) {
	t.Helper()
	srv := httptest.NewTLSServer(f.Handler())
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	a := &sitetestAsker{Answers: answers}
	s, err := driver{}.Login(context.Background(), base, a, srv.Client())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return &Client{Base: base, Sess: s, HC: srv.Client()}, a
}

type sitetestAsker struct {
	Answers map[string]site.Credentials
	Asked   []string
}

func (a *sitetestAsker) Ask(_ context.Context, mode string, _ []site.Field) (site.Credentials, error) {
	a.Asked = append(a.Asked, mode)
	c, ok := a.Answers[mode]
	if !ok {
		return nil, errors.New("unexpected round " + mode)
	}
	return c, nil
}

// bothGenerations runs a test against a fake REST-generation and a fake 1.x-generation Archery.
func bothGenerations(t *testing.T, fn func(t *testing.T, legacy bool, newFake func() *archerytest.Fake)) {
	for _, legacy := range []bool{false, true} {
		legacy := legacy
		name := map[bool]string{false: "rest", true: "v1.12"}[legacy]
		t.Run(name, func(t *testing.T) {
			fn(t, legacy, func() *archerytest.Fake { return &archerytest.Fake{Legacy: legacy} })
		})
	}
}

var okCreds = map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}, "totp": {"code": "123456"}}

func TestLoginWithoutAndWith2FA(t *testing.T) {
	bothGenerations(t, func(t *testing.T, legacy bool, newFake func() *archerytest.Fake) {
		c, a := setup(t, newFake(), okCreds)
		if strings.Join(a.Asked, ",") != "login" {
			t.Errorf("asked %v", a.Asked)
		}
		want := map[bool]string{false: GenREST, true: GenLegacy}[legacy]
		if c.Sess.Tokens["api"] != want {
			t.Errorf("generation = %q, want %q", c.Sess.Tokens["api"], want)
		}
		if c.Sess.Headers["X-CSRFToken"] != "CSRF2" {
			t.Errorf("csrf token after login not refreshed: %q", c.Sess.Headers["X-CSRFToken"])
		}
		if err := (driver{}).Probe(context.Background(), c.Base, c.Sess, c.HC); err != nil {
			t.Errorf("probe: %v", err)
		}
		stale := &site.Session{Tokens: c.Sess.Tokens, Cookies: nil}
		if err := (driver{}).Probe(context.Background(), c.Base, stale, c.HC); err == nil {
			t.Error("probe accepted a session without cookies")
		}

		f2 := newFake()
		f2.TwoFA = true
		c2, a2 := setup(t, f2, okCreds)
		if strings.Join(a2.Asked, ",") != "login,totp" || !f2.Verified {
			t.Errorf("2fa asked %v verified=%v", a2.Asked, f2.Verified)
		}
		if _, err := c2.Instances(context.Background()); err != nil {
			t.Errorf("session after 2fa unusable: %v", err)
		}
	})
}

func TestLoginFailures(t *testing.T) {
	srv := httptest.NewTLSServer((&archerytest.Fake{TwoFA: true, Legacy: true}).Handler())
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	bad := &sitetestAsker{Answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := (driver{}).Login(context.Background(), base, bad, srv.Client()); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad password: %v", err)
	}
	wrongCode := &sitetestAsker{Answers: map[string]site.Credentials{"login": okCreds["login"], "totp": {"code": "000000"}}}
	if _, err := (driver{}).Login(context.Background(), base, wrongCode, srv.Client()); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad otp: %v", err)
	}
}

func TestQueryInstancesDatabases(t *testing.T) {
	bothGenerations(t, func(t *testing.T, _ bool, newFake func() *archerytest.Fake) {
		c, _ := setup(t, newFake(), okCreds)
		ctx := context.Background()
		q, err := c.Query(ctx, QueryRequest{Instance: "prod", Database: "d", SQL: "select 1", Limit: 100})
		if err != nil || q.RowCount != 2 || q.Columns[1] != "name" || q.CostMS != 12 {
			t.Fatalf("%+v %v", q, err)
		}
		ins, err := c.Instances(ctx)
		if err != nil || len(ins) != 1 || ins[0].Name != "prod" || ins[0].ID != 7 {
			t.Fatalf("%+v %v", ins, err)
		}
		dbs, err := c.Databases(ctx, "prod")
		if err != nil || len(dbs) != 2 {
			t.Fatalf("%v %v", dbs, err)
		}
	})
	if !IsReadOnly("SELECT 1;") || IsReadOnly("delete from t") || IsReadOnly("select 1; drop table t") {
		t.Error("IsReadOnly misclassified")
	}
}

func TestExpiredSessionIsReported(t *testing.T) {
	bothGenerations(t, func(t *testing.T, _ bool, newFake func() *archerytest.Fake) {
		c, _ := setup(t, newFake(), okCreds)
		c.Sess.Cookies = nil // logged out
		if _, err := c.Instances(context.Background()); !errors.Is(err, ErrSessionInvalid) {
			t.Errorf("want ErrSessionInvalid, got %v", err)
		}
	})
}

type recNotifier struct{ msgs []string }

func (r *recNotifier) Markdown(_ context.Context, title, text string) error {
	r.msgs = append(r.msgs, title+"\n"+text)
	return nil
}

func submitReq(sql string) SubmitRequest {
	return SubmitRequest{Instance: "prod", Database: "d", SQL: sql, Title: "t", Group: "dba", Backup: true}
}

const wid = archerytest.WorkflowID

func TestRunSQLApprovalToExecution(t *testing.T) {
	bothGenerations(t, func(t *testing.T, legacy bool, newFake func() *archerytest.Fake) {
		f := newFake()
		c, _ := setup(t, f, okCreds)
		tr := NewTracker(true, time.Minute)
		tr.Poll = 10 * time.Millisecond
		n := &recNotifier{}

		sub, err := tr.Submit(context.Background(), c, n, submitReq("UPDATE t SET a=1"), 0)
		if err != nil || sub.WorkflowID != wid || len(n.msgs) != 1 || !strings.Contains(n.msgs[0], "/detail/9/") {
			t.Fatalf("submit: %+v %v %v", sub, err, n.msgs)
		}
		if legacy == (sub.AuditID != 0) {
			t.Errorf("audit id %d reported for legacy=%v", sub.AuditID, legacy)
		}
		wf := f.Submitted["workflow"].(map[string]any)
		if wf["group_id"] != float64(3) || wf["instance"] != float64(7) || wf["is_backup"] != true || wf["workflow_name"] != "t" {
			t.Errorf("submitted workflow: %v", wf)
		}

		// Not approved yet: wait times out as pending and does NOT execute.
		out, err := tr.Wait(context.Background(), c, wid, 50*time.Millisecond, nil)
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
				outs[i], _ = tr.Wait(context.Background(), c, wid, 2*time.Second, nil)
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
	})
}

func TestSubmitGuards(t *testing.T) {
	bothGenerations(t, func(t *testing.T, _ bool, newFake func() *archerytest.Fake) {
		c, _ := setup(t, newFake(), okCreds)
		ctx := context.Background()
		if _, err := NewTracker(false, time.Minute).Submit(ctx, c, nil, submitReq("ALTER TABLE t ADD c int"), 0); !errors.Is(err, ErrDDLDisabled) {
			t.Errorf("ddl: %v", err)
		}
		tr := NewTracker(true, time.Minute)
		var cf *CheckFailed
		if _, err := tr.Submit(ctx, c, nil, submitReq("BADSQL"), 0); !errors.As(err, &cf) || !strings.Contains(err.Error(), "syntax error") {
			t.Errorf("check: %v", err)
		}
		r := submitReq("UPDATE t SET a=1")
		r.Group = "nope"
		if _, err := tr.Submit(ctx, c, nil, r, 0); err == nil || !strings.Contains(err.Error(), "available: dba, dev") {
			t.Errorf("unknown group: %v", err)
		}
		r = submitReq("UPDATE t SET a=1")
		r.Instance = "ghost"
		if _, err := tr.Submit(ctx, c, nil, r, 0); err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Errorf("unknown instance: %v", err)
		}
	})
}

func TestApprovalTimeoutCancels(t *testing.T) {
	bothGenerations(t, func(t *testing.T, _ bool, newFake func() *archerytest.Fake) {
		f := newFake()
		c, _ := setup(t, f, okCreds)
		tr := NewTracker(true, time.Minute)
		tr.Poll = 5 * time.Millisecond
		if _, err := tr.Submit(context.Background(), c, nil, submitReq("UPDATE t SET a=1"), 20*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		out, err := tr.Wait(context.Background(), c, wid, 2*time.Second, nil)
		if err != nil || out.Status != "aborted" || !f.Cancelled || f.Executed != 0 || f.CancelRemark == "" {
			t.Fatalf("%+v %v cancelled=%v remark=%q", out, err, f.Cancelled, f.CancelRemark)
		}
	})
}

func TestRejectedVersusCancelled(t *testing.T) {
	bothGenerations(t, func(t *testing.T, _ bool, newFake func() *archerytest.Fake) {
		for _, tc := range []struct{ op, info, want string }{
			{"审核不通过", "touches the orders table", "rejected"},
			{"审核取消", "changed my mind", "aborted"},
		} {
			f := newFake()
			f.Status, f.LogOp, f.LogInfo = "workflow_abort", tc.op, tc.info
			c, _ := setup(t, f, okCreds)
			tr := NewTracker(true, time.Minute)
			tr.Poll = 5 * time.Millisecond
			out, err := tr.Wait(context.Background(), c, wid, time.Second, nil)
			if err != nil || out.Status != tc.want || out.Reason != tc.info || out.By != "lisi" {
				t.Errorf("%s: %+v %v", tc.op, out, err)
			}
		}
	})
}

func TestUnknownWorkflow(t *testing.T) {
	bothGenerations(t, func(t *testing.T, _ bool, newFake func() *archerytest.Fake) {
		c, _ := setup(t, newFake(), okCreds)
		if _, err := c.Status(context.Background(), 999); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v", err)
		}
	})
}

// Archery 1.x reports failures of /execute/ and /cancel/ as rendered HTML pages, not as errors.
func TestLegacyHTMLErrorPagesAreErrors(t *testing.T) {
	f := &archerytest.Fake{Legacy: true, Status: "workflow_manreviewing"}
	c, _ := setup(t, f, okCreds)
	err := c.Execute(context.Background(), wid) // not approved: the fake renders the "no permission" page
	var ae *APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Msg, "无权执行") {
		t.Errorf("execute error = %v", err)
	}
	if f.Executed != 0 {
		t.Error("executed despite the error page")
	}
}

func TestInspectTellsTheGenerations(t *testing.T) {
	for legacy, want := range map[bool]string{false: "REST", true: "1.x"} {
		srv := httptest.NewTLSServer((&archerytest.Fake{Legacy: legacy}).Handler())
		u, _ := url.Parse(srv.URL)
		out, err := driver{}.Inspect(context.Background(), u, srv.Client())
		srv.Close()
		if err != nil || !strings.Contains(strings.Join(out, " "), want) {
			t.Errorf("legacy=%v: %v %v", legacy, out, err)
		}
	}
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	u, _ := url.Parse(other.URL)
	if _, err := (driver{}).Inspect(context.Background(), u, other.Client()); err == nil {
		t.Error("a non-Archery server was accepted")
	}
}

type failingNotifier struct{}

func (failingNotifier) Markdown(context.Context, string, string) error {
	return fmt.Errorf(`Post "https://oapi.dingtalk.com/robot/send?access_token=TOK123&sign=SIG&timestamp=17": refused`)
}

func TestSubmitNotifyFailureDoesNotLeakWebhookSecrets(t *testing.T) {
	bothGenerations(t, func(t *testing.T, legacy bool, newFake func() *archerytest.Fake) {
		c, _ := setup(t, newFake(), okCreds)
		tr := NewTracker(true, time.Minute)
		sub, err := tr.Submit(context.Background(), c, failingNotifier{}, submitReq("UPDATE t SET a=1"), 0)
		if err != nil || !strings.Contains(sub.Reason, "refused") {
			t.Fatalf("submit: %+v %v", sub, err)
		}
		for _, bad := range []string{"TOK123", "sign=", "access_token", "timestamp="} {
			if strings.Contains(sub.Reason, bad) {
				t.Errorf("reason leaks %q: %s", bad, sub.Reason)
			}
		}
	})
}

func approvalMessage(t *testing.T, sql string) string {
	t.Helper()
	var msg string
	bothGenerations(t, func(t *testing.T, legacy bool, newFake func() *archerytest.Fake) {
		c, _ := setup(t, newFake(), okCreds)
		n := &recNotifier{}
		if _, err := NewTracker(true, time.Minute).Submit(context.Background(), c, n, submitReq(sql), 0); err != nil || len(n.msgs) != 1 {
			t.Fatalf("submit: %v %v", err, n.msgs)
		}
		msg = n.msgs[0]
	})
	return msg
}

func TestApprovalMessageSaysWhenTheSQLWasCut(t *testing.T) {
	long := "UPDATE t SET a=1 WHERE id IN (" + strings.Repeat("1,", 400) + "1)"
	msg := approvalMessage(t, long)
	if !strings.Contains(msg, "truncated") || !strings.Contains(msg, fmt.Sprintf("%d characters", len(long))) {
		t.Errorf("a cut SQL must be flagged with its full length:\n%s", msg)
	}
	if !strings.Contains(msg, "sha256") {
		t.Errorf("the approver needs a fingerprint to match the statement in Archery:\n%s", msg)
	}
	if !strings.Contains(msg, "Archery") {
		t.Errorf("the message should point to the full text in Archery:\n%s", msg)
	}
}

func TestApprovalMessageLeavesShortSQLAlone(t *testing.T) {
	msg := approvalMessage(t, "UPDATE t SET a=1")
	if strings.Contains(msg, "truncated") {
		t.Errorf("a short SQL is shown whole and must not be flagged:\n%s", msg)
	}
	if !strings.Contains(msg, "sha256") {
		t.Errorf("the fingerprint is useful for any SQL:\n%s", msg)
	}
}

func TestApprovalMessageCountsRunesNotBytes(t *testing.T) {
	sql := "UPDATE t SET a='" + strings.Repeat("数", 300) + "'"
	msg := approvalMessage(t, sql)
	if strings.Contains(msg, "truncated") {
		t.Errorf("%d runes fit in the limit; flagging by byte count is wrong:\n%s", len([]rune(sql)), msg)
	}
}

func sqlOfRunes(n int) string {
	const prefix = "UPDATE t SET a='"
	return prefix + strings.Repeat("x", n-len([]rune(prefix))-1) + "'"
}

func TestApprovalMessageTruncationBoundary(t *testing.T) {
	if got := len([]rune(sqlOfRunes(500))); got != 500 {
		t.Fatalf("helper is wrong: %d", got)
	}
	if msg := approvalMessage(t, sqlOfRunes(500)); strings.Contains(msg, "truncated") {
		t.Errorf("exactly 500 characters are shown whole and must not be flagged:\n%s", msg)
	}
	msg := approvalMessage(t, sqlOfRunes(501))
	if !strings.Contains(msg, "truncated") || !strings.Contains(msg, "501 characters") || !strings.Contains(msg, "first 500 ") {
		t.Errorf("501 characters must be flagged with the real numbers:\n%s", msg)
	}
}

func TestApprovalMessageShowsExactlyTheAnnouncedPreview(t *testing.T) {
	sql := sqlOfRunes(900)
	msg := approvalMessage(t, sql)
	block := msg[strings.Index(msg, "```sql\n")+len("```sql\n"):]
	block = block[:strings.Index(block, "\n```")]
	shown := strings.TrimSuffix(block, "...")
	if got := len([]rune(shown)); got != 500 {
		t.Errorf("the message says the first 500 characters are shown, but %d are", got)
	}
}
