package rocketmq

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/sitetest"
)

// fakeDashboard speaks the way the Dashboard 2.0.x of the production site does (checked against the real one and against the
// 2.0.1 image): the account goes in the query string of POST /login/login.do, a wrong password is HTTP 200 with status -1, a
// good login sets JSESSIONID and answers loginUserRole, and a read without a session is a 302 to the login page.
type fakeDashboard struct {
	*httptest.Server
	mu       sync.Mutex
	logins   []string // the query strings login.do was called with
	sessions map[string]bool
	status   int // when not zero, check.query answers with it
}

func newDashboard(t *testing.T) *fakeDashboard {
	t.Helper()
	f := &fakeDashboard{sessions: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/login.do", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.logins = append(f.logins, r.URL.RawQuery)
		f.mu.Unlock()
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		q := r.URL.Query()
		if q.Get("username") != "viewer" || q.Get("password") != "viewer-pass-1" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":-1,"data":null,"errMsg":"Bad username or password!"}`))
			return
		}
		f.mu.Lock()
		f.sessions["SESSION-ID-VALUE-1234567890"] = true
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "SESSION-ID-VALUE-1234567890", Path: "/", HttpOnly: true})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":0,"data":{"loginUserName":"viewer","loginUserRole":0,"contextPath":"/"},"errMsg":null}`))
	})
	mux.HandleFunc("/login/check.query", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		forced := f.status
		f.mu.Unlock()
		if forced != 0 {
			http.Error(w, "x", forced)
			return
		}
		c, err := r.Cookie("JSESSIONID")
		f.mu.Lock()
		ok := err == nil && f.sessions[c.Value]
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if ok {
			w.Write([]byte(`{"status":0,"data":{"loginRequired":true,"logined":true},"errMsg":null}`))
			return
		}
		w.Write([]byte(`{"status":0,"data":{"loginRequired":true,"logined":false},"errMsg":null}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/#/login", http.StatusFound) })
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeDashboard) setStatus(code int) { f.mu.Lock(); f.status = code; f.mu.Unlock() }
func (f *fakeDashboard) loginCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.logins...)
}

func answers(user, pass string) *sitetest.Asker {
	return &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": user, "password": pass}}}
}

func TestLoginSendsTheAccountTheWayThisDashboardWantsItAndKeepsTheCookie(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	a := answers("viewer", "viewer-pass-1")
	s, err := (&driver{}).Login(context.Background(), base, a, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Asked) != 1 || a.Asked[0] != "login" {
		t.Errorf("asked %v", a.Asked)
	}
	if len(s.Cookies) != 1 || s.Cookies[0].Name != "JSESSIONID" || s.Cookies[0].Value != "SESSION-ID-VALUE-1234567890" {
		t.Errorf("the session is the cookie the Dashboard set: %+v", s.Cookies)
	}
	if len(s.Headers) != 0 {
		t.Errorf("%v", s.Headers)
	}
	if calls := f.loginCalls(); len(calls) != 1 {
		t.Errorf("exactly one attempt per login, since a wrong one can lock an account: %v", calls)
	}
}

func TestTheAccountIsEscapedInTheQueryString(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	(&driver{}).Login(context.Background(), base, answers("a&b=c", "p w&d=%26#?"), http.DefaultClient)
	calls := f.loginCalls()
	if len(calls) != 1 {
		t.Fatalf("%v", calls)
	}
	q, err := url.ParseQuery(calls[0])
	if err != nil || q.Get("username") != "a&b=c" || q.Get("password") != "p w&d=%26#?" || len(q) != 2 {
		t.Errorf("each value must arrive whole and be the only parameters: %v %v", q, err)
	}
}

func TestAWrongPasswordIsBadCredentialsEvenThoughTheStatusIs200(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	_, err := (&driver{}).Login(context.Background(), base, answers("viewer", "WRONG-PASSWORD-1"), http.DefaultClient)
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "WRONG-PASSWORD-1") {
		t.Errorf("the error carries the password: %v", err)
	}
}

func TestTheDashboardBeingDownIsNotAWrongPassword(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	f.Close()
	if _, err := (&driver{}).Login(context.Background(), base, answers("viewer", "viewer-pass-1"), http.DefaultClient); !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("%v", err)
	}
}

func TestAnAnswerThatIsNotTheDashboardIsRefusedWithoutEchoingIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>SECRET-PAGE-TEXT login with your SSO</html>"))
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	_, err := (&driver{}).Login(context.Background(), base, answers("viewer", "viewer-pass-1"), http.DefaultClient)
	if err == nil || errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("a page that is not the Dashboard is not 'bad credentials': %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-PAGE-TEXT") {
		t.Errorf("%v", err)
	}
}

func TestALoginThatSetsNoCookieIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":0,"data":{"loginUserName":"viewer","loginUserRole":0},"errMsg":null}`))
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	if _, err := (&driver{}).Login(context.Background(), base, answers("viewer", "viewer-pass-1"), http.DefaultClient); err == nil {
		t.Error("a login that gives nothing to use is not a login")
	}
}

func TestAnEmptyAccountIsNotSent(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	for _, c := range [][2]string{{"", "x"}, {"  ", "x"}, {"viewer", ""}} {
		if _, err := (&driver{}).Login(context.Background(), base, answers(c[0], c[1]), http.DefaultClient); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%q: %v", c, err)
		}
	}
	if n := len(f.loginCalls()); n != 0 {
		t.Errorf("nothing is sent for an account that is not one: %d calls", n)
	}
}

func TestProbeSaysWhetherTheDashboardStillKnowsTheSession(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	s, err := (&driver{}).Login(context.Background(), base, answers("viewer", "viewer-pass-1"), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&driver{}).Probe(context.Background(), base, s, http.DefaultClient); err != nil {
		t.Errorf("a live session: %v", err)
	}
	// the Dashboard forgets it (a restart): the same cookie now says logined:false, which is a refusal, not a transport problem
	f.mu.Lock()
	f.sessions = map[string]bool{}
	f.mu.Unlock()
	err = (&driver{}).Probe(context.Background(), base, s, http.DefaultClient)
	if err == nil || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("logined:false is the site saying no: %v", err)
	}
}

func TestProbeKeepsTheSessionWhenTheGatewayIsInTheWay(t *testing.T) {
	f := newDashboard(t)
	base, _ := url.Parse(f.URL)
	s, _ := (&driver{}).Login(context.Background(), base, answers("viewer", "viewer-pass-1"), http.DefaultClient)
	for _, code := range []int{502, 503, 504, 429} {
		f.setStatus(code)
		if err := (&driver{}).Probe(context.Background(), base, s, http.DefaultClient); !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("HTTP %d: %v", code, err)
		}
	}
	for _, code := range []int{401, 403, 500} {
		f.setStatus(code)
		if err := (&driver{}).Probe(context.Background(), base, s, http.DefaultClient); err == nil || errors.Is(err, site.ErrUnreachable) {
			t.Errorf("HTTP %d: %v", code, err)
		}
	}
	f.setStatus(0)
	f.Close()
	if err := (&driver{}).Probe(context.Background(), base, s, http.DefaultClient); !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("nothing listens: %v", err)
	}
}

func TestTheProbeDoesNotSendThePasswordAndCannotBeTrickedIntoAnotherHost(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		w.Write([]byte(`{"status":0,"data":{"loginRequired":true,"logined":true},"errMsg":null}`))
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	s := &site.Session{Cookies: []*http.Cookie{{Name: "JSESSIONID", Value: "SESSION-ID-VALUE-1234567890", Path: "/"}}}
	if err := (&driver{}).Probe(context.Background(), base, s, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "GET /login/check.query" {
		t.Errorf("the probe is one GET of check.query: %v", seen)
	}
}

func TestTheDriverIsRecognisedByItsHostNameOnly(t *testing.T) {
	d := &driver{}
	for host, want := range map[string]bool{"dev-nt-mq.91aql.com": true, "rocketmq.corp.example": true, "mq.example.com": true, "rmq-console.example": true, "gitlab.example": false, "kibana.example": false, "example.com": false} {
		u, _ := url.Parse("https://" + host)
		if d.Match(u) != want {
			t.Errorf("%s: %v", host, !want)
		}
	}
	if d.Name() != "rocketmq" || !d.NeedsLogin() {
		t.Error("name and login")
	}
}

// ---- the request policy ----

// The reads that make the Dashboard worth having: they must pass.
var reads = []string{
	"/cluster/list.query", "/cluster/brokerConfig.query", "/topic/list.query", "/topic/stats.query", "/topic/route.query",
	"/topic/examineTopicConfig.query", "/topic/queryConsumerByTopic.query", "/topic/queryTopicConsumerInfo.query",
	"/consumer/groupList.query", "/consumer/queryTopicByConsumer.query", "/consumer/consumerConnection.query",
	"/consumer/consumerRunningInfo.query", "/consumer/examineSubscriptionGroupConfig.query", "/consumer/group.query",
	"/producer/producerConnection.query", "/dashboard/broker.query", "/dashboard/topic.query", "/dashboard/topicCurrent.query",
	"/ops/homePage.query", "/ops/rocketMqStatus.query", "/namesvr/nsaddr.query", "/login/check.query",
}

// Every write the Dashboard has (the ".do" paths of 2.0.1 and 2.1, and the front end's own list), and the reads that hand out
// the bodies of messages. None may pass, whatever the method.
var writes = []string{
	"/topic/createOrUpdate.do", "/topic/sendTopicMessage.do", "/topic/deleteTopic.do", "/topic/deleteTopicByBroker.do",
	"/consumer/resetOffset.do", "/consumer/skipAccumulate.do", "/consumer/deleteSubGroup.do", "/consumer/createOrUpdate.do",
	"/message/consumeMessageDirectly.do", "/monitor/createOrUpdateConsumerMonitor.do", "/monitor/deleteConsumerMonitor.do",
	"/ops/updateNameSvrAddr.do", "/ops/addNameSvrAddr.do", "/ops/updateIsVIPChannel.do", "/ops/updateUseTLS.do",
	"/acl/updateUser.do", "/acl/updateAcl.do", "/login/login.do", "/login/logout.do",
}

var bodies = []string{
	"/message/viewMessage.query", "/message/queryMessageByTopic.query", "/message/queryMessageByTopicAndKey.query",
	"/message/queryMessagePageByTopic.query", "/message/viewMessageByBrokerAndOffset.query",
	"/messageTrace/viewMessage.query", "/messageTrace/viewMessageTraceGraph.query", "/dlqMessage/queryDlqMessageByConsumerGroup.query",
}

func TestTheReadsPass(t *testing.T) {
	d := &driver{}
	for _, p := range reads {
		if err := d.CheckRequest("GET", p); err != nil {
			t.Errorf("%s must pass: %v", p, err)
		}
	}
}

func TestEveryWriteTheDashboardHasIsRefusedWhateverTheMethod(t *testing.T) {
	d := &driver{}
	for _, p := range writes {
		for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
			if err := d.CheckRequest(m, p); !errors.Is(err, site.ErrRequestRefused) {
				t.Errorf("%s %s must be refused: %v", m, p, err)
			}
		}
	}
	for _, p := range reads {
		for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
			if err := d.CheckRequest(m, p); !errors.Is(err, site.ErrRequestRefused) {
				t.Errorf("%s %s: a read is read with GET only: %v", m, p, err)
			}
		}
	}
}

func TestTheBodiesOfMessagesAreRefusedUntilTheOwnerOpensThem(t *testing.T) {
	d := &driver{}
	for _, p := range bodies {
		if err := d.CheckRequest("GET", p); !errors.Is(err, site.ErrRequestRefused) {
			t.Errorf("%s: closed by default: %v", p, err)
		}
	}
	for _, v := range []string{"", "no", "No", "false", "0", "off", "maybe", " ", "yess"} {
		d.Configure(map[string]string{"allow_message_body": v})
		if err := d.CheckRequest("GET", "/message/viewMessage.query"); err == nil {
			t.Errorf("allow_message_body %q must not open the bodies: only yes does", v)
		}
	}
	for _, v := range []string{"yes", "YES", " yes "} {
		d.Configure(map[string]string{"allow_message_body": v})
		for _, p := range bodies {
			if err := d.CheckRequest("GET", p); err != nil {
				t.Errorf("allow_message_body %q: %s must pass: %v", v, p, err)
			}
		}
	}
	// opening the bodies opens only reads: a write stays a write
	for _, p := range writes {
		if err := d.CheckRequest("GET", p); err == nil {
			t.Errorf("%s must stay refused with the bodies open", p)
		}
	}
	if err := d.CheckRequest("POST", "/message/viewMessage.query"); err == nil {
		t.Error("and a POST stays a POST")
	}
}

func TestEveryWayOfWritingAPathThatReachesAWriteIsRefused(t *testing.T) {
	d := &driver{}
	for name, p := range map[string]string{
		"dot segments to a write":     "/topic/list.query/../deleteTopic.do",
		"dot segments into a message": "/topic/../message/viewMessage.query",
		"encoded dots":                "/topic/%2e%2e/message/viewMessage.query",
		"encoded letter in a prefix":  "/%6dessage/viewMessage.query",
		"encoded slash":               "/topic%2flist.query",
		"doubled slash":               "//message/viewMessage.query",
		"backslash":                   `/topic\deleteTopic.do`,
		"matrix parameter":            "/topic/deleteTopic.do;x=.query",
		"query hiding the suffix":     "/topic/deleteTopic.do?a=.query",
		"fragment hiding the suffix":  "/topic/deleteTopic.do#.query",
		"upper-case prefix":           "/MESSAGE/viewMessage.query",
		"trailing dot":                "/topic/list.query.",
		"trailing space":              "/topic/list.query ",
		"newline":                     "/topic/list.query\n/topic/deleteTopic.do",
		"a second extension":          "/topic/list.query.do",
		"no leading slash":            "topic/list.query",
		"only the suffix":             "/.query",
	} {
		if err := d.CheckRequest("GET", p); err == nil {
			t.Errorf("%s: %q must be refused", name, p)
		}
	}
}

func TestADriverWithoutOptionsIsClosed(t *testing.T) {
	d := &driver{} // never configured
	if err := d.CheckRequest("GET", "/message/viewMessage.query"); err == nil {
		t.Error("an unconfigured driver keeps the bodies closed")
	}
	if len(d.Options()) != 1 || d.Options()[0].Key != "allow_message_body" || d.Options()[0].Default != "no" {
		t.Errorf("%+v", d.Options())
	}
	if err := d.Options()[0].Validate("maybe"); err == nil {
		t.Error("only no or yes")
	}
}

func TestTheDriverIsARequestPolicy(t *testing.T) {
	var d site.Driver = &driver{}
	if _, ok := d.(site.RequestPolicy); !ok {
		t.Fatal("the request tool finds the policy through this interface")
	}
	if err := site.CheckRequest(d, "POST", "/topic/deleteTopic.do"); !errors.Is(err, site.ErrRequestRefused) {
		t.Errorf("%v", err)
	}
}

// Go quotes the whole URL in a transport error, and this Dashboard takes the password in the URL.
func TestATransportErrorDuringLoginDoesNotQuoteThePassword(t *testing.T) {
	const pass = "PW&in the/URL=77%"
	gone := httptest.NewServer(http.NotFoundHandler())
	base, err := url.Parse(gone.URL)
	if err != nil {
		t.Fatal(err)
	}
	gone.Close()

	_, err = (&driver{}).Login(context.Background(), base, answers("viewer", pass), http.DefaultClient)
	if err == nil {
		t.Fatal("a closed port was reported as a login")
	}
	if !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a closed port must be reported as unreachable, got %v", err)
	}
	for _, form := range []string{pass, url.QueryEscape(pass)} {
		if strings.Contains(err.Error(), form) {
			t.Errorf("the error quotes the password (%q): %v", form, err)
		}
	}
}
