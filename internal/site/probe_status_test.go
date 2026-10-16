package site_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LeafAI/securl/internal/site"
)

// What a status means to a session probe. The three groups were checked against the real sites with a session that is not
// valid: GitLab, Kibana, Nightingale and KubeSphere answer 401, and Archery 1.x answers 302 to its login page. None of them
// uses a 5xx for that, so a 5xx never hides a session that has really ended.
//
//   - could not tell (the session is kept): the gateway in front of the site could not reach it (502), it is not available
//     right now (503), it did not answer in time (504), or it is asking us to slow down (429);
//   - the site said no (the session is dropped): anything else that is not a success, including 500, which some sites
//     answer for a session that has ended and which is not known to be a fault of the site.
var (
	couldNotTell = []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests}
	toldNo       = []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusFound, http.StatusInternalServerError, http.StatusNotFound, http.StatusBadRequest, http.StatusNotImplemented}
)

func TestTheStatusesThatMeanCouldNotTell(t *testing.T) {
	for _, code := range couldNotTell {
		if !site.TemporaryStatus(code) {
			t.Errorf("%d must be 'could not tell'", code)
		}
	}
	for _, code := range append(toldNo, 200, 204, 301, 400, 418, 505, 599) {
		if site.TemporaryStatus(code) {
			t.Errorf("%d must not be 'could not tell'", code)
		}
	}
}

func TestStatusProbeErrorKeepsTheStatusAndIsMarkedUnreachableOnlyForTheTemporaryOnes(t *testing.T) {
	for _, code := range couldNotTell {
		err := site.ProbeStatus("gitlab", code)
		if !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("%d: %v", code, err)
		}
	}
	for _, code := range toldNo {
		err := site.ProbeStatus("gitlab", code)
		if err == nil || errors.Is(err, site.ErrUnreachable) {
			t.Errorf("%d: %v", code, err)
		}
	}
	if site.ProbeStatus("gitlab", 200) != nil {
		t.Error("200 is a valid session")
	}
}

// For every driver that probes by status, run the probe against a real HTTP server that answers each code.
func TestEveryProbeKeepsASessionWhenTheGatewayAnswersWithATemporaryStatus(t *testing.T) {
	sess := &site.Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: "SESSION-COOKIE-VALUE-1234", Path: "/"}},
		Headers: map[string]string{"Authorization": "Bearer TOKEN-VALUE-1234567890"},
		Tokens:  map[string]string{"api": "rest"},
	}
	for _, name := range []string{"gitlab", "kibana", "nightingale", "kubesphere", "archery"} {
		d, err := site.Resolve(name, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		probeWith := func(code int) error {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", code) }))
			defer srv.Close()
			base, _ := url.Parse(srv.URL)
			return d.Probe(context.Background(), base, sess, http.DefaultClient)
		}
		for _, code := range couldNotTell {
			if err := probeWith(code); !errors.Is(err, site.ErrUnreachable) {
				t.Errorf("%s: HTTP %d is 'could not tell', got %v", name, code, err)
			}
		}
		for _, code := range []int{401, 403, 500} {
			if err := probeWith(code); err == nil || errors.Is(err, site.ErrUnreachable) {
				t.Errorf("%s: HTTP %d means the site said no, got %v", name, code, err)
			}
		}
	}
}

func TestJenkinsKeepsASessionOnATemporaryStatusAndStillReadsTheBody(t *testing.T) {
	d, _ := site.Resolve("jenkins", nil)
	sess := &site.Session{Cookies: []*http.Cookie{{Name: "JSESSIONID", Value: "SESSION-COOKIE-VALUE-1234", Path: "/"}}}
	run := func(code int, body string) error {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			fmt.Fprint(w, body)
		}))
		defer srv.Close()
		base, _ := url.Parse(srv.URL)
		return d.Probe(context.Background(), base, sess, http.DefaultClient)
	}
	for _, code := range couldNotTell {
		if err := run(code, "<html>Bad Gateway</html>"); !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("HTTP %d: %v", code, err)
		}
	}
	if err := run(200, `{"_class":"hudson.security.WhoAmI","anonymous":true,"authenticated":true,"name":"anonymous"}`); err == nil || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("the real answer for a session that is not valid (200, anonymous): %v", err)
	}
	if err := run(200, `{"_class":"hudson.model.User","authenticated":true,"name":"alice","anonymous":false}`); err != nil {
		t.Errorf("a valid session: %v", err)
	}
}
