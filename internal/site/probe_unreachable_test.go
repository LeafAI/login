package site_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	_ "github.com/LeafAI/securl/internal/site/archery"
	_ "github.com/LeafAI/securl/internal/site/gitlab"
	_ "github.com/LeafAI/securl/internal/site/jenkins"
	_ "github.com/LeafAI/securl/internal/site/kibana"
	_ "github.com/LeafAI/securl/internal/site/kubesphere"
	_ "github.com/LeafAI/securl/internal/site/nightingale"
)

// For every driver that checks a session by asking the site: when the site cannot be asked at all (nothing listens), the
// probe says so with site.ErrUnreachable, and when the site is asked and says no (401), it does not. The first keeps the
// person's login; the second ends it. Both are what the cache relies on.
func TestEveryProbeSeparatesCouldNotAskFromWasToldNo(t *testing.T) {
	sess := &site.Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: "SESSION-COOKIE-VALUE-1234", Path: "/"}},
		Headers: map[string]string{"Authorization": "Bearer TOKEN-VALUE-1234567890"},
		Tokens:  map[string]string{"api": "rest"},
	}
	for _, name := range []string{"gitlab", "kibana", "jenkins", "nightingale", "kubesphere", "archery"} {
		d, err := site.Resolve(name, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		down := httptest.NewServer(http.NotFoundHandler())
		base, _ := url.Parse(down.URL)
		down.Close() // nothing listens any more
		err = d.Probe(context.Background(), base, sess, http.DefaultClient)
		if !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("%s: a site that cannot be asked must answer ErrUnreachable, got %v", name, err)
		}

		no := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusUnauthorized) }))
		base2, _ := url.Parse(no.URL)
		err = d.Probe(context.Background(), base2, sess, http.DefaultClient)
		no.Close()
		if err == nil || errors.Is(err, site.ErrUnreachable) {
			t.Errorf("%s: a site that answered 401 has refused the session, which is not 'unreachable': %v", name, err)
		}
	}
}
