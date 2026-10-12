package archerytest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The fake imitates Archery behind https, as it runs in production: Django sets the session cookie HttpOnly, and marks both
// cookies Secure when the site is served over https (SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE). A fake whose cookies
// have neither lets a client that mishandles them pass its tests, and CodeQL reports it (alerts 3 to 6).

func serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer((&Fake{}).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func cookiesOf(t *testing.T, resp *http.Response) map[string]*http.Cookie {
	t.Helper()
	out := map[string]*http.Cookie{}
	for _, c := range resp.Cookies() {
		out[c.Name] = c
	}
	return out
}

func TestTheLoginPageCsrfCookieIsSecure(t *testing.T) {
	srv := serve(t)
	resp, err := srv.Client().Get(srv.URL + "/login/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c := cookiesOf(t, resp)["csrftoken"]
	if c == nil {
		t.Fatal("no csrftoken cookie from /login/")
	}
	if !c.Secure {
		t.Error("the csrftoken cookie from /login/ must be Secure")
	}
}

func TestTheSessionAndCsrfCookiesAfterLoginAreSecureAndTheSessionIsHttpOnly(t *testing.T) {
	srv := serve(t)
	client := srv.Client()
	resp, err := client.Get(srv.URL + "/login/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/authenticate/", strings.NewReader(url.Values{"username": {"alice"}, "password": {"pw"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRFToken", csrfBefore)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	got := cookiesOf(t, resp)
	session, csrf := got["sessionid"], got["csrftoken"]
	if session == nil || csrf == nil {
		t.Fatalf("login must set both cookies, got %v", got)
	}
	if !session.Secure || !session.HttpOnly {
		t.Errorf("sessionid: Secure=%v HttpOnly=%v, want both true", session.Secure, session.HttpOnly)
	}
	if !csrf.Secure {
		t.Error("csrftoken after login must be Secure")
	}
	// Django leaves the CSRF cookie readable by the page's script, which copies it into X-CSRFToken. Making it HttpOnly
	// would not be what Archery does, and the client would then have a fake that is stricter than the real thing.
	if csrf.HttpOnly {
		t.Error("csrftoken must stay readable: Archery's pages copy it into the X-CSRFToken header")
	}
}
