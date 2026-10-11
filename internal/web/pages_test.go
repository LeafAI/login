package web_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/api"
	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/web"
)

func buildSite(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out := filepath.Join(t.TempDir(), "site")
	if b, err := exec.Command("bash", "../../scripts/build-pages.sh", out).CombinedOutput(); err != nil {
		t.Skipf("build-pages.sh failed (missing sha256sum?): %v\n%s", err, b)
	}
	return out
}

// The published site is byte-for-byte what the binary embeds, with matching checksums.
func TestPagesSiteMatchesTheEmbeddedPage(t *testing.T) {
	site := buildSite(t)
	embedded := t.TempDir()
	if err := web.WriteTo(embedded); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "login.css", "login.js", "openpgp.min.js"} {
		a, err := os.ReadFile(filepath.Join(site, name))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(embedded, name))
		if string(a) != string(b) {
			t.Errorf("%s differs between the published site and the embedded page", name)
		}
	}
	sums, err := os.ReadFile(filepath.Join(site, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range web.Checksums() {
		if !strings.Contains(string(sums), line) {
			t.Errorf("SHA256SUMS lacks %q (what `login page` prints)", line)
		}
	}
	for _, f := range []string{".nojekyll", "robots.txt"} {
		if _, err := os.Stat(filepath.Join(site, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
}

// A hosted page lives on another origin than file://: the whole flow must work cross-origin over HTTP.
func TestBrowserHostedPageWorksCrossOrigin(t *testing.T) {
	browsertest.Require(t)
	site := buildSite(t)
	hosted := httptest.NewServer(http.FileServer(http.Dir(site)))
	defer hosted.Close()

	r := newRig(t, "login", nil)
	sub := r.answer()
	res := browsertest.DriveAt(t, hosted.URL+"/", r.frag, "submit", `{"username":"alice","password":"pw"}`, "")
	s := <-sub
	if s.Action != api.ActionSubmit || s.Fields["username"] != "alice" {
		t.Fatalf("submission %+v (page said %+v)", s, res)
	}
	if len(res.Errors) > 0 {
		t.Errorf("page errors: %v", res.Errors)
	}
}

// A page served over https must refuse an http tunnel address (the browser would block it as mixed content)
// and say why, instead of failing mysteriously later.
func TestBrowserHTTPSPageRefusesHTTPTunnel(t *testing.T) {
	browsertest.Require(t)
	site := buildSite(t)
	hosted := httptest.NewTLSServer(http.FileServer(http.Dir(site)))
	defer hosted.Close()
	r := newRig(t, "login", nil) // its API address is http://127.0.0.1:port/token
	res := browsertest.DriveAt(t, hosted.URL+"/", r.frag, "refuse", "", "")
	if !res.MainHidden || !strings.Contains(res.Msg, "https") {
		t.Errorf("expected a mixed-content refusal mentioning https, got %+v", res)
	}
}
