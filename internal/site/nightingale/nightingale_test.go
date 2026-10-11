package nightingale

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/site"
)

// tiny valid 1x1 PNG
const png1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

// fakeN9e imitates Nightingale's auth endpoints as found in its source.
type fakeN9e struct {
	captcha bool
	rsaKey  *rsa.PrivateKey
	t       *testing.T
}

func (f *fakeN9e) handler() http.Handler {
	out := func(w http.ResponseWriter, dat any, err string) {
		json.NewEncoder(w).Encode(map[string]any{"dat": dat, "err": err})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/n9e/auth/ifshowcaptcha", func(w http.ResponseWriter, r *http.Request) { out(w, map[string]bool{"show": f.captcha}, "") })
	mux.HandleFunc("/api/n9e/auth/captcha", func(w http.ResponseWriter, r *http.Request) {
		out(w, map[string]string{"imgdata": "data:image/png;base64," + png1x1, "captchaid": "CID1"}, "")
	})
	mux.HandleFunc("/api/n9e/auth/rsa-config", func(w http.ResponseWriter, r *http.Request) {
		if f.rsaKey == nil {
			out(w, map[string]any{"OpenRSA": false, "RSAPublicKey": ""}, "")
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(&f.rsaKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		out(w, map[string]any{"OpenRSA": true, "RSAPublicKey": base64.StdEncoding.EncodeToString(pemBytes)}, "")
	})
	mux.HandleFunc("/api/n9e/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		pw := b["password"]
		if f.rsaKey != nil {
			ct, err := base64.StdEncoding.DecodeString(pw)
			if err != nil {
				out(w, nil, "bad ciphertext")
				return
			}
			plain, err := rsa.DecryptPKCS1v15(rand.Reader, f.rsaKey, ct)
			if err != nil {
				out(w, nil, "decrypt failed")
				return
			}
			pw = string(plain)
		}
		if f.captcha && (b["captchaid"] != "CID1" || b["verifyvalue"] != "7") {
			out(w, nil, "incorrect verification code")
			return
		}
		if b["username"] != "alice" || pw != "pw" {
			out(w, nil, "Username or password invalid")
			return
		}
		out(w, map[string]any{"user": map[string]string{"username": "alice"}, "access_token": "AT", "refresh_token": "RT"}, "")
	})
	mux.HandleFunc("/api/n9e/self/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer AT" {
			w.WriteHeader(401)
			return
		}
		out(w, map[string]string{}, "")
	})
	return mux
}

// recorder answers rounds and remembers what it was asked.
type recorder struct {
	answers map[string]site.Credentials
	modes   []string
	fields  [][]site.Field
}

func (r *recorder) Ask(_ context.Context, mode string, f []site.Field) (site.Credentials, error) {
	r.modes = append(r.modes, mode)
	r.fields = append(r.fields, f)
	c, ok := r.answers[mode]
	if !ok {
		return nil, errors.New("unexpected round " + mode)
	}
	return c, nil
}

func login(t *testing.T, f *fakeN9e, rec *recorder) (*site.Session, error) {
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	return driver{}.Login(context.Background(), u, rec, srv.Client())
}

var plain = map[string]site.Credentials{"login": {"username": "alice", "password": "pw"}}

func TestPlainLogin(t *testing.T) {
	rec := &recorder{answers: plain}
	s, err := login(t, &fakeN9e{}, rec)
	if err != nil || s.Headers["Authorization"] != "Bearer AT" || s.Tokens["refresh_token"] != "RT" || strings.Join(rec.modes, ",") != "login" {
		t.Fatalf("%+v %v %v", s, err, rec.modes)
	}
}

func TestCaptchaIsShownToTheHuman(t *testing.T) {
	rec := &recorder{answers: map[string]site.Credentials{"custom": {"username": "alice", "password": "pw", "verifyvalue": " 7 "}}}
	s, err := login(t, &fakeN9e{captcha: true}, rec)
	if err != nil || s.Tokens["access_token"] != "AT" {
		t.Fatalf("%+v %v", s, err)
	}
	// one round, "custom", with the captcha image attached to the answer field
	if strings.Join(rec.modes, ",") != "custom" {
		t.Fatalf("rounds: %v", rec.modes)
	}
	var img string
	for _, f := range rec.fields[0] {
		if f.Name == "verifyvalue" {
			img = f.Image
		}
	}
	if !strings.HasPrefix(img, "data:image/png;base64,") {
		t.Errorf("captcha image missing from the human round: %+v", rec.fields[0])
	}

	wrong := &recorder{answers: map[string]site.Credentials{"custom": {"username": "alice", "password": "pw", "verifyvalue": "9"}}}
	if _, err := login(t, &fakeN9e{captcha: true}, wrong); !errors.Is(err, site.ErrBadCredentials) || !strings.Contains(err.Error(), "captcha") {
		t.Errorf("wrong captcha: %v", err)
	}
}

func TestRSAEncryptedPassword(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, err := login(t, &fakeN9e{rsaKey: key}, &recorder{answers: plain})
	if err != nil || s.Tokens["access_token"] != "AT" {
		t.Fatalf("rsa login: %+v %v", s, err)
	}
	// wrong password still maps to bad credentials (the fake decrypts then compares)
	bad := &recorder{answers: map[string]site.Credentials{"login": {"username": "alice", "password": "nope"}}}
	if _, err := login(t, &fakeN9e{rsaKey: key}, bad); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("bad password with rsa: %v", err)
	}
}

func TestBadPasswordAndProbe(t *testing.T) {
	bad := &recorder{answers: map[string]site.Credentials{"login": {"username": "alice", "password": "x"}}}
	if _, err := login(t, &fakeN9e{}, bad); !errors.Is(err, site.ErrBadCredentials) || len(bad.modes) != 1 {
		t.Errorf("bad creds: %v asked=%v", err, bad.modes)
	}
	srv := httptest.NewServer((&fakeN9e{}).handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	s := &site.Session{Headers: map[string]string{"Authorization": "Bearer AT"}}
	if err := (driver{}).Probe(context.Background(), u, s, srv.Client()); err != nil {
		t.Errorf("probe: %v", err)
	}
	s.Headers["Authorization"] = "Bearer old"
	if err := (driver{}).Probe(context.Background(), u, s, srv.Client()); err == nil {
		t.Error("stale token accepted")
	}
}

func TestInspect(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer((&fakeN9e{captcha: true, rsaKey: key}).handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	out, err := driver{}.Inspect(context.Background(), u, srv.Client())
	got := strings.Join(out, " | ")
	if err != nil || !strings.Contains(got, "captcha required: true") || !strings.Contains(got, "RSA-encrypted password required: true") {
		t.Errorf("%q %v", got, err)
	}
	plain := httptest.NewServer((&fakeN9e{}).handler())
	defer plain.Close()
	u, _ = url.Parse(plain.URL)
	out, _ = driver{}.Inspect(context.Background(), u, plain.Client())
	if got := strings.Join(out, " | "); !strings.Contains(got, "captcha required: false") || !strings.Contains(got, "RSA-encrypted password required: false") {
		t.Errorf("plain: %q", got)
	}
}
