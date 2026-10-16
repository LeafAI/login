// Package nightingale logs in to Nightingale (n9e) v7.
//
// Verified against the Nightingale source: POST /api/n9e/auth/login takes
// {username, password, captchaid, verifyvalue} and answers {"dat":{access_token,refresh_token,user},"err":""}.
// Nightingale has no TOTP. Instead it can require (a) a math-image captcha (GET /auth/ifshowcaptcha,
// POST /auth/captcha) and (b) an RSA-encrypted password (GET /auth/rsa-config). Both are handled:
// the captcha image is shown to the human in the login step.
package nightingale

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "nightingale" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	return strings.Contains(h, "nightingale") || strings.Contains(h, "n9e")
}

type reply struct {
	Dat json.RawMessage `json:"dat"`
	Err string          `json:"err"`
}

func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	api := &api{base: base, hc: hc}

	fields, mode := site.LoginFields, "login"
	var captchaID string
	if show, err := api.showCaptcha(ctx); err != nil {
		return nil, err
	} else if show {
		id, img, err := api.newCaptcha(ctx)
		if err != nil {
			return nil, err
		}
		captchaID, mode = id, "custom"
		fields = []site.Field{
			{Name: "username", Label: "Username"},
			{Name: "password", Label: "Password", Secret: true},
			{Name: "verifyvalue", Label: "Captcha (solve the calculation)", Image: img},
		}
	}
	creds, err := ask.Ask(ctx, mode, fields)
	if err != nil {
		return nil, err
	}

	password := creds["password"]
	if pub, err := api.rsaKey(ctx); err != nil {
		return nil, err
	} else if pub != nil {
		if password, err = encrypt(pub, password); err != nil {
			return nil, fmt.Errorf("%w: cannot encrypt the password: %v", site.ErrLoginRejected, err)
		}
	}

	var r reply
	status, raw, err := api.post(ctx, "/api/n9e/auth/login", map[string]string{
		"username": creds["username"], "password": password, "captchaid": captchaID, "verifyvalue": strings.TrimSpace(creds["verifyvalue"])}, &r)
	if err != nil {
		return nil, err
	}
	var d struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.Unmarshal(r.Dat, &d)
	if d.AccessToken == "" {
		msg := site.Clip(firstNonEmpty(r.Err, raw), 200)
		switch {
		case status >= 500:
			return nil, fmt.Errorf("%w: nightingale returned %d: %s", site.ErrLoginRejected, status, msg)
		case strings.Contains(strings.ToLower(r.Err), "verification code"):
			return nil, fmt.Errorf("%w: wrong captcha answer (%s)", site.ErrBadCredentials, msg)
		}
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, msg)
	}
	return &site.Session{
		Headers: map[string]string{"Authorization": "Bearer " + d.AccessToken},
		Tokens:  map[string]string{"access_token": d.AccessToken, "refresh_token": d.RefreshToken},
	}, nil
}

type api struct {
	base *url.URL
	hc   *http.Client
}

func (a *api) do(ctx context.Context, method, path string, payload any, out *reply) (int, string, error) {
	var body *bytes.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base.String()+path, body)
	if err != nil {
		return 0, "", err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	raw := site.ReadBody(resp)
	if out != nil {
		json.Unmarshal([]byte(raw), out)
	}
	return resp.StatusCode, raw, nil
}

func (a *api) post(ctx context.Context, path string, payload any, out *reply) (int, string, error) {
	return a.do(ctx, http.MethodPost, path, payload, out)
}

func (a *api) showCaptcha(ctx context.Context) (bool, error) {
	var r reply
	status, _, err := a.do(ctx, http.MethodGet, "/api/n9e/auth/ifshowcaptcha", nil, &r)
	if err != nil {
		return false, err
	}
	if status != 200 {
		return false, nil // older/other builds without the endpoint: assume no captcha
	}
	var d struct {
		Show bool `json:"show"`
	}
	json.Unmarshal(r.Dat, &d)
	return d.Show, nil
}

func (a *api) newCaptcha(ctx context.Context) (id, image string, err error) {
	var r reply
	if _, _, err = a.post(ctx, "/api/n9e/auth/captcha", struct{}{}, &r); err != nil {
		return "", "", err
	}
	var d struct {
		ImgData   string `json:"imgdata"`
		CaptchaID string `json:"captchaid"`
	}
	json.Unmarshal(r.Dat, &d)
	if d.CaptchaID == "" || d.ImgData == "" {
		return "", "", fmt.Errorf("%w: nightingale did not return a captcha (%s)", site.ErrLoginRejected, site.Clip(r.Err, 120))
	}
	img := d.ImgData
	if !strings.HasPrefix(img, "data:") {
		img = "data:image/png;base64," + img
	}
	return d.CaptchaID, img, nil
}

// rsaKey returns the server's public key when it requires RSA-encrypted passwords, else nil.
func (a *api) rsaKey(ctx context.Context) (*rsa.PublicKey, error) {
	var r reply
	status, _, err := a.do(ctx, http.MethodGet, "/api/n9e/auth/rsa-config", nil, &r)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, nil
	}
	// The Go struct has no json tags, so keys are OpenRSA / RSAPublicKey; accept snake_case too.
	var d struct {
		OpenRSA       bool   `json:"OpenRSA"`
		OpenRSA2      bool   `json:"open_rsa"`
		RSAPublicKey  string `json:"RSAPublicKey"`
		RSAPublicKey2 string `json:"rsa_public_key"`
	}
	json.Unmarshal(r.Dat, &d)
	if !d.OpenRSA && !d.OpenRSA2 {
		return nil, nil
	}
	keyB64 := firstNonEmpty(d.RSAPublicKey, d.RSAPublicKey2)
	pemBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad RSA public key from nightingale", site.ErrLoginRejected)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("%w: bad RSA public key from nightingale", site.ErrLoginRejected)
	}
	parsed, err := x509.ParsePKIXPublicKey(blk.Bytes)
	pub, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: unsupported RSA public key from nightingale", site.ErrLoginRejected)
	}
	return pub, nil
}

// encrypt mirrors Nightingale's front end: RSA PKCS#1 v1.5, base64.
func encrypt(pub *rsa.PublicKey, plain string) (string, error) {
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(plain))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/api/n9e/self/profile", nil)
	req.Header.Set("Authorization", s.Headers["Authorization"])
	resp, err := hc.Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("nightingale token invalid: %s", resp.Status)
	}
	return nil
}

// Inspect reports whether login needs a captcha and an RSA-encrypted password.
func (driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	a := &api{base: base, hc: hc}
	show, err := a.showCaptcha(ctx)
	if err != nil {
		return nil, err
	}
	pub, err := a.rsaKey(ctx)
	if err != nil {
		return nil, err
	}
	return []string{
		fmt.Sprintf("captcha required: %v (it is shown to the human in the login step)", show),
		fmt.Sprintf("RSA-encrypted password required: %v", pub != nil),
	}, nil
}
