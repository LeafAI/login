// Package notify sends messages through a DingTalk custom robot webhook.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

type DingTalk struct {
	Webhook string
	Secret  string   // optional signing secret ("加签")
	Keyword string   // optional custom keyword required by the robot's security settings
	Mobiles []string // @ these phone numbers
	HTTP    *http.Client
	Now     func() time.Time
}

// Sign returns the DingTalk signature for a millisecond timestamp.
func Sign(secret string, tsMillis int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d\n%s", tsMillis, secret)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Markdown sends a markdown message.
func (d *DingTalk) Markdown(ctx context.Context, title, text string) error {
	if d.Webhook == "" {
		return fmt.Errorf("dingtalk webhook is not configured (set dingtalk.webhook or SECURL_DINGTALK_WEBHOOK)")
	}
	if d.Keyword != "" {
		title = d.Keyword + " " + title
	}
	u, err := url.Parse(d.Webhook)
	if err != nil {
		return fmt.Errorf("dingtalk: the webhook URL is malformed: %w", scrubURLError(err))
	}
	if d.Secret != "" {
		now := time.Now
		if d.Now != nil {
			now = d.Now
		}
		ts := now().UnixMilli()
		q := u.Query()
		q.Set("timestamp", strconv.FormatInt(ts, 10))
		q.Set("sign", Sign(d.Secret, ts))
		u.RawQuery = q.Encode()
	}
	body, _ := json.Marshal(map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": title, "text": text},
		"at":       map[string]any{"atMobiles": d.Mobiles, "isAtAll": false},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("dingtalk: could not build the request: %w", scrubURLError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	hc := d.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("dingtalk: request failed: %w", scrubURLError(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var r struct {
		Code int    `json:"errcode"`
		Msg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(b, &r); err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("dingtalk: http %d: %s", resp.StatusCode, string(b))
	}
	if r.Code != 0 {
		return fmt.Errorf("dingtalk: errcode %d: %s", r.Code, r.Msg)
	}
	return nil
}

// scrubURLError drops the request URL that net/http copies into *url.Error: for a DingTalk webhook it
// carries access_token, sign and timestamp, which must never reach logs, the terminal or an AI agent.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

var credentialParam = regexp.MustCompile(`(?i)\b(access_token|sign|timestamp)=[^&\s"')]*`)
var urlWithQuery = regexp.MustCompile(`(https?://[^\s"'?]*)\?[^\s"')]*`)

// Redact removes webhook credentials from free text. It is a safety net for errors produced outside
// this package (other Notifier implementations, wrapped messages): query strings are cut from every URL
// and any stray access_token, sign or timestamp parameter is blanked.
func Redact(s string) string {
	s = urlWithQuery.ReplaceAllString(s, "$1")
	return credentialParam.ReplaceAllString(s, "")
}
