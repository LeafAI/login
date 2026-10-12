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
	"strings"
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
	// DingTalk mentions a person only when the number is in at.atMobiles AND written as "@number" in the text. The list
	// alone sends the message and mentions nobody. The numbers come from the configuration, never from the message.
	mobiles := cleanMobiles(d.Mobiles)
	if len(mobiles) > 0 {
		text = "@" + strings.Join(mobiles, " @") + "\n\n" + text
	}
	body, _ := json.Marshal(map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": title, "text": text},
		"at":       map[string]any{"atMobiles": mobiles, "isAtAll": false},
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

// cleanMobiles returns the phone numbers to mention: digits only, each once, in the order given. Surrounding spaces are
// ignored. An entry with any other character (a "+", a letter, a line break) is refused rather than repaired, as the
// setup wizard refuses it: rewriting a number would mention someone the person did not mean, and passing it on would
// put something that is not a number into a message. The result is never nil, so that it is sent as an empty list and
// not as JSON null.
func cleanMobiles(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] || strings.Trim(m, "0123456789") != "" {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
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
