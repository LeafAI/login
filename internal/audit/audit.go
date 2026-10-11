// Package audit appends one JSON line per security-relevant event: who asked for what, and what happened.
// It records metadata only. Cookies, tokens, passwords and SQL text never appear in it.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one line of the audit log.
type Event struct {
	Time     string `json:"time"`
	Event    string `json:"event"`              // tool_call | human_request | human_round | tunnel | rate_limited
	Tool     string `json:"tool,omitempty"`     // MCP tool name
	Client   string `json:"client,omitempty"`   // MCP client name/version as reported at initialize
	Site     string `json:"site,omitempty"`     // driver name
	Host     string `json:"host,omitempty"`     // site host:port
	Reason   string `json:"reason,omitempty"`   // the reason the agent gave (already length-limited)
	Result   string `json:"result,omitempty"`   // ok | pending | error code
	Cached   bool   `json:"cached,omitempty"`   // the session came from the cache, nobody was asked
	Mode     string `json:"mode,omitempty"`     // human_round: login | totp | custom
	Round    int    `json:"round,omitempty"`    // human_round: 1, 2, ...
	Tunnel   string `json:"tunnel,omitempty"`   // tunnel: the provider that carries the link (pinggy, localhost.run, ...)
	Attempts int    `json:"attempts,omitempty"` // tunnel: tunnels opened until one carried traffic (more than 1 = dead ones were replaced)
	Millis   int64  `json:"ms,omitempty"`
	SQLBytes int    `json:"sql_bytes,omitempty"` // size of submitted SQL, never its text
	SQLHash  string `json:"sql_sha256,omitempty"`
	Workflow int    `json:"workflow_id,omitempty"`
	Method   string `json:"method,omitempty"` // request: the HTTP method
	Path     string `json:"path,omitempty"`   // request: the path, never the query string
	Status   int    `json:"status,omitempty"` // request: the site's HTTP status
	Bytes    int    `json:"bytes,omitempty"`  // request: size of the answer the site sent
}

// Fingerprint returns the length and a short SHA-256 prefix of s, enough to match a statement to the one
// shown to approvers without storing it.
func Fingerprint(s string) (int, string) {
	sum := sha256.Sum256([]byte(s))
	return len(s), hex.EncodeToString(sum[:6])
}

// Log writes events. The zero value and a nil *Log discard everything.
type Log struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
	warn func(string, ...any)
}

// Open returns a log appending to path ("" disables auditing). Missing directories are created (0700); the file is 0600.
func Open(path string, warn func(string, ...any)) (*Log, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log %s: %w", path, err)
	}
	f.Close()
	return &Log{path: path, now: time.Now, warn: warn}, nil
}

// Record appends e. A write failure is reported through warn and never fails the caller's operation.
func (l *Log) Record(e Event) {
	if l == nil {
		return
	}
	if e.Time == "" {
		e.Time = l.now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(e)
	if err != nil {
		l.report("encode: %v", err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.report("open: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		l.report("write: %v", err)
	}
}

func (l *Log) report(f string, a ...any) {
	if l.warn != nil {
		l.warn("audit log: "+f, a...)
	}
}
