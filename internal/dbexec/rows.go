package dbexec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LeafAI/securl/internal/sqlscan"
)

// bounded collects rows until the row limit or the byte limit is reached.
type bounded struct {
	cols      []string
	rows      [][]any
	max       int
	bytes     int
	truncated bool
}

func newBounded(cols []string, maxRows int) *bounded {
	return &bounded{cols: cols, max: maxRows, rows: [][]any{}}
}

// add stores one row and reports whether more rows may follow. The row that does not fit is dropped and marks the result
// truncated, so "truncated" always means rows exist that the caller did not get.
func (b *bounded) add(vals []any) bool {
	if len(b.rows) >= b.max {
		b.truncated = true
		return false
	}
	row := make([]any, len(vals))
	size := 0
	for i, v := range vals {
		row[i] = jsonValue(v)
		size += valueSize(row[i])
	}
	if b.bytes+size > MaxResultBytes && len(b.rows) > 0 {
		b.truncated = true
		return false
	}
	b.rows = append(b.rows, row)
	b.bytes += size
	return true
}

func (b *bounded) result() *QueryResult {
	return &QueryResult{Columns: b.cols, Rows: b.rows, Truncated: b.truncated, TotalBytes: b.bytes}
}

func valueSize(v any) int {
	switch x := v.(type) {
	case nil:
		return 4
	case string:
		return len(x)
	}
	return 16
}

// jsonValue turns a driver value into something that encodes as JSON and cannot be huge: text is cut at MaxCellBytes
// (on a character boundary), bytes become text when they are text and base64 when they are not, timestamps are RFC 3339,
// and numbers the driver hands back as arbitrary-precision keep their digits as text.
func jsonValue(v any) any {
	switch x := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return x
	case string:
		return clipText(x)
	case []byte:
		return bytesValue(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case *big.Int:
		return x.String()
	case fmt.Stringer:
		return clipText(x.String())
	case [16]byte:
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
	case map[string]any, []any:
		if b, err := json.Marshal(x); err == nil {
			return clipText(string(b))
		}
	}
	return clipText(fmt.Sprint(v))
}

func bytesValue(b []byte) any {
	if len(b) > MaxCellBytes {
		b = b[:MaxCellBytes]
	}
	if utf8.Valid(b) && !strings.ContainsRune(string(b), 0) {
		return string(b)
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b)
}

func clipText(s string) string {
	if len(s) <= MaxCellBytes {
		return s
	}
	return strings.ToValidUTF8(s[:MaxCellBytes], "") + "…[cut]"
}

// marshalRows is used by the tests to prove that a result encodes.
func marshalRows(rows [][]any) ([]byte, error) { return json.Marshal(rows) }

// statements cuts a text for the drivers that must run statements one at a time.
func statements(q string) []string {
	if out, ok := sqlscan.Statements(q); ok {
		return out
	}
	return []string{q}
}

// safeMessage keeps what a server says about itself short and free of control characters. A server's error text about a
// statement or a login never holds the password the client sent, but it is clipped all the same.
func safeMessage(m string) string {
	m = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, m)
	if len(m) > 300 {
		m = strings.ToValidUTF8(m[:300], "") + "…"
	}
	return m
}

// connectReason describes a connection failure without echoing anything that could carry a credential.
func connectReason(err error) string {
	msg := err.Error()
	for _, marker := range []string{"password=", "passwd=", "pwd="} {
		if i := strings.Index(strings.ToLower(msg), marker); i >= 0 {
			return "connection failed"
		}
	}
	return safeMessage(msg)
}
