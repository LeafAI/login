package archery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/site"
)

// sqlcheckServer answers every request with body, as a real Archery does for /api/v1/workflow/sqlcheck/.
func sqlcheckServer(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	return &Client{Base: base, Sess: &site.Session{Tokens: map[string]string{"api": GenREST}}, HC: srv.Client()}
}

// The shapes below are what Archery's review engines really send. The serializer declares only a few fields (the rest of a
// row is whatever the engine put there), and the engines disagree on the types: Inception sends numbers where
// go-inception sends strings, an empty value is "" where a count is expected, and a missing one is null.
func TestCheckReadsEveryShapeOfReviewRowAnArcheryEngineSends(t *testing.T) {
	for name, tc := range map[string]struct {
		body      string
		wantLevel string
		wantMsg   string
	}{
		"goinception strings": {`{"is_execute":false,"checked":null,"warning":null,"error":null,"warning_count":0,"error_count":0,"is_critical":false,"syntax_type":2,
			"rows":[{"id":1,"stage":"CHECKED","errlevel":0,"stagestatus":"Audit completed","errormessage":"","sql":"UPDATE t SET a=1","affected_rows":"1","sequence":"0_0_00000000","backup_dbname":"","execute_time":"0","sqlsha1":"","backup_time":""}]}`, "ok", ""},
		"inception numbers":   {`{"checked":null,"error":null,"warning":null,"rows":[{"id":1,"stage":"CHECKED","errlevel":0,"errormessage":"","sql":"UPDATE t SET a=1","affected_rows":1,"sequence":"0_0_0","backup_dbname":"","execute_time":0}]}`, "ok", ""},
		"empty affected rows": {`{"rows":[{"id":1,"stage":"","errlevel":0,"errormessage":"","sql":"UPDATE t SET a=1","affected_rows":"","execute_time":"","backup_dbname":""}]}`, "ok", ""},
		"null everything":     {`{"checked":null,"rows":[{"id":1,"stage":null,"errlevel":null,"errormessage":null,"sql":"UPDATE t SET a=1","affected_rows":null,"execute_time":null,"backup_dbname":null}]}`, "ok", ""},
		"float affected rows": {`{"rows":[{"id":1,"errlevel":0,"sql":"x","affected_rows":1.0,"execute_time":0.25}]}`, "ok", ""},
		"string errlevel":     {`{"rows":[{"id":1,"errlevel":"2","errormessage":"table not found","sql":"x","affected_rows":"0"}]}`, "error", "table not found"},
		"string id":           {`{"rows":[{"id":"1","errlevel":1,"errormessage":"no WHERE","sql":"x"}]}`, "warning", "no WHERE"},
		"missing rows":        {`{"checked":null,"error":null}`, "", ""},
		"error as text":       {`{"error":"syntax error near 'x'","rows":[{"id":1,"errlevel":2,"errormessage":"syntax error","sql":"x"}]}`, "error", "syntax error"},
	} {
		c := sqlcheckServer(t, tc.body)
		rows, err := c.Check(context.Background(), 23, "appdb", "UPDATE t SET a=1")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if tc.wantLevel == "" {
			if len(rows) != 0 {
				t.Errorf("%s: want no rows, got %+v", name, rows)
			}
			continue
		}
		if len(rows) != 1 || rows[0].Level != tc.wantLevel || rows[0].Message != tc.wantMsg {
			t.Errorf("%s: %+v", name, rows)
		}
	}
}

// A body that is not JSON at all is still an error, and says what came back.
func TestCheckStillRefusesAnAnswerThatIsNotJSON(t *testing.T) {
	c := sqlcheckServer(t, `<html>502 Bad Gateway</html>`)
	_, err := c.Check(context.Background(), 23, "appdb", "SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Errorf("%v", err)
	}
}

// A row that cannot be read at all must fail closed: an unreadable review is not a clean one.
func TestAReviewRowThatCannotBeReadIsNotTakenAsClean(t *testing.T) {
	for name, body := range map[string]string{
		"row is a string":   `{"rows":["ok"]}`,
		"errlevel is text":  `{"rows":[{"id":1,"errlevel":"banana","sql":"x"}]}`,
		"errlevel is array": `{"rows":[{"id":1,"errlevel":[2],"sql":"x"}]}`,
		"errlevel is bool":  `{"rows":[{"id":1,"errlevel":true,"sql":"x"}]}`,
	} {
		c := sqlcheckServer(t, body)
		rows, err := c.Check(context.Background(), 23, "appdb", "SELECT 1")
		if err == nil {
			for _, r := range rows {
				if r.Level == "ok" {
					t.Errorf("%s: an unreadable review row became clean: %+v", name, rows)
				}
			}
		}
	}
}

// testdata/sqlcheck_real.json is a real answer of /api/v1/workflow/sqlcheck/ from the production Archery, with the SQL text
// replaced and every field and every type as received. It is the answer that made archery_run_sql fail for any statement:
// "execute_time" is the number 0 and the reader wanted text. A fake that only sends what its author expects never finds a
// difference like that, so this file is the test of record.
func TestTheRealSqlcheckAnswerIsRead(t *testing.T) {
	raw, err := os.ReadFile("testdata/sqlcheck_real.json")
	if err != nil {
		t.Fatal(err)
	}
	c := sqlcheckServer(t, string(raw))
	rows, err := c.Check(context.Background(), 23, "appdb", "UPDATE t SET a = 0 WHERE id = 1;")
	if err != nil {
		t.Fatalf("the real answer must be read: %v", err)
	}
	if len(rows) != 1 || rows[0].Level != "ok" || rows[0].Sequence != 1 {
		t.Errorf("%+v", rows)
	}
}

// The same answer, with one field changed at a time to a type another engine sends. Whatever else a field may be, the
// review must still come out as the review said.
func TestEveryFieldOfTheRealAnswerSurvivesATypeChange(t *testing.T) {
	raw, _ := os.ReadFile("testdata/sqlcheck_real.json")
	var base map[string]any
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	row := func(m map[string]any) map[string]any { return m["rows"].([]any)[0].(map[string]any) }
	for _, field := range []string{"affected_rows", "execute_time", "backup_dbname", "errormessage", "sequence", "sql"} {
		for name, v := range map[string]any{"string": "7", "empty": "", "null": nil, "float": 1.5} {
			if (field == "affected_rows") && (name == "float") {
				continue // a count is whole
			}
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			row(m)[field] = v
			b, _ := json.Marshal(m)
			rows, err := sqlcheckServer(t, string(b)).Check(context.Background(), 23, "appdb", "x")
			if err != nil || len(rows) != 1 || rows[0].Level != "ok" {
				t.Errorf("%s as %s: %+v %v", field, name, rows, err)
			}
		}
	}
	_ = base
}

// When an answer cannot be read, the error says which field and what was wrong with it, and never repeats a value: the
// first time this failed, finding the field meant guessing, and the answer holds SQL text and table names.
func TestAnUnreadableAnswerNamesTheFieldAndNotTheValue(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want []string
	}{
		"errlevel is text":    {`{"rows":[{"id":1,"errlevel":"SECRETWORD","sql":"DROP TABLE customers"}]}`, []string{"errlevel"}},
		"id is a bool":        {`{"rows":[{"id":true,"errlevel":0,"sql":"DROP TABLE customers"}]}`, []string{"id"}},
		"rows is an object":   {`{"rows":{"a":1}}`, []string{"rows"}},
		"second row is bad":   {`{"rows":[{"id":1,"errlevel":0},{"id":2,"errlevel":[1],"sql":"DROP TABLE customers"}]}`, []string{"errlevel"}},
		"execute_time object": {`{"rows":[{"id":1,"errlevel":0,"execute_time":{"x":"SECRETWORD"}}]}`, []string{"execute_time"}},
		"not json":            {`<html>SECRETWORD</html>`, []string{"not JSON"}},
	} {
		_, err := sqlcheckServer(t, tc.body).Check(context.Background(), 23, "appdb", "x")
		if err == nil {
			t.Errorf("%s: must fail", name)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the error should name %q: %v", name, w, err)
			}
		}
		for _, leak := range []string{"SECRETWORD", "customers"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error repeats the answer's content (%q): %v", name, leak, err)
			}
		}
	}
}

// The same holds when the reading happens deeper than the first call: the workflow answers go through the same reader.
func TestTheDescriptionOfAnErrorIsBounded(t *testing.T) {
	_, err := sqlcheckServer(t, `{"rows":[{"id":1,"errlevel":"`+strings.Repeat("x", 5000)+`"}]}`).Check(context.Background(), 23, "appdb", "x")
	if err == nil || len(err.Error()) > 400 {
		t.Errorf("%d bytes: %v", len(err.Error()), err)
	}
}

// The wording is part of what the owner reads when something fails, so it is checked as text, article included.
func TestTheDescriptionOfAnUnreadableAnswerIsPlainEnglish(t *testing.T) {
	for body, want := range map[string]string{
		`{"rows":[{"id":1,"errlevel":"banana"}]}`:            "the field rows.errlevel holds a string where a number was expected",
		`{"rows":[{"id":1,"errlevel":0,"execute_time":{}}]}`: "the field rows.execute_time holds an object where text was expected",
		`{"rows":{"a":1}}`:               "the field rows holds an object where a list was expected",
		`{"rows":"x"}`:                   "the field rows holds a string where a list was expected",
		`<html>502 Bad Gateway</html>`:   "the answer is not JSON (28 bytes, starts with markup (an HTML page?))",
		`{"rows":[{"id":1,"errlevel":0,`: "starts with a JSON document that is cut or malformed",
		`plain words`:                    "starts with plain text",
		``:                               "starts with nothing",
	} {
		_, err := sqlcheckServer(t, body).Check(context.Background(), 23, "appdb", "x")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", body, want, err)
		}
	}
}

// An error of a kind this package does not know is not repeated: what it says may quote the answer.
func TestAnErrorOfAnUnknownKindIsNotRepeated(t *testing.T) {
	got := describeUnreadable(`{"rows":[{"sql":"DROP TABLE customers"}]}`, errors.New(`bad value "DROP TABLE customers"`))
	if strings.Contains(got, "customers") || strings.Contains(got, "DROP") || !strings.Contains(got, "could not be read") {
		t.Errorf("%q", got)
	}
}
