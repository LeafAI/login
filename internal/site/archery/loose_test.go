package archery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLooseIntReadsWhatTheEnginesSend(t *testing.T) {
	for in, want := range map[string]int{`0`: 0, `7`: 7, `-1`: -1, `"7"`: 7, `" 7 "`: 7, `""`: 0, `"  "`: 0, `null`: 0, `1.0`: 1, `"2.0"`: 2, `1e2`: 100} {
		var n looseInt
		if err := json.Unmarshal([]byte(in), &n); err != nil || int(n) != want {
			t.Errorf("%s: got %d, %v; want %d", in, n, err, want)
		}
	}
}

// A value nobody understands is an error, never a zero: a zero errlevel reads as "no problem".
func TestLooseIntRefusesWhatIsNotAWholeNumber(t *testing.T) {
	for _, in := range []string{`"banana"`, `"1.5"`, `1.5`, `true`, `false`, `[2]`, `{"a":1}`, `"NaN"`, `"Infinity"`, `"1e400"`, `1e400`, `9007199254740993`, `"9007199254740993"`, `1e300`} {
		var n looseInt
		if err := json.Unmarshal([]byte(in), &n); err == nil {
			t.Errorf("%s must be refused, got %d", in, n)
		}
	}
}

func TestLooseStringReadsWhatTheEnginesSend(t *testing.T) {
	for in, want := range map[string]string{`"abc"`: "abc", `""`: "", `null`: "", `0`: "0", `0.25`: "0.25", `12`: "12", `-3`: "-3", `"0.5"`: "0.5", `"a\u00e9"`: "aé"} {
		var s looseString
		if err := json.Unmarshal([]byte(in), &s); err != nil || string(s) != want {
			t.Errorf("%s: got %q, %v; want %q", in, s, err, want)
		}
	}
}

func TestLooseStringRefusesWhatIsNotText(t *testing.T) {
	for _, in := range []string{`true`, `false`, `[1]`, `{"a":1}`} {
		var s looseString
		if err := json.Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("%s must be refused, got %q", in, s)
		}
	}
}

func TestTheErrorNamesWhatWasRefusedAndClipsIt(t *testing.T) {
	var n looseInt
	err := json.Unmarshal([]byte(`"`+strings.Repeat("x", 500)+`"`), &n)
	if err == nil || len(err.Error()) > 200 {
		t.Errorf("%v", err)
	}
}

// An errlevel the table does not know is an error row, not a clean one.
func TestAnErrLevelOutsideTheKnownLevelsCountsAsAnError(t *testing.T) {
	c := sqlcheckServer(t, `{"rows":[{"id":1,"errlevel":9,"errormessage":"odd","sql":"x"},{"id":2,"errlevel":-1,"sql":"y"}]}`)
	rows, err := c.Check(t.Context(), 23, "appdb", "x")
	if err != nil || len(rows) != 2 || rows[0].Level != "error" || rows[1].Level != "error" {
		t.Errorf("%+v %v", rows, err)
	}
}

// "NaN" and the infinities parse as floats; none of them is a count.
func TestLooseIntRefusesNaNAndTheInfinities(t *testing.T) {
	for _, in := range []string{`"NaN"`, `"nan"`, `"Inf"`, `"+Inf"`, `"-Inf"`, `"Infinity"`, `"-Infinity"`} {
		var n looseInt
		if err := json.Unmarshal([]byte(in), &n); err == nil {
			t.Errorf("%s must be refused, got %d", in, n)
		}
	}
}
