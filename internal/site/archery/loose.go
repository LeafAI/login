package archery

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strconv"
	"strings"
)

// looseInt reads a whole number, as an errlevel or a row count (it fits 32 bits), from what Archery's engines send for one:
// a number, a number as text, an empty string or null (zero). Anything else (text that is not a number, a fraction, a boolean, an array) is an error, so that a value
// nobody understands is reported and not turned into a zero that reads as "nothing wrong".
type looseInt int

func (n *looseInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*n = 0
		return nil
	}
	s := string(b)
	if b[0] == '"' {
		var t string
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		if s = strings.TrimSpace(t); s == "" {
			*n = 0
			return nil
		}
	}
	// "1.0", "2.0" and "1e2" are whole numbers that a float carries without loss, as long as it is small: beyond 2^31 an
	// errlevel or a row count means nothing, and a float cannot tell neighbours apart past 2^53. NaN is not equal to its
	// own truncation and an infinity is beyond the bound, so neither needs a check of its own.
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > math.MaxInt32 {
		return &json.UnmarshalTypeError{Value: jsonKind(b), Type: reflect.TypeFor[int32]()}
	}
	*n = looseInt(int(f))
	return nil
}

// looseString reads text from what the engines send for it: a string, a number (the time a statement took) or null (empty).
// An object, an array or a boolean is an error.
type looseString string

func (s *looseString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0 || string(b) == "null":
		*s = ""
	case b[0] == '"':
		var t string
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		*s = looseString(t)
	case b[0] == '-' || (b[0] >= '0' && b[0] <= '9'):
		var n json.Number
		if err := json.Unmarshal(b, &n); err != nil {
			return err
		}
		*s = looseString(n.String())
	default:
		return &json.UnmarshalTypeError{Value: jsonKind(b), Type: reflect.TypeFor[string]()}
	}
	return nil
}

// jsonKind names the kind of a JSON value the way encoding/json does ("string", "number", "bool", "object", "array"),
// and never the value: it ends up in an error, and the answers hold SQL text and table names.
func jsonKind(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return "nothing"
	}
	switch b[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "bool"
	}
	return "number"
}
