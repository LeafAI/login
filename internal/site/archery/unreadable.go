package archery

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// describeUnreadable says why an answer of Archery could not be read, in terms of its shape: which field, and what kind of
// value was there instead. It never repeats a value. The answers hold SQL text, table names and the text of errors, and
// the description ends up in what an agent sees, so a description that quoted the answer would hand over what the agent
// has no business with; and a clipped quotation of the start of an answer says nothing about which field was wrong.
func describeUnreadable(raw string, err error) string {
	var syn *json.SyntaxError
	if errors.As(err, &syn) || !json.Valid([]byte(raw)) {
		return fmt.Sprintf("the answer is not JSON (%d bytes, starts with %s)", len(raw), startsLike(raw))
	}
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		field := strings.TrimPrefix(ute.Field, ".")
		if field == "" {
			field = "(top level)"
		}
		return fmt.Sprintf("the field %s holds %s where %s was expected", field, kindOf(ute.Value), goKind(ute.Type.String()))
	}
	// Every reader of this package reports an UnmarshalTypeError, so this is for one that does not. What such an error says
	// is not known to be free of the answer's content, so it is not repeated.
	return "a field could not be read (the reader's error is not shown: it may quote the answer)"
}

// startsLike names how an answer begins without quoting it: an HTML page, a JSON object or array, plain text.
func startsLike(raw string) string {
	t := strings.TrimSpace(raw)
	switch {
	case t == "":
		return "nothing"
	case strings.HasPrefix(t, "<"):
		return "markup (an HTML page?)"
	case t[0] == '{' || t[0] == '[':
		return "a JSON document that is cut or malformed"
	}
	return "plain text"
}

// kindOf is encoding/json's word for what was found ("string", "number", "bool", "object", "array"), with its article.
func kindOf(v string) string {
	switch strings.TrimPrefix(v, "number ") {
	case "":
		return "a value of another type"
	case "object", "array":
		return "an " + v
	}
	return "a " + strings.TrimPrefix(v, "number ")
}

func goKind(t string) string {
	switch {
	case strings.HasPrefix(t, "int"), strings.HasPrefix(t, "uint"), strings.HasPrefix(t, "float"):
		return "a number"
	case t == "string":
		return "text"
	case t == "bool":
		return "true or false"
	case strings.HasPrefix(t, "[]"):
		return "a list"
	}
	return "another type"
}
