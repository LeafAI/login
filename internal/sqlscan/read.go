package sqlscan

import "strings"

// readWords are the words a read statement may start with.
var readWords = map[string]bool{
	"select": true, "with": true, "show": true, "explain": true, "describe": true, "desc": true, "values": true, "table": true,
}

// writeClauses are words that, inside an otherwise ordinary read statement, make it do something else: write a file
// (INTO OUTFILE, INTO DUMPFILE, and Postgres' SELECT ... INTO, which creates a table), or take locks (FOR UPDATE).
// A word that merely sounds like one of them (a column called "into" is quoted) is not matched, because quoted
// identifiers, strings and comments are skipped.
var writeClauses = map[string]bool{"into": true, "outfile": true, "dumpfile": true}

// lockWords follow FOR in a locking clause.
var lockWords = map[string]bool{"update": true, "share": true, "no": true, "key": true}

// IsSingleRead reports whether sql is exactly one statement and that statement only reads: it starts with a reading
// keyword and has no INTO or locking clause. Anything the scan cannot prove (an unterminated string or comment, a NUL
// byte, a statement that reads differently with and without backslash escapes) is not a read.
//
// A data-modifying CTE (WITH d AS (DELETE ...) SELECT ...) starts with a reading keyword, so it passes this scan; the
// database's read-only transaction is what refuses it. This is the first net, not the only one.
func IsSingleRead(sql string) bool {
	return isSingleRead(sql, true) && isSingleRead(sql, false)
}

func isSingleRead(sql string, backslash bool) bool {
	stmts, ok := split(sql, backslash)
	if !ok || len(stmts) != 1 {
		return false
	}
	words := stmts[0]
	for len(words) > 0 && words[0] == "(" { // (SELECT 1) UNION (SELECT 2)
		words = words[1:]
	}
	if len(words) == 0 || !readWords[words[0]] {
		return false
	}
	for i, w := range words {
		if writeClauses[w] {
			return false
		}
		if w == "for" && i+1 < len(words) && lockWords[words[i+1]] {
			return false
		}
	}
	return true
}

// OnlyComments reports whether sql holds nothing but white space, comments and semicolons.
func OnlyComments(sql string) bool {
	stmts, ok := split(sql, true)
	return ok && len(stmts) == 0
}

// split cuts sql into statements and returns the bare words of each, lower-cased, in order. Comments and white space are
// dropped; the content of strings and quoted identifiers is skipped (a quoted token becomes the placeholder "?", so a
// statement made only of a string still counts as a statement). Empty statements are dropped. ok is false when the text
// does not end cleanly or holds a NUL byte.
func split(sql string, backslash bool) (stmts [][]string, ok bool) {
	if strings.IndexByte(sql, 0) >= 0 {
		return nil, false
	}
	s := scanner{src: sql, backslash: backslash}
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			stmts = append(stmts, cur)
			cur = nil
		}
	}
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c <= ' ':
			s.i++
		case c == ';':
			flush()
			s.i++
		case c == '#':
			s.skipLine()
		case c == '-' && s.isDashComment():
			s.skipLine()
		case c == '/' && s.at("/*"):
			if bad := s.comment(); bad {
				return nil, false
			}
		case c == '*' && s.inExec && s.at("*/"):
			s.inExec = false
			s.i += 2
		case c == '\'' || c == '"' || c == '`':
			if !s.quoted(c) {
				return nil, false
			}
			cur = append(cur, "?")
		case isWordByte(c):
			cur = append(cur, s.word())
		default:
			s.i++
			cur = append(cur, string(c))
		}
	}
	if s.inExec {
		return nil, false
	}
	flush()
	return stmts, true
}

// Statements cuts sql into its statements at the semicolons that end them (not those in strings, quoted identifiers or
// comments), keeping each statement's own text. Empty statements are dropped. ok is false when the cut would depend on a
// guess: the text does not end cleanly, holds a NUL byte, or is cut differently with and without backslash escapes (a
// server's NO_BACKSLASH_ESCAPES mode decides which is right, and the client cannot know it).
func Statements(sql string) (out []string, ok bool) {
	a, okA := cutStatements(sql, true)
	b, okB := cutStatements(sql, false)
	if !okA || !okB || len(a) != len(b) {
		return nil, false
	}
	for i := range a {
		if a[i] != b[i] {
			return nil, false
		}
	}
	return a, true
}

func cutStatements(sql string, backslash bool) ([]string, bool) {
	if strings.IndexByte(sql, 0) >= 0 {
		return nil, false
	}
	s := scanner{src: sql, backslash: backslash}
	var out []string
	start, hasWord := 0, false
	end := func(to int) {
		if hasWord {
			out = append(out, sql[start:to])
		}
		hasWord = false
	}
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c <= ' ':
			s.i++
		case c == ';':
			end(s.i)
			s.i++
			start = s.i
		case c == '#':
			s.skipLine()
		case c == '-' && s.isDashComment():
			s.skipLine()
		case c == '/' && s.at("/*"):
			if bad := s.comment(); bad {
				return nil, false
			}
		case c == '*' && s.inExec && s.at("*/"):
			s.inExec = false
			s.i += 2
		case c == '\'' || c == '"' || c == '`':
			if !s.quoted(c) {
				return nil, false
			}
			hasWord = true
		case isWordByte(c):
			s.word()
			hasWord = true
		default:
			s.i++
			hasWord = true
		}
	}
	if s.inExec {
		return nil, false
	}
	end(len(sql))
	return out, true
}
