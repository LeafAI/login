package archery

import "strings"

// ddlWords are the statement keywords that archery.allow_ddl: false refuses. PREPARE and EXECUTE are
// included because they run SQL the scanner cannot see.
var ddlWords = map[string]bool{
	"create": true, "alter": true, "drop": true, "truncate": true, "rename": true,
	"prepare": true, "execute": true,
}

// HasDDL reports whether any statement of sql is DDL, or cannot be proven not to be.
//
// It is a lexical scan, not a regular expression: comments count as white space, string literals and
// quoted identifiers are skipped, statements are split on ";" and only the first keyword of each is
// examined. MySQL "executable comments" (/*! ... */ and /*M! ... */) run as code, so their content is
// scanned. Whether a backslash escapes a quote depends on the server's NO_BACKSLASH_ESCAPES mode, which
// the client cannot know, so both readings are tried and either one finding DDL is enough. Input that
// does not end cleanly (an open string, comment or quoted identifier) is refused too.
func HasDDL(sql string) bool {
	return scanDDL(sql, true) || scanDDL(sql, false)
}

func scanDDL(sql string, backslash bool) bool {
	s := scanner{src: sql, backslash: backslash}
	return s.run()
}

type scanner struct {
	src       string
	i         int
	backslash bool
	inExec    bool // inside an executable comment, where "*/" ends it
}

func (s *scanner) run() bool {
	atStart := true
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c <= ' ':
			s.i++
		case c == ';':
			atStart = true
			s.i++
		case c == '#':
			s.skipLine()
		case c == '-' && s.isDashComment():
			s.skipLine()
		case c == '/' && s.at("/*"):
			if bad := s.comment(); bad {
				return true
			}
		case c == '*' && s.inExec && s.at("*/"):
			s.inExec = false
			s.i += 2
		case c == '\'' || c == '"' || c == '`':
			if !s.quoted(c) {
				return true
			}
			atStart = false
		case isWordByte(c):
			word := s.word()
			if atStart && ddlWords[word] {
				return true
			}
			atStart = false
		default:
			atStart = false
			s.i++
		}
	}
	return false
}

func (s *scanner) at(p string) bool { return strings.HasPrefix(s.src[s.i:], p) }

// isDashComment: "--" starts a comment only when followed by white space, a control character or the end.
func (s *scanner) isDashComment() bool {
	if !s.at("--") {
		return false
	}
	return s.i+2 >= len(s.src) || s.src[s.i+2] <= ' '
}

func (s *scanner) skipLine() {
	if n := strings.IndexByte(s.src[s.i:], '\n'); n >= 0 {
		s.i += n + 1
		return
	}
	s.i = len(s.src)
}

// comment handles "/*". An executable comment is entered (its content is code); an ordinary one is
// skipped. It reports true when an ordinary comment never closes.
func (s *scanner) comment() bool {
	rest := s.src[s.i+2:]
	if strings.HasPrefix(rest, "!") || strings.HasPrefix(rest, "M!") {
		s.i += 2 + strings.IndexByte(rest, '!') + 1
		for s.i < len(s.src) && s.src[s.i] >= '0' && s.src[s.i] <= '9' {
			s.i++
		}
		s.inExec = true
		return false
	}
	end := strings.Index(rest, "*/")
	if end < 0 {
		return true
	}
	s.i += 2 + end + 2
	return false
}

// quoted skips a string literal or quoted identifier opened by q; false means it never closes.
func (s *scanner) quoted(q byte) bool {
	s.i++
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '\\' && s.backslash && q != '`':
			s.i += 2
		case c == q && s.i+1 < len(s.src) && s.src[s.i+1] == q:
			s.i += 2
		case c == q:
			s.i++
			return true
		default:
			s.i++
		}
	}
	return false
}

func (s *scanner) word() string {
	start := s.i
	for s.i < len(s.src) && isWordByte(s.src[s.i]) {
		s.i++
	}
	return strings.ToLower(s.src[start:s.i])
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}
