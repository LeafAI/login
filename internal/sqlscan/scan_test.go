package sqlscan

import (
	"strings"
	"testing"
)

func TestHasDDLDetects(t *testing.T) {
	for name, sql := range map[string]string{
		"plain":                                             "DROP TABLE t",
		"lower case":                                        "drop table t",
		"mixed case":                                        "DrOp TaBlE t",
		"leading blank lines":                               "\n\n  \tCREATE TABLE t (a int)",
		"block comment before":                              "/* x */ DROP TABLE t",
		"line comment before":                               "-- note\nDROP TABLE t",
		"hash comment before":                               "# note\nDROP TABLE t",
		"several comments before":                           "/* a */ -- b\n# c\n  /* d */ TRUNCATE t",
		"second statement same line":                        "UPDATE t SET a=1; DROP TABLE t",
		"second statement next line":                        "UPDATE t SET a=1;\nALTER TABLE t ADD c int",
		"after empty statements":                            ";;; RENAME TABLE a TO b",
		"executable comment":                                "/*!50000 DROP TABLE t */",
		"executable comment no ver":                         "/*! DROP TABLE t */",
		"mariadb executable comment":                        "/*M!100100 DROP TABLE t */",
		"executable then plain":                             "SELECT 1; /*!50000 TRUNCATE t */",
		"comment between words":                             "DROP/**/TABLE t",
		"keyword after statement in executable comment":     "/*!50000 SELECT 1; DROP TABLE t */",
		"string with semicolon then ddl":                    "SELECT ';'; DROP TABLE t",
		"string with quote then ddl":                        "SELECT 'it''s'; DROP TABLE t",
		"double quoted then ddl":                            `SELECT "a;b"; DROP TABLE t`,
		"backtick then ddl":                                 "SELECT `a;b`; DROP TABLE t",
		"dynamic prepare":                                   "SET @s='DROP TABLE t'; PREPARE x FROM @s; EXECUTE x",
		"dynamic execute only":                              "EXECUTE x",
		"create user is create":                             "CREATE USER u",
		"backslash string ends under NO_BACKSLASH":          `SELECT '\'; DROP TABLE t; -- '`,
		"unterminated string fails closed":                  "SELECT 'oops; DROP TABLE t",
		"unterminated comment fails closed":                 "SELECT 1; /* oops DROP TABLE t",
		"unterminated backtick fails closed":                "SELECT `oops",
		"escaped quote is ambiguous (NO_BACKSLASH_ESCAPES)": `UPDATE t SET a='it\'s; drop table t' WHERE id=1`,
		"backslash escape hides it only under NO_BACKSLASH": "SELECT 'x\\''; DROP TABLE t; -- '",
		"dash dash without space is not a comment":          "SELECT 1--1; DROP TABLE t",
		"backslash does not escape inside backticks":        "SELECT `a\\`; DROP TABLE t; -- `",
		"empty executable comment before ddl":               "/*!50000 */ DROP TABLE t",
		"nul padding":                                       "SELECT 1;\x00DROP TABLE t",
	} {
		if !HasDDL(sql) {
			t.Errorf("%s: %q must count as DDL", name, sql)
		}
	}
}

func TestHasDDLAllowsOrdinarySQL(t *testing.T) {
	for name, sql := range map[string]string{
		"select":                           "SELECT * FROM t",
		"update":                           "UPDATE t SET a=1 WHERE id=2",
		"insert":                           "INSERT INTO t(a) VALUES (1)",
		"delete":                           "DELETE FROM t WHERE id=1",
		"several dml":                      "UPDATE t SET a=1;\nINSERT INTO t(a) VALUES (2);\nDELETE FROM t WHERE id=3;",
		"keyword in string":                "UPDATE t SET note='please drop table x; create index' WHERE id=1",
		"keyword in double quotes":         `UPDATE t SET note="drop table x" WHERE id=1`,
		"keyword in comment":               "UPDATE t SET a=1 -- drop table t\n",
		"keyword in block comment":         "/* drop table t */ UPDATE t SET a=1",
		"keyword in hash comment":          "UPDATE t SET a=1 # drop table t",
		"keyword in plain /*+ hint*/":      "SELECT /*+ drop table t */ 1",
		"keyword as column":                "SELECT `drop`, `create` FROM t",
		"keyword as suffix":                "UPDATE t SET dropped=1, created_at=now()",
		"keyword in identifier":            "SELECT * FROM truncate_log",
		"double dash without space":        "SELECT 1--1",
		"doubled quote in string":          "UPDATE t SET a='it''s; drop table t' WHERE id=1",
		"truncate function in select":      "SELECT TRUNCATE(a, 1) FROM t",
		"truncate function in update":      "UPDATE t SET a = TRUNCATE(b, 2) WHERE id = 1",
		"rename as alias":                  "SELECT a AS rename FROM t",
		"replace function":                 "UPDATE t SET a = REPLACE(a, 'x', 'y')",
		"keyword prefix of first word":     "dropped_rows_cleanup",
		"keyword prefix with underline":    "create_log_entry",
		"keyword word after a string":      "SELECT 'a' drop FROM t",
		"keyword word after a number":      "SELECT 1 drop FROM t",
		"keyword word after punct":         "SELECT (drop) FROM t",
		"keyword word after operator":      "SELECT a + drop FROM t",
		"keyword after comma":              "SELECT a, drop FROM t",
		"keyword after quoted ident":       "SELECT `a` create FROM t",
		"statement starting with a paren":  "(drop)",
		"statement starting with a union":  "(SELECT 1) UNION (SELECT 2)",
		"statement starting with a string": "'x' drop",
		"empty":                            "",
		"only comments":                    "/* a */ -- b\n# c",
		"call":                             "CALL cleanup()",
		"with cte":                         "WITH x AS (SELECT 1) SELECT * FROM x",
		"set variable":                     "SET @a = 1; SELECT @a",
	} {
		if HasDDL(sql) {
			t.Errorf("%s: %q must not count as DDL", name, sql)
		}
	}
}

func TestHasDDLIsFastOnLargeInput(t *testing.T) {
	big := strings.Repeat("UPDATE t SET a=1 WHERE id=2; /* c */ ", 200000)
	if HasDDL(big) {
		t.Fatal("unexpected DDL")
	}
	if !HasDDL(big + "DROP TABLE t") {
		t.Fatal("DDL at the very end must be found")
	}
}

func TestIsSingleReadAcceptsOneReadingStatement(t *testing.T) {
	for name, sql := range map[string]string{
		"select":               "SELECT * FROM t",
		"lower":                "select 1",
		"trailing semicolon":   "SELECT 1;",
		"trailing semis":       "SELECT 1;;  ",
		"leading comment":      "/* x */ SELECT 1",
		"leading line comment": "-- note\nSELECT 1",
		"with":                 "WITH x AS (SELECT 1) SELECT * FROM x",
		"show":                 "SHOW TABLES",
		"explain":              "EXPLAIN SELECT 1",
		"describe":             "DESCRIBE t",
		"values":               "VALUES (1), (2)",
		"paren select":         "(SELECT 1) UNION (SELECT 2)",
		"semicolon in string":  "SELECT ';' AS a",
		"semicolon in comment": "SELECT 1 /* ; */",
		"keyword in string":    "SELECT 'delete from t; drop table x'",
		"table":                "TABLE items",
	} {
		if !IsSingleRead(sql) {
			t.Errorf("%s: %q is one read statement", name, sql)
		}
	}
}

func TestIsSingleReadRefusesAnythingElse(t *testing.T) {
	for name, sql := range map[string]string{
		"update":                 "UPDATE t SET a = 1",
		"insert":                 "INSERT INTO t VALUES (1)",
		"delete":                 "DELETE FROM t",
		"drop":                   "DROP TABLE t",
		"two statements":         "SELECT 1; SELECT 2",
		"select then delete":     "SELECT 1; DELETE FROM t",
		"comment between":        "SELECT 1 /* a */; /* b */ DELETE FROM t",
		"executable comment":     "SELECT 1; /*!50000 DELETE FROM t */",
		"empty":                  "",
		"blank":                  "  \n ",
		"only comment":           "-- x",
		"unterminated string":    "SELECT 'oops",
		"unterminated comment":   "SELECT 1 /* oops",
		"call":                   "CALL p()",
		"set":                    "SET @a = 1",
		"copy":                   "COPY t TO PROGRAM 'id'",
		"do":                     "DO $$ BEGIN DELETE FROM t; END $$",
		"select into outfile":    "SELECT * FROM t INTO OUTFILE '/tmp/x'",
		"select into dumpfile":   "SELECT 1 INTO DUMPFILE '/tmp/x'",
		"select for update":      "SELECT * FROM t FOR UPDATE",
		"select for share":       "SELECT * FROM t FOR SHARE",
		"load data":              "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t",
		"semicolon after string": "SELECT 'a'; UPDATE t SET a = 1",
		"nul":                    "SELECT 1;\x00DELETE FROM t",
		"backslash quote":        `SELECT '\'; DELETE FROM t; -- '`,
	} {
		if IsSingleRead(sql) {
			t.Errorf("%s: %q is not a single read statement", name, sql)
		}
	}
}

func TestOnlyComments(t *testing.T) {
	for sql, want := range map[string]bool{
		"": true, "  ": true, "-- a": true, "/* a */": true, "# a": true, "/* a */ -- b\n": true, ";": true, " ; ; ": true,
		"SELECT 1": false, "/* a */ SELECT 1": false, "-- a\nSELECT 1": false, "/*! SELECT 1 */": false,
	} {
		if got := OnlyComments(sql); got != want {
			t.Errorf("OnlyComments(%q) = %v, want %v", sql, got, want)
		}
	}
}

func TestStatementsCutsTheTextAtTheSemicolonsThatEndStatements(t *testing.T) {
	for name, tc := range map[string]struct {
		sql  string
		want []string
	}{
		"one":                {"UPDATE t SET a=1", []string{"UPDATE t SET a=1"}},
		"two":                {"UPDATE t SET a=1; DELETE FROM t", []string{"UPDATE t SET a=1", "DELETE FROM t"}},
		"trailing":           {"UPDATE t SET a=1;", []string{"UPDATE t SET a=1"}},
		"empty ones":         {";; UPDATE t SET a=1 ;;", []string{"UPDATE t SET a=1"}},
		"semicolon in text":  {"UPDATE t SET a=';' WHERE id=1; DELETE FROM t", []string{"UPDATE t SET a=';' WHERE id=1", "DELETE FROM t"}},
		"semicolon in ident": {"SELECT `a;b` FROM t; SELECT 2", []string{"SELECT `a;b` FROM t", "SELECT 2"}},
		"semicolon in cmnt":  {"UPDATE t SET a=1 /* ; */; DELETE FROM t", []string{"UPDATE t SET a=1 /* ; */", "DELETE FROM t"}},
		"semicolon in line":  {"UPDATE t SET a=1 -- ;\n; DELETE FROM t", []string{"UPDATE t SET a=1 -- ;", "DELETE FROM t"}},
		"blank":              {"  ", nil},
		"only comment":       {"-- x", nil},
	} {
		got, ok := Statements(tc.sql)
		if !ok {
			t.Errorf("%s: not splittable", name)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
			continue
		}
		for i := range got {
			if strings.TrimSpace(got[i]) != tc.want[i] {
				t.Errorf("%s: statement %d is %q, want %q", name, i, got[i], tc.want[i])
			}
		}
	}
}

func TestStatementsRefusesTextItCannotCutSafely(t *testing.T) {
	for name, sql := range map[string]string{
		"unterminated string":  "UPDATE t SET a='x",
		"unterminated comment": "UPDATE t SET a=1 /* x",
		"nul":                  "UPDATE t SET a=1;\x00DELETE FROM t",
		"backslash ambiguity":  `UPDATE t SET a='it\'s; DELETE FROM t; -- '`,
	} {
		if _, ok := Statements(sql); ok {
			t.Errorf("%s: %q must not be split", name, sql)
		}
	}
}
