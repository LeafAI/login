package archery

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
