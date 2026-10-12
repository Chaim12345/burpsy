package scanner

import "testing"

// The statement-echo rule (burpsy-react-ui-j1mk.36): the marker must sit inside echoed SQL statement
// text. Each negative row is a response a parameterised or merely reflecting endpoint produces, and
// each would pass a rule that only asked for an error signature plus the marker somewhere.
func TestSQLStatementEchoesOnlyWhenTheValueIsInsideTheStatementText(t *testing.T) {
	const m = "zq0a1b2c3d4e5f"
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"H2 relayed through Spring, concatenated",
			"StatementCallback; SQL [select * from cars where id='1" + m + "']; Data conversion error converting \"1" + m + "\"; SQL statement:\nselect * from cars where id='1" + m + "' [22018-214]", true},
		{"PostgreSQL log form, concatenated",
			"ERROR:  invalid input syntax for type integer: \"7" + m + "\"\nSTATEMENT:  SELECT name FROM vehicles WHERE id = '7" + m + "'", true},
		{"unquoted numeric context",
			"Syntax error in SQL statement \"SELECT * FROM T WHERE ID=1" + m + "[*]\"", true},
		{"H2 with a bound parameter: the value is quoted only in the conversion message",
			"Data conversion error converting \"1" + m + "\"; SQL statement:\nselect * from cars where id=? [22018-214]", false},
		{"PostgreSQL with a bound parameter",
			"ERROR:  invalid input syntax for type integer: \"7" + m + "\"\nSTATEMENT:  SELECT name FROM vehicles WHERE id = $1", false},
		{"reflection beside an unrelated statement",
			"you searched for 1" + m + "\nselect * from cars where id=?", false},
		{"a verb with no clause before the marker",
			"could not select " + m, false},
		{"marker absent", "select * from cars where id='1'", false},
	}
	for _, c := range cases {
		if got := sqlStatementEchoes(c.body, m); got != c.want {
			t.Errorf("%s: sqlStatementEchoes = %v, want %v", c.name, got, c.want)
		}
	}
}

// A conversion error alone is what a parameterised query raises too, so it is only ever a
// signature for the echo rule, never in the bank the quote probes confirm on.
func TestTypeConversionErrorsAreNotStandaloneSQLSignatures(t *testing.T) {
	for _, sig := range sqlEngineErrorSignatures {
		for _, bank := range SQLErrorSignatures {
			if sig == bank {
				t.Errorf("%q is in SQLErrorSignatures: a quote probe would confirm on it alone", sig)
			}
		}
	}
	if _, ok := sqlDatabaseErrorIntroduced("ok", "Data conversion error converting \"x\""); !ok {
		t.Error("the echo rule must recognise an H2 conversion error as a database error")
	}
	if _, ok := sqlDatabaseErrorIntroduced("Data conversion error converting \"x\"", "Data conversion error converting \"y\""); ok {
		t.Error("an error already in the baseline is not introduced by the probe")
	}
}
