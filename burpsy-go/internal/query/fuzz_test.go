package query

import "testing"

// ibhs: FuzzParse: the history query parser never panics on arbitrary input.
func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("status:200")
	f.Add("method:GET AND host:example.com")
	f.Add("NOT (a OR b) AND c")
	f.Add("\"unterminated")
	f.Add("((((")
	f.Add("a:>=5 b:<3")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = Parse(in)
	})
}
