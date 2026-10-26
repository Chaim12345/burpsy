package session

import "testing"

// ibhs: FuzzJSONPath: the JSON path subset parser and walker never panic, and a path that parses
// walks any input to one of the walker's defined outcomes.
func FuzzJSONPath(f *testing.F) {
	f.Add("a.b[0].c", []byte(`{"a":{"b":[{"c":1}]}}`))
	f.Add("a", []byte(`{"a":"x"}`))
	f.Add("[0]", []byte(`[1,2]`))
	f.Add("a[", []byte(`{}`))
	f.Add("a..b", []byte(`{}`))
	f.Add("a[99999999999999999999]", []byte(`[]`))
	f.Add("a", []byte(`not json`))
	f.Add("", []byte{})
	f.Fuzz(func(t *testing.T, path string, src []byte) {
		p, err := parseJSONPath(path)
		if err != nil {
			return
		}
		_, _, _, _ = walkJSON(src, p)
	})
}
