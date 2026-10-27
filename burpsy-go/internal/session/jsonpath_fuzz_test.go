package session

import (
	"reflect"
	"testing"
)

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
		// Oracle 1: parsing is deterministic, and exactly one of (path, error) comes back.
		p2, err2 := parseJSONPath(path)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(p, p2) {
			t.Fatalf("parseJSONPath(%q) is not deterministic: %v/%v vs %v/%v", path, p, err, p2, err2)
		}
		if err != nil {
			if p != nil {
				t.Fatalf("parseJSONPath(%q) returned both a path %v and an error %v", path, p, err)
			}
			return
		}
		// Oracle 2: the walk is deterministic and lands in one of the defined outcomes; a source that is
		// not JSON is reported as not-ok and as missing, never as a found value.
		v1, o1, d1, ok1 := walkJSON(src, p)
		v2, o2, d2, ok2 := walkJSON(src, p)
		if v1 != v2 || o1 != o2 || d1 != d2 || ok1 != ok2 {
			t.Fatalf("walkJSON(%q, %q) is not deterministic", src, path)
		}
		switch o1 {
		case jsonWalkFound, jsonWalkMissing, jsonWalkNull, jsonWalkNotAValue:
		default:
			t.Fatalf("walkJSON(%q, %q) returned an undefined outcome %v", src, path, o1)
		}
		if !ok1 && o1 != jsonWalkMissing {
			t.Fatalf("a non-JSON source must report missing, got %v for %q", o1, src)
		}
		if o1 != jsonWalkFound && v1 != "" {
			t.Fatalf("outcome %v carries a value %q", o1, v1)
		}
	})
}
