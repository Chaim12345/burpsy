package apidoc

import (
	"reflect"
	"testing"
)

// ibhs: FuzzParse: the API document importer never panics on arbitrary bytes.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	f.Add([]byte("openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n"))
	f.Add([]byte(`{"swagger":"2.0","paths":{}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://a/","headers":[]}}]}}`))
	f.Add([]byte("{"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Oracle: parsing is deterministic, and exactly one of (document, error) is returned.
		d1, err1 := Parse(data)
		d2, err2 := Parse(data)
		if (err1 == nil) != (err2 == nil) || (err1 != nil && err1.Error() != err2.Error()) {
			t.Fatalf("Parse is not deterministic on %q: %v vs %v", data, err1, err2)
		}
		if (d1 == nil) == (err1 == nil) {
			t.Fatalf("Parse(%q) returned document=%v with error=%v: want exactly one", data, d1 != nil, err1)
		}
		if err1 == nil && !reflect.DeepEqual(d1, d2) {
			t.Fatalf("Parse is not deterministic on %q: documents differ", data)
		}
	})
}
